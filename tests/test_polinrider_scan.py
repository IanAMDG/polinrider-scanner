from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER_PATH = ROOT / "tools" / "polinrider_scan.py"
RULES_PATH = ROOT / "tools" / "polinrider_iocs.json"
SPEC = importlib.util.spec_from_file_location("polinrider_scan", SCANNER_PATH)
assert SPEC and SPEC.loader
scanner_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = scanner_module
SPEC.loader.exec_module(scanner_module)


class PolinRiderScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(self, *extra: str, rules: Path = RULES_PATH) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCANNER_PATH),
                str(self.root),
                "--rules",
                str(rules),
                "--format",
                "json",
                *extra,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def write(self, relative: str, data: str | bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
        return path

    def result(self, completed: subprocess.CompletedProcess[str]) -> dict:
        self.assertFalse(completed.stderr, completed.stderr)
        return json.loads(completed.stdout)

    def test_clean_project_has_no_findings(self) -> None:
        self.write("public/fonts/legit.woff2", b"wOF2" + bytes(128))
        self.write("vite.config.js", "export default { server: { port: 3000 } };\n")
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(self.result(completed)["findings"], [])

    def test_normal_text_assets_are_not_treated_as_javascript(self) -> None:
        self.write(
            "static/site.css",
            "/* https://example.invalid */ .sample { width: function(example); }\n",
        )
        self.write(
            "static/icon.svg",
            '<svg xmlns="http://www.w3.org/2000/svg"><path id="_0x1"/></svg>\n',
        )
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(self.result(completed)["findings"], [])

    def test_javascript_node_cluster_in_text_asset_is_detected(self) -> None:
        self.write(
            "static/disguised.css",
            "const cp = require('child_process'); cp.exec(Buffer.from('eA==', 'base64'));\n",
        )
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 1)
        self.assertIn("PR004", {item["rule_id"] for item in self.result(completed)["findings"]})

    def test_public_scanner_signature_declarations_are_not_payload_hits(self) -> None:
        primary = "rmcej" + "%otb%"
        self.write(
            "scanner.sh",
            "#!/bin/sh\n# PolinRider Malware Scanner\n"
            f"PRIMARY_SIG='({primary},2857687)'\n"
            "SECONDARY_SIG='_$_1e42'\n",
        )
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(self.result(completed)["findings"], [])

    def test_prior_scanner_json_report_is_not_rescanned_as_payload(self) -> None:
        primary = "rmcej" + "%otb%"
        self.write(
            "previous-scan.json",
            json.dumps(
                {
                    "scanner": {"name": "polinrider-scan", "version": "1.0.0"},
                    "findings": [{"evidence": f"{primary} + 2857687"}],
                    "stats": {},
                }
            ),
        )
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(self.result(completed)["findings"], [])

    def test_eot_magic_is_checked_at_the_documented_header_offset(self) -> None:
        data = bytearray(64)
        data[34:36] = b"LP"
        self.assertTrue(scanner_module.has_valid_asset_magic(".eot", bytes(data)))
        self.assertFalse(scanner_module.has_valid_asset_magic(".eot", b"LP" + bytes(62)))

    def test_git_blob_batches_bound_batch_memory(self) -> None:
        candidates = [("a", 20), ("b", 20), ("c", 5)]
        self.assertEqual(
            list(scanner_module.git_blob_batches(candidates, max_bytes=32)),
            [["a"], ["b", "c"]],
        )

    def test_detects_folder_open_fake_font_chain(self) -> None:
        self.write(
            ".vscode/tasks.json",
            """{
              // JSONC is valid in VS Code tasks files.
              "tasks": [{
                "label": "eslint-check",
                "runOptions": {"runOn": "folderOpen"},
                "command": "node ./public/fonts/fa-solid-400.woff2"
              }]
            }""",
        )
        self.write(
            ".vscode/settings.json",
            '{"task.allowAutomaticTasks": true, "terminal.integrated.defaultProfile.windows": "Command Prompt"}',
        )
        self.write(
            "public/fonts/fa-solid-400.woff2",
            b"\x00" * 64 + b"require('child_process'); fetch('https://example.invalid')",
        )
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 1)
        rule_ids = {finding["rule_id"] for finding in self.result(completed)["findings"]}
        self.assertTrue({"PR002", "PR003", "PR004", "PR009"}.issubset(rule_ids))

    def test_detects_padded_config_variant(self) -> None:
        self.write(
            "vite.config.js",
            (" " * 1000) + "eval(Buffer.from('eA==','base64').toString()); fetch('https://example.invalid');",
        )
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 1)
        finding = next(item for item in self.result(completed)["findings"] if item["rule_id"] == "PR005")
        self.assertEqual(finding["severity"], "high")

    def test_detects_publicly_reported_inline_node_task_variant(self) -> None:
        self.write(
            ".vscode/tasks.json",
            json.dumps(
                {
                    "tasks": [
                        {
                            "label": "eslint-check",
                            "command": "node",
                            "args": [
                                "-e",
                                "new Function('require', Buffer.from('eA==', 'base64'))(require)",
                            ],
                            "runOptions": {"runOn": "folderOpen"},
                        }
                    ]
                }
            ),
        )
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 1)
        self.assertIn("PR002", {item["rule_id"] for item in self.result(completed)["findings"]})

    def test_detects_documented_automatic_task_setting_value(self) -> None:
        self.write(".vscode/settings.json", '{"task.allowAutomaticTasks": "on"}')
        completed = self.run_cli("--fail-on", "medium")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("PR003", {item["rule_id"] for item in self.result(completed)["findings"]})

    def test_detects_history_laundering_script(self) -> None:
        self.write(
            "temp_auto_push.bat",
            """@echo off
            git config user.name "Someone"
            git config user.email "someone@example.invalid"
            date 01-01-2026
            git commit --amend --no-edit
            git push -uf origin main
            """,
        )
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 1)
        self.assertIn("PR006", {item["rule_id"] for item in self.result(completed)["findings"]})

    def test_detects_corroborated_loader_fingerprint(self) -> None:
        primary_marker = "rmcej" + "%otb%"
        decoder = "_$_" + "1e42"
        self.write("src/ordinary.js", f"const marker='{primary_marker}'; function {decoder}() {{}}")
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 1)
        self.assertIn("PR010", {item["rule_id"] for item in self.result(completed)["findings"]})

    def test_config_bat_gitignore_is_supporting_evidence(self) -> None:
        self.write(".gitignore", "node_modules\nconfig.bat\n")
        self.write("config.bat", "@echo off\necho setup\n")
        completed = self.run_cli("--fail-on", "medium")
        self.assertEqual(completed.returncode, 1)
        findings = [item for item in self.result(completed)["findings"] if item["rule_id"] == "PR011"]
        self.assertEqual(len(findings), 2)

    def test_detects_campaign_package_in_manifest(self) -> None:
        package = "tailwindcss" + "-style-animate"
        self.write("package.json", json.dumps({"dependencies": {package: "1.1.6"}}))
        completed = self.run_cli()
        self.assertEqual(completed.returncode, 1)
        self.assertIn("PR008", {item["rule_id"] for item in self.result(completed)["findings"]})

    def test_exact_hash_rules_are_updateable(self) -> None:
        payload = b"test-only-payload"
        digest = hashlib.sha256(payload).hexdigest()
        custom_rules = self.root / "custom-rules.json"
        custom_rules.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "payloads": [{"variant": "test", "sha256": digest, "size": len(payload)}],
                    "campaign_strings": [],
                    "affected_packages": [],
                }
            ),
            encoding="utf-8",
        )
        self.write("payload.bin", payload)
        completed = self.run_cli(rules=custom_rules)
        self.assertEqual(completed.returncode, 1)
        self.assertIn("PR001", {item["rule_id"] for item in self.result(completed)["findings"]})

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_does_not_follow_symlinks(self) -> None:
        outside = self.root.parent / (self.root.name + "-outside")
        outside.mkdir()
        try:
            (outside / "package.json").write_text(
                json.dumps({"dependencies": {"tailwindcss" + "-style-animate": "1.1.6"}}),
                encoding="utf-8",
            )
            os.symlink(outside, self.root / "linked-outside")
            completed = self.run_cli()
            self.assertEqual(completed.returncode, 0)
            document = self.result(completed)
            self.assertEqual(document["findings"], [])
            self.assertEqual(document["stats"]["symlinks_skipped"], 1)
        finally:
            shutil.rmtree(outside)

    @unittest.skipUnless(shutil.which("git"), "Git is unavailable")
    def test_git_history_scan_finds_deleted_indicator(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Test"], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        suspicious = self.write(
            "temp_auto_push.bat",
            "git config user.name X\ndate 01-01-2026\ngit commit --amend --no-edit\ngit push --force origin main\n",
        )
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "add"], check=True)
        suspicious.unlink()
        subprocess.run(["git", "-C", str(self.root), "add", "-u"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "remove"], check=True)

        without_history = self.run_cli()
        self.assertEqual(without_history.returncode, 0)
        with_history = self.run_cli("--git-history")
        self.assertEqual(with_history.returncode, 1)
        findings = self.result(with_history)["findings"]
        self.assertTrue(any(item["rule_id"] == "PR006" and item["source"].startswith("git:") for item in findings))

    @unittest.skipUnless(shutil.which("git"), "Git is unavailable")
    def test_repository_discovery_ignores_stale_parent_git_directory(self) -> None:
        (self.root / ".git").mkdir()
        nested = self.root / "projects" / "valid"
        nested.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(nested)], check=True)
        rules = scanner_module.load_rules(RULES_PATH)
        scanner = scanner_module.Scanner(
            rules,
            max_bytes=8 * 1024 * 1024,
            include_vendor=False,
            excludes=[],
            skip_exact=[],
            max_findings=1000,
            progress=False,
        )
        repositories = scanner_module.discover_git_repositories(self.root, scanner)
        self.assertEqual(repositories, [nested.resolve()])

    def test_writes_valid_sarif(self) -> None:
        self.write(
            "package.json",
            json.dumps({"dependencies": {"tailwindcss" + "-style-animate": "1.1.6"}}),
        )
        sarif = self.root / "result.sarif"
        completed = self.run_cli("--sarif", str(sarif))
        self.assertEqual(completed.returncode, 1)
        document = json.loads(sarif.read_text(encoding="utf-8"))
        self.assertEqual(document["version"], "2.1.0")
        self.assertEqual(document["runs"][0]["results"][0]["ruleId"], "PR008")

    def test_progress_uses_stderr_without_corrupting_json(self) -> None:
        self.write("clean.js", "export const clean = true;\n")
        completed = self.run_cli("--progress", "always")
        self.assertEqual(completed.returncode, 0)
        self.assertIn("filesystem:", completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["findings"], [])


if __name__ == "__main__":
    unittest.main()
