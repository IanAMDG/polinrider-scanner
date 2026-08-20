#!/usr/bin/env python3
"""Read-only PolinRider / Contagious Interview repository scanner.

The scanner uses only Python's standard library. It never imports or executes
files from the scan target. Optional Git-history scanning uses read-only Git
plumbing commands and never checks out a historical file.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence


VERSION = "1.1.0"
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
GIT_BATCH_BYTES = 32 * 1024 * 1024
DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
MANIFEST_NAMES = {
    "composer.json",
    "composer.lock",
    "go.mod",
    "go.sum",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}
SUSPICIOUS_ASSET_SUFFIXES = {
    ".css",
    ".dict",
    ".eot",
    ".jpeg",
    ".jpg",
    ".otf",
    ".png",
    ".svg",
    ".ttf",
    ".woff",
    ".woff2",
}
ASSET_MAGICS: dict[str, tuple[bytes, ...]] = {
    ".jpeg": (b"\xff\xd8\xff",),
    ".jpg": (b"\xff\xd8\xff",),
    ".otf": (b"OTTO",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".ttf": (b"\x00\x01\x00\x00", b"true", b"typ1"),
    ".woff": (b"wOFF",),
    ".woff2": (b"wOF2",),
}
TEXT_IOC_SUFFIXES = {
    ".bat",
    ".cjs",
    ".cmd",
    ".env",
    ".js",
    ".jsx",
    ".json",
    ".mjs",
    ".ps1",
    ".sh",
    ".ts",
    ".tsx",
    ".vue",
    ".svelte",
    ".yaml",
    ".yml",
}
CONFIG_JS_RE = re.compile(
    r"(?:config\.(?:c?js|mjs|ts)|tailwind\.js|webpack\.mix\.js)$",
    re.IGNORECASE,
)


@dataclasses.dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    path: str
    line: int
    message: str
    source: str = "worktree"
    evidence: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Stats:
    files_seen: int = 0
    files_read: int = 0
    bytes_read: int = 0
    symlinks_skipped: int = 0
    files_too_large: int = 0
    git_objects_seen: int = 0
    git_blobs_read: int = 0


@dataclasses.dataclass
class Rules:
    payload_by_hash: dict[str, dict[str, Any]]
    payload_sizes: set[int]
    payload_signatures: list[dict[str, Any]]
    campaign_strings: list[dict[str, str]]
    affected_packages: dict[str, list[dict[str, Any]]]


class Scanner:
    def __init__(
        self,
        rules: Rules,
        *,
        max_bytes: int,
        include_vendor: bool,
        excludes: Sequence[str],
        skip_exact: Iterable[Path],
        max_findings: int,
        progress: bool,
    ) -> None:
        self.rules = rules
        self.max_bytes = max_bytes
        self.include_vendor = include_vendor
        self.excludes = tuple(excludes)
        self.skip_exact = {safe_resolve(path) for path in skip_exact}
        self.max_findings = max_findings
        self.progress_enabled = progress
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.stats = Stats()
        self._dedupe: set[tuple[str, str, int, str]] = set()
        self._worktree_digests: dict[str, str] = {}
        self.git_repositories: set[Path] = set()
        self._last_progress = 0.0

    def progress(self, message: str, *, force: bool = False) -> None:
        if not self.progress_enabled:
            return
        now = time.monotonic()
        if force or now - self._last_progress >= 2.0:
            print(f"[polinrider-scan] {message}", file=sys.stderr, flush=True)
            self._last_progress = now

    def add(self, finding: Finding) -> None:
        key = (finding.rule_id, finding.path, finding.line, finding.source)
        if key in self._dedupe:
            return
        if len(self.findings) >= self.max_findings:
            if not any("finding limit" in error for error in self.errors):
                self.errors.append(
                    f"finding limit ({self.max_findings}) reached; results are incomplete"
                )
            return
        self._dedupe.add(key)
        self.findings.append(finding)

    def scan_path(self, target: Path) -> None:
        if target.is_symlink():
            self.stats.symlinks_skipped += 1
            return
        target = safe_resolve(target)
        start_seen = self.stats.files_seen
        start_read = self.stats.files_read
        self.progress(f"filesystem: scanning {target}", force=True)
        if not target.exists():
            self.errors.append(f"scan target does not exist: {target}")
            return
        repository = git_root(target)
        if repository is not None:
            self.git_repositories.add(repository)
        if target.is_file():
            self._scan_file(target, target.name)
            return

        def walk_error(error: OSError) -> None:
            self.errors.append(f"cannot traverse {error.filename or target}: {error}")

        for directory, dirs, files in os.walk(
            target, followlinks=False, onerror=walk_error
        ):
            directory_path = Path(directory)
            if ".git" in dirs or ".git" in files:
                repository = git_root(directory_path)
                if repository is not None and repository not in self.git_repositories:
                    self.git_repositories.add(repository)
                    self.progress(
                        f"repository discovery: {len(self.git_repositories):,} Git repositories found"
                    )
            kept_dirs: list[str] = []
            for name in dirs:
                candidate = directory_path / name
                relative = posix_relative(candidate, target)
                if candidate.is_symlink():
                    self.stats.symlinks_skipped += 1
                elif self._excluded(relative, is_dir=True):
                    continue
                else:
                    kept_dirs.append(name)
            dirs[:] = kept_dirs

            for name in files:
                candidate = directory_path / name
                relative = posix_relative(candidate, target)
                if candidate.is_symlink():
                    self.stats.symlinks_skipped += 1
                    continue
                if self._excluded(relative, is_dir=False):
                    continue
                self._scan_file(candidate, relative)
                if self.stats.files_seen % 500 == 0:
                    self.progress(
                        f"filesystem: {self.stats.files_seen:,} files visited, "
                        f"{self.stats.files_read:,} candidates read, {len(self.findings):,} findings"
                    )
        self.progress(
            f"filesystem: finished {target} "
            f"({self.stats.files_seen - start_seen:,} files visited, "
            f"{self.stats.files_read - start_read:,} candidates read, "
            f"{len(self.git_repositories):,} Git repositories found)",
            force=True,
        )

    def _excluded(self, relative: str, *, is_dir: bool) -> bool:
        parts = Path(relative).parts
        if not self.include_vendor and any(part in DEFAULT_EXCLUDED_DIRS for part in parts):
            return True
        if any(fnmatch.fnmatch(relative, pattern) for pattern in self.excludes):
            return True
        if is_dir and any(fnmatch.fnmatch(relative + "/", pattern) for pattern in self.excludes):
            return True
        return False

    def _scan_file(self, path: Path, display_path: str) -> None:
        self.stats.files_seen += 1
        if safe_resolve(path) in self.skip_exact:
            return
        try:
            size = path.stat().st_size
        except OSError as exc:
            self.errors.append(f"cannot stat {display_path}: {exc}")
            return

        needs_hash = size in self.rules.payload_sizes
        needs_content = is_content_candidate(display_path)
        if not needs_hash and not needs_content:
            return
        if size > self.max_bytes and not needs_hash:
            self.stats.files_too_large += 1
            return
        try:
            data = path.read_bytes()
        except OSError as exc:
            self.errors.append(f"cannot read {display_path}: {exc}")
            return
        self.stats.files_read += 1
        self.stats.bytes_read += len(data)
        self._worktree_digests[display_path.replace("\\", "/")] = hashlib.sha256(data).hexdigest()
        self.scan_bytes(display_path, data, source="worktree")

    def scan_bytes(self, display_path: str, data: bytes, *, source: str) -> None:
        normalized = display_path.replace("\\", "/")
        lower_path = normalized.lower()

        if is_scanner_json_report(lower_path, data):
            return

        if len(data) in self.rules.payload_sizes:
            digest = hashlib.sha256(data).hexdigest()
            payload = self.rules.payload_by_hash.get(digest)
            if payload:
                confidence = payload.get("confidence", "publicly-corroborated")
                severity = payload.get("severity", "critical")
                if confidence == "incident-artifact-only":
                    title = "Incident-supplied payload hash"
                    message = (
                        f"Exact SHA-256 match for incident-artifact {payload['variant']} payload; "
                        "this hash was not independently corroborated in public reporting."
                    )
                else:
                    title = "Known PolinRider payload hash"
                    message = f"Exact SHA-256 match for PolinRider {payload['variant']} payload."
                self.add(
                    Finding(
                        "PR001",
                        title,
                        severity,
                        normalized,
                        1,
                        message,
                        source,
                        f"sha256:{digest}",
                    )
                )

        if Path(lower_path).suffix in SUSPICIOUS_ASSET_SUFFIXES:
            self._scan_asset(normalized, data, source)

        text: str | None = None
        if is_text_rule_candidate(lower_path) or Path(lower_path).suffix in SUSPICIOUS_ASSET_SUFFIXES:
            text = decode_text(data)

        if text is not None:
            self._scan_payload_signatures(normalized, text, source)

        if text is not None and is_vscode_file(lower_path, "tasks.json"):
            self._scan_tasks(normalized, text, source)
        if text is not None and is_vscode_file(lower_path, "settings.json"):
            self._scan_settings(normalized, text, source)
        if text is not None and CONFIG_JS_RE.search(Path(lower_path).name):
            self._scan_config(normalized, text, source)
        if text is not None and lower_path.endswith((".bat", ".cmd")):
            self._scan_batch(normalized, text, source)
        if text is not None and (Path(lower_path).name == "config.bat" or Path(lower_path).name == ".gitignore"):
            self._scan_orchestrator(normalized, text, source)
        if text is not None and is_ioc_text_candidate(lower_path):
            self._scan_campaign_strings(normalized, text, source)
        if text is not None and Path(lower_path).name in MANIFEST_NAMES:
            self._scan_packages(normalized, text, source)

    def _scan_asset(self, path: str, data: bytes, source: str) -> None:
        suffix = Path(path.lower()).suffix
        if has_valid_asset_magic(suffix, data):
            return
        lower = data.lower()
        node_markers = [
            b"require(",
            b"child_process",
            b"process.env",
            b"buffer.from",
        ]
        execution_markers = [
            b"fetch(",
            b"eval(",
            b"new function",
            b"fromcodepoint",
            b"_0x",
        ]
        node_count = sum(marker in lower for marker in node_markers)
        execution_count = sum(marker in lower for marker in execution_markers)
        marker_count = node_count + execution_count
        nul_ratio = data.count(b"\x00") / max(1, len(data))
        known_path = path.lower().endswith(
            ("/public/fonts/fa-solid-400.woff2", "/public/fontawesome/fa-solid-400.woff2")
        ) or path.lower() in {
            "public/fonts/fa-solid-400.woff2",
            "public/fontawesome/fa-solid-400.woff2",
        }
        javascript_like = (
            node_count >= 2
            or (node_count >= 1 and execution_count >= 1)
            or execution_count >= 3
            or (marker_count >= 1 and nul_ratio >= 0.05)
        )
        if (known_path and marker_count >= 1) or javascript_like:
            severity = "critical" if known_path and marker_count >= 1 else "high"
            self.add(
                Finding(
                    "PR004",
                    "JavaScript disguised as a static asset",
                    severity,
                    path,
                    1,
                    "Static asset has invalid file magic or a campaign path and contains JavaScript characteristics.",
                    source,
                    f"node_markers={node_count}; execution_markers={execution_count}; "
                    f"nul_ratio={nul_ratio:.2%}",
                )
            )

    def _scan_tasks(self, path: str, text: str, source: str) -> None:
        compact = re.sub(r"\s+", " ", text)
        folder_open = bool(re.search(r'["\']?runOn["\']?\s*:\s*["\']folderOpen["\']', compact, re.I))
        invokes_asset = bool(
            re.search(
                r"\bnode(?:\.exe)?\b[^\r\n]{0,300}?\.(?:woff2?|ttf|otf|eot|png|jpe?g|svg|css|dict|md)(?:\s|[\"']|$)",
                compact,
                re.I,
            )
        )
        piped_download = bool(
            re.search(
                r"\b(?:curl|wget)\b[^\r\n]{0,500}?\|\s*(?:sh|bash|zsh|cmd|powershell|pwsh)\b",
                compact,
                re.I,
            )
        )
        inline_loader = bool(
            re.search(
                r"\bnode(?:\.exe)?\b[^\r\n]{0,200}?(?:\s-e\b|[\"']-e[\"'])",
                compact,
                re.I,
            )
            and re.search(r"(?:new\s+Function|eval\s*\(|Buffer\.from|https?://)", compact, re.I)
        )
        known_infrastructure = any(
            item["value"].lower() in compact.lower() for item in self.rules.campaign_strings
        )
        hidden = bool(
            re.search(r'["\']?(?:hide)["\']?\s*:\s*true\b', compact, re.I)
            or re.search(r'["\']?reveal["\']?\s*:\s*["\']never["\']', compact, re.I)
        )
        if folder_open and (invokes_asset or piped_download or inline_loader or known_infrastructure):
            line = line_for(text, "folderOpen")
            mechanisms = [
                label
                for label, matched in (
                    ("node executes non-source asset", invokes_asset),
                    ("download piped to shell", piped_download),
                    ("inline Node loader", inline_loader),
                    ("known campaign infrastructure", known_infrastructure),
                )
                if matched
            ]
            self.add(
                Finding(
                    "PR002",
                    "Malicious VS Code folder-open execution task",
                    "critical",
                    path,
                    line,
                    "A task runs automatically on folder open and uses a publicly observed Contagious Interview execution pattern.",
                    source,
                    "runOn:folderOpen + " + ", ".join(mechanisms),
                )
            )
        elif folder_open and (re.search(r"eslint-check", compact, re.I) or hidden):
            self.add(
                Finding(
                    "PR002A",
                    "Suspicious PolinRider-like folder-open task",
                    "high",
                    path,
                    line_for(text, "folderOpen"),
                    "An automatic folder-open task uses the campaign-observed eslint-check label or hides its terminal presentation.",
                    source,
                )
            )
        elif folder_open:
            self.add(
                Finding(
                    "PR002B",
                    "Automatic VS Code folder-open task",
                    "medium",
                    path,
                    line_for(text, "folderOpen"),
                    "Automatic folder-open tasks can be legitimate, but this execution surface should be reviewed.",
                    source,
                )
            )

    def _scan_settings(self, path: str, text: str, source: str) -> None:
        if re.search(
            r'["\']?task\.allowAutomaticTasks["\']?\s*:\s*(?:true\b|["\']on["\'])',
            text,
            re.I,
        ):
            shell = bool(re.search(r"Command Prompt|cmd\.exe", text, re.I))
            message = "VS Code automatic tasks are explicitly enabled."
            if shell:
                message += " The Windows default shell is also set to Command Prompt."
            self.add(
                Finding(
                    "PR003",
                    "Automatic VS Code tasks enabled",
                    "medium",
                    path,
                    line_for(text, "task.allowAutomaticTasks"),
                    message,
                    source,
                )
            )

    def _scan_config(self, path: str, text: str, source: str) -> None:
        lines = text.splitlines() or [text]
        longest_index, longest = max(enumerate(lines, start=1), key=lambda item: len(item[1]))
        lower = text.lower()
        markers = [
            "eval(",
            "function(",
            "new function",
            "buffer.from",
            "atob(",
            "child_process",
            "execsync",
            "spawn(",
            "fetch(",
            "https://",
            "http://",
        ]
        count = sum(marker in lower for marker in markers)
        leading = len(longest) - len(longest.lstrip())
        obfuscated = bool(
            re.search(r"(?:eval\s*\(|new\s+Function)[\s\S]{0,400}?(?:Buffer\.from|atob\s*\(|fromCharCode)", text, re.I)
            or re.search(r"_0x[a-f0-9]{4,}", text, re.I)
        )
        padded = len(longest) > 900 or leading >= 300
        if obfuscated and (count >= 2 or padded):
            severity = "high"
            message = "JavaScript config contains an obfuscated execution pattern, with padding or multiple loader markers."
        elif padded and count >= 1:
            severity = "high"
            message = "JavaScript config contains execution/network markers on an oversized or whitespace-padded line."
        elif len(longest) > 900:
            severity = "low"
            message = "Oversized config line may be minified or whitespace-padded; review manually."
        else:
            return
        self.add(
            Finding(
                "PR005",
                "Obfuscated or padded JavaScript config loader",
                severity,
                path,
                longest_index,
                message,
                source,
                f"line_length={len(longest)}; markers={count}; leading_whitespace={leading}; obfuscated={obfuscated}",
            )
        )

    def _scan_batch(self, path: str, text: str, source: str) -> None:
        lower = text.lower()
        markers = {
            "amend": bool(re.search(r"git\s+commit\b[^\r\n]*--amend", lower)),
            "force_push": bool(re.search(r"git\s+push\b[^\r\n]*(?:-f|--force)", lower)),
            "spoof_name": "git config user.name" in lower,
            "spoof_email": "git config user.email" in lower,
            "clock": bool(re.search(r"\b(?:date|time|set-date)\b", lower)),
        }
        count = sum(markers.values())
        known_name = Path(path).name.lower() in {"temp_auto_push.bat", "temp_interactive_push.bat"}
        propagation_cluster = "last_commit_date" in lower and "last_commit_time" in lower
        if count >= 3 or known_name or propagation_cluster:
            self.add(
                Finding(
                    "PR006",
                    "Git-history laundering batch script",
                    "high",
                    path,
                    1,
                    "Batch script name or content matches publicly reported PolinRider history-rewrite propagation.",
                    source,
                    ", ".join(key for key, matched in markers.items() if matched),
                )
            )

    def _scan_campaign_strings(self, path: str, text: str, source: str) -> None:
        lower = text.lower()
        for item in self.rules.campaign_strings:
            value = item["value"]
            if value.lower() not in lower:
                continue
            self.add(
                Finding(
                    "PR007",
                    "Known campaign indicator",
                    item["severity"],
                    path,
                    line_for(text, value),
                    item["description"],
                    source,
                    value,
                )
            )

    def _scan_payload_signatures(self, path: str, text: str, source: str) -> None:
        if (
            "polinrider malware scanner" in text.lower()
            and re.search(r"^\s*PRIMARY_SIG=", text, re.MULTILINE)
            and re.search(r"^\s*SECONDARY_SIG=", text, re.MULTILINE)
        ):
            return
        lower = text.lower()
        for signature in self.rules.payload_signatures:
            markers = [str(value) for value in signature.get("all_of", []) if value]
            if not markers or not all(marker.lower() in lower for marker in markers):
                continue
            first = markers[0]
            self.add(
                Finding(
                    "PR010",
                    str(signature.get("name", "PolinRider source-code fingerprint")),
                    str(signature.get("severity", "critical")),
                    path,
                    line_for(text, first),
                    "File contains a corroborated PolinRider loader fingerprint cluster.",
                    source,
                    " + ".join(markers),
                )
            )

    def _scan_orchestrator(self, path: str, text: str, source: str) -> None:
        name = Path(path).name.lower()
        if name == "config.bat":
            self.add(
                Finding(
                    "PR011",
                    "Possible PolinRider propagation orchestrator",
                    "medium",
                    path,
                    1,
                    "A config.bat file is supporting evidence in public PolinRider investigations; review its contents and nearby findings.",
                    source,
                )
            )
        elif name == ".gitignore" and re.search(r"(?m)^\s*config\.bat\s*$", text, re.I):
            self.add(
                Finding(
                    "PR011",
                    "PolinRider-associated ignored orchestrator",
                    "medium",
                    path,
                    line_for(text, "config.bat"),
                    ".gitignore hides config.bat, a propagation pattern reported in PolinRider investigations.",
                    source,
                    "config.bat",
                )
            )

    def _scan_packages(self, path: str, text: str, source: str) -> None:
        lower = text.lower()
        for package, artifacts in sorted(self.rules.affected_packages.items()):
            pattern = rf"(?<![A-Za-z0-9_.-]){re.escape(package.lower())}(?![A-Za-z0-9_.-])"
            if not re.search(pattern, lower):
                continue
            versions = sorted(
                {
                    version
                    for artifact in artifacts
                    for version in artifact.get("versions", [])
                    if version
                }
            )
            matched_versions = [version for version in versions if version_token_present(lower, version)]
            exact = bool(matched_versions)
            security_placeholder_only = exact and all(
                version.endswith("-security") for version in matched_versions
            )
            severity = "medium" if not exact or security_placeholder_only else "high"
            if exact:
                detail = "affected version(s) " + ", ".join(matched_versions[:5])
            else:
                detail = "version could not be confirmed from this file"
            self.add(
                Finding(
                    "PR008",
                    "Campaign-associated package",
                    severity,
                    path,
                    line_for(text, package),
                    f"Manifest or lockfile references Socket-listed package {package!r}; {detail}.",
                    source,
                    package,
                )
            )

    def add_chain_findings(self) -> None:
        by_source: dict[str, list[Finding]] = {}
        for finding in self.findings:
            by_source.setdefault(finding.source, []).append(finding)
        for source, findings in by_source.items():
            task_findings = [finding for finding in findings if finding.rule_id == "PR002"]
            for task in task_findings:
                marker = ".vscode/tasks.json"
                marker_index = task.path.lower().rfind(marker)
                if marker_index < 0:
                    continue
                root = task.path[:marker_index].rstrip("/")
                payload_path = (
                    f"{root}/public/fonts/fa-solid-400.woff2"
                    if root
                    else "public/fonts/fa-solid-400.woff2"
                )
                has_payload = any(
                    finding.rule_id in {"PR001", "PR004"}
                    and finding.path.lstrip("/").lower() == payload_path.lower()
                    for finding in findings
                )
                if has_payload:
                    self.add(
                        Finding(
                            "PR009",
                            "PolinRider execution chain present",
                            "critical",
                            task.path,
                            task.line,
                            "The same project contains an automatic folder-open task and the disguised font payload path.",
                            source,
                        )
                    )

    def scan_git_history(self, target: Path) -> None:
        root = git_root(target)
        if root is None:
            self.errors.append(f"--git-history requested but no Git repository found at {target}")
            return
        start_objects = self.stats.git_objects_seen
        start_blobs = self.stats.git_blobs_read
        self.progress(f"git history: enumerating objects in {root}", force=True)
        try:
            object_lines = run_git(
                root, ["rev-list", "--objects", "--all", "--missing=print"]
            ).decode(
                "utf-8", "surrogateescape"
            ).splitlines()
        except (OSError, subprocess.CalledProcessError) as exc:
            self.errors.append(f"cannot enumerate Git history at {root}: {format_process_error(exc)}")
            return

        oid_paths: dict[str, list[str]] = {}
        missing_objects = 0
        for raw in object_lines:
            if not raw:
                continue
            if raw.startswith("?"):
                missing_objects += 1
                continue
            oid, _, path = raw.partition(" ")
            if path:
                oid_paths.setdefault(oid, []).append(path)
        if missing_objects:
            self.errors.append(
                f"Git history incomplete at {root}: {missing_objects} promised objects "
                "are missing locally; network fetching was disabled"
            )
        self.stats.git_objects_seen += len(oid_paths)
        self.progress(
            f"git history: {len(oid_paths):,} named objects; selecting candidate blobs",
            force=True,
        )
        if not oid_paths:
            return

        oids = list(oid_paths)
        request = ("\n".join(oids) + "\n").encode("ascii")
        try:
            checked = run_git(
                root,
                ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                input_bytes=request,
            ).decode("ascii", "replace")
        except (OSError, subprocess.CalledProcessError) as exc:
            self.errors.append(f"cannot inspect Git object metadata: {format_process_error(exc)}")
            return

        candidates: list[tuple[str, int]] = []
        for line in checked.splitlines():
            parts = line.split()
            if len(parts) != 3 or parts[1] != "blob":
                continue
            oid, _, raw_size = parts
            try:
                size = int(raw_size)
            except ValueError:
                continue
            paths = oid_paths.get(oid, [])
            if size in self.rules.payload_sizes or (
                size <= self.max_bytes and any(is_content_candidate(path) for path in paths)
            ):
                candidates.append((oid, size))

        if not candidates:
            self.progress(f"git history: no candidate blobs in {root}", force=True)
            return
        self.progress(
            f"git history: reading {len(candidates):,} unique candidate blobs",
            force=True,
        )
        for oid_batch in git_blob_batches(candidates):
            request = ("\n".join(oid_batch) + "\n").encode("ascii")
            try:
                batch = run_git(root, ["cat-file", "--batch"], input_bytes=request)
            except (OSError, subprocess.CalledProcessError) as exc:
                self.errors.append(f"cannot read selected Git blobs: {format_process_error(exc)}")
                return
            if not self._scan_git_batch(batch, oid_batch, oid_paths):
                return
            self.progress(
                f"git history: {self.stats.git_blobs_read:,}/{len(candidates):,} "
                f"candidate blobs read, {len(self.findings):,} findings"
            )
        self.progress(
            f"git history: finished {root} "
            f"({self.stats.git_objects_seen - start_objects:,} objects, "
            f"{self.stats.git_blobs_read - start_blobs:,} candidate blobs)",
            force=True,
        )

    def _scan_git_batch(
        self, batch: bytes, expected_oids: Sequence[str], oid_paths: dict[str, list[str]]
    ) -> bool:
        cursor = 0
        for expected_oid in expected_oids:
            newline = batch.find(b"\n", cursor)
            if newline < 0:
                self.errors.append("truncated response from git cat-file --batch")
                return False
            header = batch[cursor:newline].decode("ascii", "replace")
            cursor = newline + 1
            parts = header.split()
            if len(parts) != 3 or parts[1] != "blob":
                self.errors.append(f"unexpected git cat-file response: {header}")
                return False
            oid, _, raw_size = parts
            if oid != expected_oid:
                self.errors.append(
                    f"unexpected Git object {oid}; expected {expected_oid}"
                )
                return False
            try:
                size = int(raw_size)
            except ValueError:
                self.errors.append(f"invalid Git blob size for {oid}: {raw_size}")
                return False
            data = batch[cursor : cursor + size]
            cursor += size
            if cursor >= len(batch) or batch[cursor : cursor + 1] != b"\n":
                self.errors.append(f"malformed Git blob response for {expected_oid}")
                return False
            cursor += 1
            self.stats.git_blobs_read += 1
            self.stats.bytes_read += len(data)
            source = f"git:{oid}"
            digest = hashlib.sha256(data).hexdigest()
            for path in oid_paths.get(oid, ["<unknown>"]):
                if self._excluded(path, is_dir=False):
                    continue
                if self._worktree_digests.get(path.replace("\\", "/")) == digest:
                    continue
                if len(data) in self.rules.payload_sizes or is_content_candidate(path):
                    self.scan_bytes(path, data, source=source)
        if cursor != len(batch):
            self.errors.append("unexpected trailing data from git cat-file --batch")
            return False
        return True


def safe_resolve(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except OSError:
        return path.absolute()


def posix_relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def has_valid_asset_magic(suffix: str, data: bytes) -> bool:
    if suffix == ".eot":
        # Embedded OpenType stores the little-endian 0x504c magic at offset 34.
        return len(data) >= 36 and data[34:36] == b"LP"
    magics = ASSET_MAGICS.get(suffix, ())
    return bool(magics and data.startswith(magics))


def git_blob_batches(
    candidates: Sequence[tuple[str, int]], max_bytes: int = GIT_BATCH_BYTES
) -> Iterator[list[str]]:
    """Group Git blobs so cat-file output stays within a bounded memory window."""
    batch: list[str] = []
    batch_bytes = 0
    for oid, size in candidates:
        if batch and batch_bytes + size > max_bytes:
            yield batch
            batch = []
            batch_bytes = 0
        batch.append(oid)
        batch_bytes += size
    if batch:
        yield batch


def is_content_candidate(path: str) -> bool:
    lower = path.replace("\\", "/").lower()
    name = Path(lower).name
    return (
        Path(lower).suffix in SUSPICIOUS_ASSET_SUFFIXES
        or is_vscode_file(lower, "tasks.json")
        or is_vscode_file(lower, "settings.json")
        or bool(CONFIG_JS_RE.search(name))
        or lower.endswith((".bat", ".cmd"))
        or name == ".gitignore"
        or name in MANIFEST_NAMES
        or is_ioc_text_candidate(lower)
    )


def is_scanner_json_report(path: str, data: bytes) -> bool:
    if not path.lower().endswith(".json") or b"polinrider-scan" not in data.lower():
        return False
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(document, dict):
        return False
    scanner = document.get("scanner")
    if isinstance(scanner, dict) and scanner.get("name") == "polinrider-scan":
        return True
    runs = document.get("runs")
    return bool(
        isinstance(runs, list)
        and any(
            isinstance(run, dict)
            and isinstance(run.get("tool"), dict)
            and isinstance(run["tool"].get("driver"), dict)
            and run["tool"]["driver"].get("name") == "polinrider-scan"
            for run in runs
        )
    )


def is_vscode_file(path: str, name: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    target = f".vscode/{name.lower()}"
    return normalized == target or normalized.endswith("/" + target)


def is_text_rule_candidate(path: str) -> bool:
    lower = path.lower()
    return (
        Path(lower).suffix in TEXT_IOC_SUFFIXES
        or Path(lower).name in MANIFEST_NAMES
        or Path(lower).name == ".gitignore"
    )


def is_ioc_text_candidate(path: str) -> bool:
    lower = path.lower()
    name = Path(lower).name
    if name == "polinrider_iocs.json":
        return False
    return Path(lower).suffix in TEXT_IOC_SUFFIXES or name in MANIFEST_NAMES or name == ".gitignore"


def decode_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", "replace").replace("\x00", "")


def line_for(text: str, needle: str) -> int:
    index = text.lower().find(needle.lower())
    return 1 if index < 0 else text.count("\n", 0, index) + 1


def version_token_present(lower_text: str, version: str) -> bool:
    escaped = re.escape(version.lower())
    return bool(re.search(rf"(?<![A-Za-z0-9_.+-]){escaped}(?![A-Za-z0-9_.+-])", lower_text))


def load_rules(path: Path) -> Rules:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load rules from {path}: {exc}") from exc
    if raw.get("schema_version") != 1:
        raise ValueError(f"unsupported rules schema in {path}")

    payload_by_hash: dict[str, dict[str, Any]] = {}
    payload_sizes: set[int] = set()
    for payload in raw.get("payloads", []):
        digest = str(payload.get("sha256", "")).lower()
        size = payload.get("size")
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not isinstance(size, int) or size < 0:
            raise ValueError(f"invalid payload rule in {path}: {payload!r}")
        payload_by_hash[digest] = payload
        payload_sizes.add(size)

    payload_signatures: list[dict[str, Any]] = []
    for signature in raw.get("payload_signatures", []):
        markers = [str(value) for value in signature.get("all_of", []) if value]
        severity = str(signature.get("severity", ""))
        if len(markers) < 2 or severity not in SEVERITY_RANK:
            raise ValueError(f"invalid payload signature in {path}: {signature!r}")
        payload_signatures.append(
            {
                "name": str(signature.get("name", "PolinRider source-code fingerprint")),
                "all_of": markers,
                "severity": severity,
                "source": str(signature.get("source", "")),
            }
        )

    campaign_strings: list[dict[str, str]] = []
    for item in raw.get("campaign_strings", []):
        value = str(item.get("value", ""))
        severity = str(item.get("severity", ""))
        description = str(item.get("description", ""))
        if not value or severity not in SEVERITY_RANK or not description:
            raise ValueError(f"invalid campaign string rule in {path}: {item!r}")
        campaign_strings.append(
            {"value": value, "severity": severity, "description": description}
        )

    packages: dict[str, list[dict[str, Any]]] = {}
    for value in raw.get("affected_packages", []):
        if isinstance(value, str) and value:
            packages.setdefault(value.lower(), []).append(
                {"ecosystem": "unspecified", "versions": []}
            )
        elif isinstance(value, dict) and value.get("name"):
            name = str(value["name"]).lower()
            packages.setdefault(name, []).append(
                {
                    "ecosystem": str(value.get("ecosystem", "unspecified")),
                    "versions": [str(item) for item in value.get("versions", []) if item],
                }
            )

    csv_name = raw.get("affected_packages_csv")
    if csv_name:
        csv_path = path.parent / str(csv_name)
        try:
            with csv_path.open("r", encoding="utf-8", newline="") as handle:
                for row in csv.DictReader(handle):
                    ecosystem = (row.get("Ecosystem") or "unspecified").lower()
                    namespace = row.get("Namespace") or ""
                    raw_name = row.get("Name") or ""
                    if not raw_name:
                        continue
                    name = f"{namespace}/{raw_name}" if namespace else raw_name
                    key = name.lower()
                    version = row.get("Version") or ""
                    existing = next(
                        (
                            item
                            for item in packages.get(key, [])
                            if item.get("ecosystem") == ecosystem
                        ),
                        None,
                    )
                    if existing is None:
                        existing = {"ecosystem": ecosystem, "versions": []}
                        packages.setdefault(key, []).append(existing)
                    if version and version not in existing["versions"]:
                        existing["versions"].append(version)
        except (OSError, csv.Error) as exc:
            raise ValueError(f"cannot load affected-package CSV {csv_path}: {exc}") from exc

    return Rules(payload_by_hash, payload_sizes, payload_signatures, campaign_strings, packages)


def git_root(target: Path) -> Path | None:
    candidate = target if target.is_dir() else target.parent
    try:
        output = run_git(candidate, ["rev-parse", "--show-toplevel"])
    except (OSError, subprocess.CalledProcessError):
        return None
    return safe_resolve(Path(output.decode("utf-8", "surrogateescape").strip()))


def discover_git_repositories(target: Path, scanner: Scanner) -> list[Path]:
    direct = git_root(target)
    if direct is not None:
        return [direct]
    target = safe_resolve(target)
    if not target.is_dir():
        return []
    repositories: list[Path] = []
    def walk_error(error: OSError) -> None:
        scanner.errors.append(f"cannot discover Git repositories under {target}: {error}")

    for directory, dirs, files in os.walk(
        target, followlinks=False, onerror=walk_error
    ):
        directory_path = Path(directory)
        relative_dir = posix_relative(directory_path, target)
        if ".git" in dirs or ".git" in files:
            resolved = git_root(directory_path)
            if resolved is not None:
                repositories.append(resolved)
                dirs[:] = []
                continue
            # Ignore a stale/incomplete .git entry but continue looking below it.
            dirs[:] = [name for name in dirs if name != ".git"]
        dirs[:] = [
            name
            for name in dirs
            if not (directory_path / name).is_symlink()
            and not scanner._excluded(
                name if relative_dir == "." else f"{relative_dir}/{name}", is_dir=True
            )
        ]
    return repositories


def git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "protocol.allow",
            "GIT_CONFIG_VALUE_0": "never",
        }
    )
    return environment


def run_git(root: Path, args: Sequence[str], *, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env=git_environment(),
        timeout=300,
    )
    return completed.stdout


def format_process_error(exc: BaseException) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        return exc.stderr.decode("utf-8", "replace").strip() or str(exc)
    return str(exc)


def result_document(scanner: Scanner, roots: Sequence[Path], exit_code: int) -> dict[str, Any]:
    findings = sorted(
        scanner.findings,
        key=lambda item: (-SEVERITY_RANK[item.severity], item.path, item.line, item.rule_id),
    )
    return {
        "scanner": {"name": "polinrider-scan", "version": VERSION},
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "roots": [str(safe_resolve(root)) for root in roots],
        "findings": [finding.as_dict() for finding in findings],
        "errors": scanner.errors,
        "stats": dataclasses.asdict(scanner.stats),
        "exit_code": exit_code,
    }


def text_report(document: dict[str, Any]) -> str:
    lines: list[str] = []
    findings = document["findings"]
    if findings:
        for finding in findings:
            source = "" if finding["source"] == "worktree" else f" [{finding['source']}]"
            lines.append(
                f"{finding['severity'].upper():8} {finding['rule_id']} "
                f"{finding['path']}:{finding['line']}{source} — {finding['message']}"
            )
    else:
        lines.append("No PolinRider indicators found.")
    for error in document["errors"]:
        lines.append(f"ERROR    scan incomplete — {error}")
    stats = document["stats"]
    lines.append(
        f"Scanned {stats['files_seen']} filesystem files and "
        f"{stats['git_blobs_read']} selected Git-history blobs; "
        f"{len(findings)} finding(s), {len(document['errors'])} error(s)."
    )
    return "\n".join(lines) + "\n"


def github_report(document: dict[str, Any]) -> str:
    lines: list[str] = []
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "notice"}
    for finding in document["findings"]:
        path = annotation_escape(finding["path"], property_value=True)
        title = annotation_escape(f"{finding['rule_id']} {finding['title']}", property_value=True)
        message = annotation_escape(finding["message"], property_value=False)
        lines.append(
            f"::{level[finding['severity']]} file={path},line={finding['line']},title={title}::{message}"
        )
    for error in document["errors"]:
        lines.append(f"::error title=PolinRider scan incomplete::{annotation_escape(error, False)}")
    lines.append(annotation_escape(text_report(document).strip(), False))
    return "\n".join(lines) + "\n"


def annotation_escape(value: str, property_value: bool) -> str:
    escaped = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        escaped = escaped.replace(":", "%3A").replace(",", "%2C")
    return escaped


def sarif_report(document: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in document["findings"]:
        rule_id = finding["rule_id"]
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding["title"],
                "shortDescription": {"text": finding["title"]},
                "defaultConfiguration": {
                    "level": "error" if finding["severity"] in {"critical", "high"} else "warning"
                },
                "properties": {"security-severity": str(SEVERITY_RANK[finding["severity"]] * 2.5)},
            },
        )
        message = finding["message"]
        if finding["source"] != "worktree":
            message += f" Source: {finding['source']}."
        results.append(
            {
                "ruleId": rule_id,
                "level": "error" if finding["severity"] in {"critical", "high"} else "warning",
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding["path"]},
                            "region": {"startLine": max(1, int(finding["line"]))},
                        }
                    }
                ],
                "properties": {"severity": finding["severity"], "source": finding["source"]},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "polinrider-scan",
                        "version": VERSION,
                        "informationUri": "https://socket.dev/supply-chain-attacks/polinrider",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not document["errors"],
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": error}}
                            for error in document["errors"]
                        ],
                    }
                ],
            }
        ],
    }


def determine_exit(scanner: Scanner, fail_on: str) -> int:
    if scanner.errors:
        return 2
    threshold = SEVERITY_RANK[fail_on]
    return 1 if any(SEVERITY_RANK[item.severity] >= threshold for item in scanner.findings) else 0


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    default_rules = Path(__file__).with_name("polinrider_iocs.json")
    parser = argparse.ArgumentParser(
        description="Read-only scanner for PolinRider / Contagious Interview indicators."
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Files or directories to scan")
    parser.add_argument("--rules", type=Path, default=default_rules, help="IOC rules JSON")
    parser.add_argument(
        "--git-history",
        action="store_true",
        help="Also scan blobs reachable from all local Git refs (read-only; no checkout)",
    )
    parser.add_argument(
        "--include-vendor",
        action="store_true",
        help="Include dependency/build directories such as node_modules, vendor, dist, and .venv",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude a relative path glob; repeatable",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=8 * 1024 * 1024,
        help="Maximum bytes read for heuristic content rules (default: 8 MiB)",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=1000,
        help="Stop recording findings after this limit (default: 1000)",
    )
    parser.add_argument(
        "--fail-on",
        choices=list(SEVERITY_RANK),
        default="high",
        help="Lowest severity that exits 1 (default: high)",
    )
    parser.add_argument(
        "--progress",
        choices=["auto", "always", "never"],
        default="auto",
        help="Progress updates on stderr (default: auto when attached to a terminal)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif", "github"],
        default="text",
        help="Primary output format",
    )
    parser.add_argument("--output", type=Path, help="Write primary output to this path")
    parser.add_argument("--sarif", type=Path, help="Also write a SARIF 2.1.0 report")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args(argv)
    if args.max_bytes < 1 or args.max_findings < 1:
        parser.error("--max-bytes and --max-findings must be positive")
    return args


def write_output(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        rules = load_rules(args.rules)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    roots = [Path(value) for value in args.paths]
    skip_exact = [Path(__file__), args.rules]
    if args.output:
        skip_exact.append(args.output)
    if args.sarif:
        skip_exact.append(args.sarif)
    scanner = Scanner(
        rules,
        max_bytes=args.max_bytes,
        include_vendor=args.include_vendor,
        excludes=args.exclude,
        skip_exact=skip_exact,
        max_findings=args.max_findings,
        progress=args.progress == "always" or (args.progress == "auto" and sys.stderr.isatty()),
    )
    for root in roots:
        scanner.scan_path(root)
    if args.git_history:
        if not scanner.git_repositories:
            scanner.errors.append(
                "--git-history requested but no Git repository was found under the scan roots"
            )
        for repository in sorted(scanner.git_repositories):
            scanner.scan_git_history(repository)
    scanner.add_chain_findings()

    exit_code = determine_exit(scanner, args.fail_on)
    document = result_document(scanner, roots, exit_code)
    if args.format == "json":
        rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    elif args.format == "sarif":
        rendered = json.dumps(sarif_report(document), indent=2, sort_keys=True) + "\n"
    elif args.format == "github":
        rendered = github_report(document)
    else:
        rendered = text_report(document)

    if args.output:
        write_output(args.output, rendered)
        print(text_report(document), end="")
    else:
        print(rendered, end="")
    if args.sarif:
        write_output(args.sarif, json.dumps(sarif_report(document), indent=2, sort_keys=True) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
