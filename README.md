# PolinRider static scanner

A dependency-free, read-only scanner for repository indicators associated with
PolinRider and the broader Contagious Interview VS Code task vector. It works as
a local Python CLI and in GitHub Actions. It never imports or executes target
files, installs target dependencies, checks out historical files, or makes a
network request while scanning.

## What public research confirmed

The AI-generated incident artifact was treated as an unverified lead. The
scanner's behavioral rules were independently checked against public sources:

- Socket confirms the PolinRider campaign name, whitespace-padded JavaScript in
  `*config.js` files, fake `.woff2` loaders, hidden VS Code task execution, and
  Git history rewriting. Socket recommends auditing `runOn: "folderOpen"`
  tasks, commands that pass atypical file extensions to Node, config files, and
  font/static asset directories.
- Abstract Security independently documents the Contagious Interview task
  vector, including `folderOpen`, the `eslint-check` label, Node executing font,
  image, CSS, and dictionary files, inline `node -e` loaders, and downloaders
  piped to shells.
- Microsoft documents that `task.allowAutomaticTasks` controls `folderOpen`
  tasks. Automatic tasks do not run in an untrusted workspace. The supported
  values are `"on"` and `"off"`; the scanner also detects the legacy/observed
  boolean `true` form.
- The package/version rules are a dated local snapshot of Socket's live
  PolinRider CSV feed, not names copied from the incident artifact.
- Sonatype and the public OpenSourceMalware scanner corroborate the exact V1
  decoder markers. The latter also confirms the observed propagation filenames
  and supporting `config.bat`/`.gitignore` pattern. A separately reported V2
  decoder marker is included as a content fingerprint, with its lower source
  confidence recorded in the rules file.

Only one of the artifact's four SHA-256 values (`53abf377...a0e8`) could be
corroborated publicly, and it is the only one enabled. Its weaker public source
chain is recorded in the rule metadata. The other three hashes, the artifact's
uncorroborated package claims, generic service domain, exact IP/port claim, and
case-specific AWS pivot are not used as default campaign detections.

See [research/polinrider-scanner.md](research/polinrider-scanner.md) for the
cited validation record and confidence notes.

## Use from another repository

Because this repository and its reusable workflow are public, repositories in
other GitHub organizations can call the scanner without copying its code or
granting it a personal access token. The scan executes on the caller's runner
and uses the caller's normal GitHub Actions minutes.

Copy [`examples/workflow-dispatch.yml`](examples/workflow-dispatch.yml) to
`.github/workflows/polinrider-scan.yml` in the repository to scan, then replace
`REPLACE_WITH_FULL_COMMIT_SHA` with a reviewed full commit SHA from this
repository. Pinning the call prevents a future branch or tag update from
silently changing code executed in the caller.

The example adds a manual **Run workflow** button and calls:

```yaml
jobs:
  scan:
    uses: IanAMDG/polinrider-scanner/.github/workflows/reusable-scan.yml@REPLACE_WITH_FULL_COMMIT_SHA
    with:
      git_history: true
      fail_on: high
      upload_sarif: true
```

The target organization's Actions policy must allow actions and reusable
workflows from `IanAMDG/polinrider-scanner`. An organization administrator may
need to add that repository to the allowed list. The caller grants only
`contents: read` and `security-events: write`; set `upload_sarif: false` and
omit `security-events: write` if GitHub code scanning is unavailable.

The reusable workflow checks out the target repository and then obtains the
scanner from `job.workflow_repository` at `job.workflow_sha`. This means the
scanner source is tied to the exact reusable-workflow revision selected by the
caller. It never runs code from the target repository. This mechanism requires
GitHub.com; the two `job.workflow_*` properties are not currently available on
GitHub Enterprise Server.

Supported inputs are:

| Input | Default | Meaning |
| --- | --- | --- |
| `git_history` | `true` | Scan blobs reachable from the caller's local Git refs |
| `include_vendor` | `false` | Include dependency and build directories |
| `fail_on` | `high` | Fail at `low`, `medium`, `high`, or `critical` severity |
| `upload_sarif` | `true` | Best-effort upload to GitHub code scanning |

## Install a self-contained copy

Copy this directory's contents into the root of the repository. The expected
layout is:

```text
.github/workflows/polinrider-scan.yml
tools/polinrider_scan.py
tools/polinrider_iocs.json
tools/polinrider_packages.csv
```

No Python packages are required. Python 3.9 or newer is recommended.

## Run locally

Scan a working tree:

```bash
python3 tools/polinrider_scan.py /path/to/repository
```

On Windows, run the same dependency-free scanner from PowerShell with the
Python launcher (or substitute `python` if that is how Python is installed):

```powershell
py -3 tools/polinrider_scan.py C:\path\to\repository
```

Also scan every blob reachable from the repository's local refs, without
checking historical files out:

```bash
python3 tools/polinrider_scan.py /path/to/repository --git-history
```

History scanning is offline. Git lazy fetching and all Git transport protocols
are disabled; a partial clone is scanned using the objects already present and
reported as incomplete when promised objects are missing. `--git-history`
requires the Git command-line client; worktree-only scanning does not.

Progress is automatic on an interactive terminal and is written to stderr, so
JSON and SARIF on stdout stay valid. Force it on or off with:

```bash
python3 tools/polinrider_scan.py . --git-history --progress always
python3 tools/polinrider_scan.py . --progress never --format json
```

Include dependency and build directories that are skipped by default:

```bash
python3 tools/polinrider_scan.py /path/to/repository --include-vendor
```

Machine-readable reports:

```bash
python3 tools/polinrider_scan.py . --format json --output scan.json
python3 tools/polinrider_scan.py . --format sarif --output scan.sarif
```

Exit codes are stable:

- `0`: scan completed; no finding at or above `--fail-on` (default: `high`)
- `1`: at least one finding met the failure threshold
- `2`: scan was incomplete or configuration was invalid

Medium and low findings are still reported. Use `--fail-on medium` for a
strict review gate.

## GitHub Actions

The included standalone workflow runs in this repository on pushes, pull
requests, weekly, and by manual dispatch. It:

1. checks out full history with credentials disabled after checkout;
2. on pull requests, loads the scanner and rule data from the trusted base
   commit rather than executing the pull request's copy;
3. scans the worktree and blobs reachable from all local refs with rate-limited
   phase, repository-discovery, file, and Git-blob progress on every run;
4. emits native GitHub log annotations;
5. writes SARIF and attempts to upload it to code scanning; and
6. fails on high or critical findings, or if the scan is incomplete.

Third-party actions are pinned to full commit SHAs. Dependabot or a deliberate
reviewed update should advance those pins.

SARIF upload requires code scanning to be available for the repository. The
upload is best-effort so the scanner and annotations still work when that
feature is unavailable or a pull request comes from a fork.

## Detections

| Rule | Signal | Default severity |
| --- | --- | --- |
| `PR001` | Exact publicly corroborated payload SHA-256 | Critical; weaker-source-chain confidence recorded |
| `PR002` | `folderOpen` task plus non-source asset execution, piped downloader, inline loader, or campaign infrastructure | Critical |
| `PR002A` | `folderOpen` task plus observed label or hidden presentation | High |
| `PR002B` | Other automatic `folderOpen` task | Medium; review |
| `PR003` | Automatic VS Code tasks explicitly enabled | Medium; review |
| `PR004` | Invalid static-asset magic plus JavaScript characteristics or observed fake-font path | High/critical |
| `PR005` | Obfuscated or whitespace-padded JavaScript config loader | High, or low for an oversized line alone |
| `PR006` | Batch script combining amend, force-push, identity spoofing, and clock manipulation | High |
| `PR007` | Publicly corroborated campaign domain or Chrome extension ID | High |
| `PR008` | Socket-listed package; high only when an affected version is visible | Medium/high |
| `PR009` | Correlated automatic task and fake-font path in one project | Critical |
| `PR010` | Exact V1/V2 PolinRider decoder source fingerprint | Critical/high |
| `PR011` | Observed propagation filename or `config.bat` plus `.gitignore` orchestration | High/medium |

The scanner deliberately requires correlated behavior for its strongest
heuristics. A `.woff2` filename, a large JavaScript line, or a `folderOpen` task
alone is not treated as confirmed malware.

## Relationship to the public shell scanner

The public `polinrider-scanner.sh` is a good, intentionally narrow first-pass
scanner. This implementation adopts its strongest exact V1 fingerprints,
propagation filenames, and orchestrator evidence. It extends coverage to the
reported V2 fingerprint, VS Code task variants, fake assets, affected package
versions, SARIF, and reachable Git history. To keep that broader scan fast, it
hashes exact-size candidates, reads only relevant file types, skips dependency
and build trees by default, deduplicates Git objects, suppresses duplicate
current-tree/history findings, batches historical blobs into bounded memory
windows, discovers repositories during the filesystem pass, and rate-limits
progress output. It recognizes its own JSON reports and the public shell
scanner's signature declarations so IOC reference material is not diagnosed as
a payload.

The shell scanner's suggested immediate history rewrite is intentionally not
automated here. Preserve evidence and determine scope before any force-push or
destructive cleanup.

## Update the package snapshot

The included CSV is a snapshot retrieved from Socket on 2026-08-20. Review the
diff before committing an update:

```bash
curl -fsSL \
  https://socket.dev/api/public/supply-chain-attacks/polinrider/packages.csv \
  -o tools/polinrider_packages.csv
git diff -- tools/polinrider_packages.csv
```

The scanner itself remains offline. `polinrider_iocs.json` contains the static
hash and infrastructure rules and can be reviewed or replaced independently.

## Safety and limitations

- Do not open a suspected repository in VS Code, Cursor, or another IDE before
  inspecting it. Clone/checkout and this scanner do not execute repository
  content; editor and build actions can.
- A clean static scan does not prove the host is clean. It cannot detect a
  second stage that already executed and self-removed, memory-only activity,
  stolen credentials, or a compromised browser session.
- `--git-history` scans blobs reachable from local refs. It cannot recover a
  deleted remote branch that was never fetched, expired GitHub audit events, or
  objects already pruned from the local repository.
- Symlinks are not followed, keeping a repository scan inside the requested
  tree. Dependency/build directories are skipped unless `--include-vendor` is
  supplied.
- On a hit, preserve evidence before deletion, isolate the endpoint, and rotate
  exposed credentials from a known-clean device. Static scanning is triage, not
  incident closure.

## Test

```bash
python3 -m unittest discover -s tests -v
```

The tests construct inert synthetic fixtures in temporary directories. No
malware sample or affected repository is included or downloaded.
