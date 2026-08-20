# PolinRider / Contagious Interview static-scanner research

Research date: 2026-08-20 (America/Chicago)

## Scope and safety boundary

This note supports a scanner that runs locally and in GitHub Actions. The research was limited to first-party threat reports, official product documentation, standards, and a vendor-maintained IOC feed. No affected repository was cloned or downloaded, no package or payload sample was retrieved, and no untrusted code was executed. The only machine-readable campaign data read was Socket's public package/extension CSV, which is an IOC list rather than a repository or package artifact.

The scanner should make the same distinction: it should **read bytes and metadata only**. It must not import or `require()` JavaScript, invoke npm/Composer/Go tooling, launch an editor, evaluate configuration files, run GitHub workflow content, or attempt to deobfuscate by executing a suspect string.

## Independent audit of the linked Claude artifact

The linked page identifies itself as **“Content is user-generated and unverified.”** It was inspected only as rendered text. It is not an authoritative threat-intelligence source, and none of its host-specific incident assertions should be inherited into scanner rules without an independent source. The table below audits the claims that materially affect a scanner.

| Artifact claim | Independent result | Scanner consequence |
|---|---|---|
| The campaign is called PolinRider and overlaps DPRK-linked Contagious Interview / Famous Chollima activity. | **Corroborated, high confidence.** Socket uses the PolinRider name on its live tracker and in first-party incident reports; OpenSourceMalware also publishes first-party research under that name. | The family name is safe to use, while results for broader related rules should still be labeled “Contagious Interview” rather than automatically attributed to PolinRider. |
| Delivery commonly uses fake developer interviews/coding assignments, and later stages steal credentials, browser data, developer tokens, and wallets. | **Corroborated, very high confidence.** Socket, JFrog, and Microsoft each document this broader campaign model and recovered stealer/backdoor capabilities. [JFrog analysis](https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/), [Microsoft Contagious Interview analysis](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/) | Use the behavior to explain risk and incident-response urgency. A repository-only static scanner cannot prove that any data was stolen or that a host is clean. |
| A hidden `.vscode/tasks.json` task named `eslint-check`, with `runOn: "folderOpen"`, runs `node ./public/fonts/fa-solid-400.woff2`; the file is JavaScript rather than a font. | **Corroborated, very high confidence.** JFrog publishes that exact task label, command path, and trigger. Abstract Security independently documents the `eslint-check` pattern and Node execution of `.woff`, `.woff2`, `.svg`, `.jpeg`, `.png`, and `.dict` files. JFrog’s analyzed loader was preceded by 752 **space** characters; the artifact’s exact “null-padded” description and local byte count were not independently verified. [JFrog analysis](https://research.jfrog.com/post/hijacked-npm-vscode-tasks-blockchain/), [Abstract Security analysis](https://www.abstract.security/blog/contagious-interview-tracking-the-vs-code-tasks-infection-vector) | Treat the exact compound behavior as critical. Also implement extension-agnostic rules because the campaign has used several asset types and paths. Detect whitespace and NUL padding as shapes, but neither padding form alone is a family IOC. |
| `.vscode/settings.json` containing `task.allowAutomaticTasks:true` “disarms” the prompt and guarantees zero-interaction execution. | **Only partly corroborated; current-form claim is inaccurate.** VS Code documents the current setting as a string enum: `"on"` or `"off"`, with `"off"` the default. Automatic tasks never run in an untrusted workspace. Microsoft’s current source schema also defines a string enum; boolean `true` is a legacy/invalid value associated with a fixed 2022 bug. [VS Code Tasks docs](https://code.visualstudio.com/docs/debugtest/tasks), [VS Code setting schema](https://github.com/microsoft/vscode/blob/main/src/vs/workbench/contrib/tasks/browser/task.contribution.ts), [legacy bug](https://github.com/microsoft/vscode/issues/158285) | Flag both `"on"` and legacy boolean `true` as suspicious supporting evidence, but do not claim that current VS Code will honor boolean `true`. A task still requires a trusted workspace or an explicit automatic-task allowance. |
| Obfuscated JavaScript is appended to otherwise legitimate `*config.js` files and hidden after a very large horizontal whitespace gap. | **Corroborated, very high confidence.** Socket directly documents the technique in its campaign and Packagist investigations; Abstract independently documents horizontal whitespace concealment in malicious VS Code tasks. [Socket Packagist analysis](https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package), [Socket campaign analysis](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands) | Scan recursively and by content, not only at the repository root or only files literally named `config.js`. A long line/whitespace run alone is contextual, not a malware verdict. |
| Four fake-font SHA-256 values are “published IOCs”: `53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8` (v1), `e7d740510f261fcc711cedd9686581812a4d271edfd485e44df4aeb121de8d86` (v2), `9fbb31129c04e8eb1a50519fc864c74d1b20d57c07d4099348f8fbc9a1a1eae6` (v3), and `6250fc1ab5eab3cb1347344739e4549d139a9a36cab098b98e5baed4cdbc217d` (v4). | **Only the first is publicly corroborated.** [Nextron Research](https://x.com/nextronresearch/status/2069802303817679083) publicly associated `53ab…a0e8` with `fa-solid-400.woff2`, and it is reproduced in vendor/community IOC reporting. No indexed first-party or high-trust public source was found for the artifact’s other three exact hashes, byte sizes, or v2/v3/v4 labels. Moreover, OpenSourceMalware’s 2026-04-11 update described only two active code variants, whose V2 content markers do not validate the artifact’s three later hashes. | Include `53ab…a0e8` with an explicit weaker-source-chain note. **Do not ship the artifact’s v2/v3/v4 hashes as trusted default IOCs** unless an independent source or preserved sample provenance is supplied. Do not infer variant numbering from hash labels. |
| `react-svg-plugin` and `react-svg-config` are campaign package IOCs. | **Malicious status corroborated; PolinRider attribution not established by the current tracker.** OSV/GitHub Advisory records mark them malicious as [MAL-2025-5167](https://osv.dev/vulnerability/MAL-2025-5167) and [MAL-2025-5517](https://osv.dev/vulnerability/MAL-2025-5517). Neither name appears in Socket’s current PolinRider CSV. | They may be included in a separately labeled malicious-package / broader Contagious Interview rule set. Do not present their presence as proof of PolinRider based solely on the artifact. |
| `api.npoint.io` is a campaign IOC. | **Use in Contagious Interview is corroborated, but it is a legitimate shared storage service.** Abstract documents it as JSON staging infrastructure used by the campaign. | Score only with executable fetch/eval behavior, a known URL path, or another campaign signal; never fail solely on the hostname. |
| `vscode-config.vercel.app`, `vscode-bootstrapper.vercel.app`, and `vscode-setup.vercel.app` are campaign domains. | **Mixed.** Abstract’s first-party IOC appendix corroborates `vscode-config.vercel.app` and `vscode-bootstrapper.vercel.app`; OpenSourceMalware also corroborates the latter. `vscode-setup.vercel.app` was found only in lower-confidence community reporting during this review, not in the primary reports inspected. | Treat the first two as contextual/high in a download-execute task. Keep `vscode-setup.vercel.app` provisional or omit it from the trusted default set. A Vercel hostname alone is not sufficient. |
| `146.70.41.188:1224` is campaign infrastructure. | **Partly reproducible.** The IP appears in public reporting derived from an earlier OpenSourceMalware Contagious Interview report, but the exact `:1224` endpoint was not independently reproduced from the primary sources inspected. It is absent from the current Socket PolinRider IOC set. | Do not promote the exact host:port to a high-confidence default IOC based on the artifact. If retained as optional intelligence, label its weaker provenance. |
| Chrome extension ID `nafkmlanpinblehjeebdjaolelielbgc` is affected. | **Corroborated, high confidence.** Socket’s live CSV lists versions `1.0.1` and `1.0.2`. | Match exact extension ID + affected version. The ID alone does not establish whether a later remediated version is malicious. |
| `temp_auto_push.bat` manipulates dates/authorship, amends commits, and force-pushes to conceal propagation. | **Campaign behavior corroborated, high confidence.** OpenSourceMalware publishes the propagation filename and the internal cluster `LAST_COMMIT_DATE`, `LAST_COMMIT_TIME`, `git commit --amend --no-verify`, and `git push -uf`; Socket independently warns that campaign commit dates/history were manipulated. Whether the artifact’s private repository actually contained this file remains a separate unverified case fact. | Detect the filename plus internal command cluster. Do not infer the real pusher or infection time from forged Git author/date metadata. |
| The campaign totals are 199 artifacts across 123 packages in npm, Composer/Packagist, Go, GitHub Actions, and Chrome. | **Counts corroborated as a dated snapshot; GitHub Actions claim not corroborated.** On 2026-08-20 Socket’s CSV had 199 rows / 123 unique ecosystem+namespace+name values: 65 npm, 49 Composer, 83 Go, and 2 Chrome rows. It had **zero Actions rows**, and the primary reports inspected did not describe a GitHub-Actions-native PolinRider payload. | Use the dated CSV snapshot or an explicit refresh. Scan workflows for the same content/behavior IOCs, but do not invent an Actions-specific family signature or flag normal `actions/*` usage. |
| Named repositories/accounts were infected; several local copies existed; no execution occurred on the inspected host; authors were forged; and case-specific host, identifier, and credential values are pivots/IOCs. | **Not independently reproducible from public campaign research.** These are case-specific assertions about a private host, repositories, identities, credentials, prior remediation attempts, and local evidence. The artifact alone cannot establish them. Exact private-case values are intentionally omitted from this public research record. | Do not embed repo/account/person names, host values, identifiers, or credential strings in a general malware scanner. They belong only in an authenticated incident case record. The scanner also cannot determine past execution or exfiltration from a repository tree. |

Bottom line: the artifact accurately summarizes several real campaign mechanisms, but it mixes those mechanisms with unverifiable private-case assertions, three uncorroborated hashes, an unsupported GitHub Actions ecosystem claim, and an outdated/invalid VS Code setting form. The scanner’s default signature set should include only independently corroborated indicators and should keep provisional or related-family intelligence clearly separated.

## Primary campaign findings

Socket describes PolinRider as an ongoing North Korea-linked campaign associated with the broader Contagious Interview / Famous Chollima cluster. The current tracker says the attackers compromise legitimate maintainers and repositories, inject obfuscated JavaScript loaders, publish malicious release artifacts, and conceal changes through whitespace padding, fake `.woff2` files, VS Code tasks, and rewritten Git history. The observed loader uses TRON, Aptos, and BNB Smart Chain RPC services to retrieve encrypted second-stage material, then decrypts and executes it. [Socket live campaign tracker](https://socket.dev/supply-chain-attacks/polinrider)

Socket's July 1 report documents 162 malicious release artifacts across 108 packages/extensions at publication time, including traces in 80 Go modules, 10 Packagist packages, and one Chrome extension. It says earlier variants put obfuscated JavaScript in `*config.js`; later variants put the loader in fake `.woff2` files and execute it through `.vscode/tasks.json`. The report specifically calls out `vite.config.js`, `eslint.config.js`, other `config.js` files, `.vscode/tasks.json`, and font/static asset directories. It also warns that the GitHub landing page and visible commit dates are not reliable because the campaign used force-pushes and anti-dated commits. [Socket campaign analysis](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands)

The campaign is still changing. On 2026-08-20, Socket's live feed contained **199 affected artifacts / 123 unique ecosystem+namespace+package identifiers**: 65 npm records, 49 Composer records, 83 Go records, and 2 Chrome-extension records. The canonical machine-readable list is [Socket's PolinRider CSV](https://socket.dev/api/public/supply-chain-attacks/polinrider/packages.csv). This should be treated as an updatable IOC source, not copied once and assumed complete forever.

Confidence: **high** for the campaign behavior and affected-artifact records because Socket is the reporting/detection owner. Limitation: the tracker is live and counts or entries can change after this note.

## File and code shapes worth detecting

### 1. Appended, horizontally hidden JavaScript

Socket's Packagist investigation found malicious JavaScript appended after an otherwise ordinary `tailwind.js` export and pushed far to the right with a large whitespace gap. Directly published fingerprints include:

- `global['!']` (an observed example sets it to `9-0264-2`)
- `_$_1e42`
- `rmcej%otb%`
- `global['_V']` / campaign values beginning with `A`
- `eth_getTransactionByHash`
- `windowsHide`
- combinations of the RPC hostnames and the loader's XOR/wallet identifiers below

The same report explains that the loader reconstructs Node.js `require` and `module`, calls `eval()` on decrypted code, and may call `child_process.spawn()` with `detached: true`, `stdio: "ignore"`, and `windowsHide: true`. [Socket Packagist analysis and suggested static search](https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package)

High-confidence static rule: an exact campaign marker or wallet/key is present. Medium/high contextual rule: a build/config file contains a very long whitespace run followed by obfuscated JavaScript plus one or more of `eval`, dynamic `Function`, Node module aliases, detached child-process options, or a campaign RPC string. `eval` or `windowsHide` alone is too generic to call malware.

Files explicitly recommended for review by Socket include:

- `tailwind.js`, `tailwind.config.*`, `postcss.config.*`
- `vite.config.*`, `eslint.config.*`, `next.config.*`, `webpack.mix.js`, and other `*config.js`
- `.vscode/tasks.json`
- `composer.json`, `package.json`, `.github/workflows/*`, and `scripts/*`
- files in font/static asset directories

These are review surfaces, not all confirmed malicious filenames. The scanner should label a filename-only match as context, not a finding.

### 2. Fake font used as JavaScript

Socket directly reports fake `.woff2` font files that contain the JavaScript loader and are passed to Node from a VS Code task. A valid WOFF2 file begins with the four-byte signature `0x77 0x4f 0x46 0x32` (`wOF2`). [W3C WOFF2 Recommendation](https://www.w3.org/TR/WOFF2/) For comparison, OpenType files use `0x00010000` for TrueType outlines or `OTTO` for CFF/CFF2 outlines, and collections begin with `ttcf`. [Microsoft OpenType specification](https://learn.microsoft.com/en-us/typography/opentype/spec/otff)

Recommended static rule:

- A `.woff2` file without `wOF2` is suspicious, but may merely be corrupt or mislabeled.
- Raise confidence sharply if its bytes are mostly text/JavaScript, contain a direct PolinRider fingerprint, contain Node primitives such as `require`, `process`, `child_process`, `Buffer`, `eval`, or `Function`, or are referenced as a `node` argument by a `folderOpen` task.
- Do not decode or run the file. Hash and read a bounded amount of it as bytes.

### 3. VS Code folder-open execution

VS Code's task schema supports `runOptions.runOn: "folderOpen"`. The setting `task.allowAutomaticTasks` controls whether such tasks can run automatically; current documented values are `"off"` (default/prompt) and `"on"` (always run in a trusted workspace). Automatic tasks never run in an untrusted workspace. [VS Code Tasks documentation](https://code.visualstudio.com/docs/debugtest/tasks)

VS Code also documents why this is dangerous: workspace task definitions live in the committed `.vscode` directory, tasks can run scripts and binaries, and Restricted Mode disables or gates tasks, terminals, debugging, workspace settings, extensions, and agents. [VS Code Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust)

Socket's confirmed campaign shape is a hidden `.vscode/tasks.json` task that runs on folder open and executes a fake `.woff2` file with Node. [Socket campaign analysis](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands)

Recommended rules:

- `runOptions.runOn == "folderOpen"` by itself: **medium / suspicious**, because legitimate automatic tasks exist.
- `folderOpen` plus `node`/`node.exe` executing a font or another non-code asset: **critical / high-confidence campaign behavior**.
- `folderOpen` plus shell piping from a downloader (`curl|wget` into `sh|bash|node|python|powershell`), a known IOC, `hide: true`, or `presentation.reveal: "never"`: **high**, although concealment fields alone are not malware.
- `.vscode/settings.json` setting `task.allowAutomaticTasks` to `"on"`: **medium**. Consider also flagging legacy boolean `true` as suspicious input, but note that the current official setting type is the strings `on`/`off`; do not describe `true` as the current documented form.

Local-use advice should say not to open the suspect folder in a trusted VS Code/Cursor workspace before scanning. Restricted Mode is an extra control, not proof that every extension respects it.

### 4. Package and ecosystem variants

Socket documents all of these as PolinRider delivery/compromise surfaces:

- npm packages, including recent import-time implants. Not every variant uses lifecycle scripts; in the Joyfill incident, loading the CommonJS package entrypoint was sufficient, so `npm install --ignore-scripts` did not prevent execution after import.
- Packagist/Composer packages and dev branches, including the `tailwind.js` injection described above.
- Go modules. The July campaign report counted compromise traces in 80 Go modules; the live CSV now contains the exact module/version records.
- Chrome extensions.

The current live campaign page renders ecosystem labels including `actions`, but the reviewed first-party reports did **not** document a distinct PolinRider loader that executes as a GitHub Action. Do not invent one. `.github/workflows/*` is still a high-risk inspection surface and Socket explicitly recommends reviewing it, but the scanner should only emit a PolinRider finding there when content matches a campaign IOC or behavioral rule. GitHub Actions hardening is separately relevant to running the scanner safely.

For manifest/lockfile detection, compare exact name+version tuples from the Socket CSV against:

- npm: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`
- Composer: `composer.json`, `composer.lock`
- Go: `go.mod`, `go.sum` (handle `/go.mod` suffix entries and case variants carefully)

An exact affected name+version is **high**. A package name without the affected version should normally be informational or omitted; some packages are legitimate projects with only particular releases/branches compromised.

## Published exact IOCs

### Core loader/network fingerprints

Directly published by Socket in its Packagist and Joyfill investigations:

| Type | Value | Confidence / caveat |
|---|---|---|
| Marker | `global['!']` | High campaign fingerprint when found in appended/obfuscated config code |
| Marker | `_$_1e42` | High campaign fingerprint |
| Marker | `rmcej%otb%` | High campaign-family fingerprint |
| Protocol | `eth_getTransactionByHash` | Medium alone; high with other fingerprints |
| Domain | `api.trongrid.io` | Medium alone: legitimate public RPC infrastructure |
| Domain | `fullnode.mainnet.aptoslabs.com` | Medium alone: legitimate public RPC infrastructure |
| Domain | `bsc-dataseed.binance.org` | Medium alone: legitimate public RPC infrastructure |
| Domain | `bsc-rpc.publicnode.com` | Medium alone: legitimate public RPC infrastructure |
| IPv4/port | `166.88.134.62:443`, `166.88.134.62:80` | High in the documented chain |
| URL/IP | `23.27.13.43/$/boot` | High in the documented chain |
| IPv4/port | `198.105.127.210:443`, `198.105.127.210:80` | High in the documented chain |
| IPv4/port | `23.27.202.27:443`, `23.27.202.27:27017` | High in the documented chain |
| Protocol marker | `Sec-V` / observed `Sec-V: A9-0135-3` | High with this loader family |
| XOR key | `2[gWfGj;<:-93Z^C` | Very high source-code fingerprint |
| XOR key | `m6:tTh^D)cBz?NM]` | Very high source-code fingerprint in the Packagist loader |
| XOR key | `ThZG+0jfXE6VAGOJ` | Very high DEV#POPPER bootstrap fingerprint |
| TRON | `TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP` | Very high source-code fingerprint |
| TRON | `TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG` | Very high source-code fingerprint |
| TRON | `TA48dct6rFW8BXsiLAtjFaVFoSuryMjD3v` | Very high source-code fingerprint |
| Aptos | `0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e` | Very high source-code fingerprint |
| Aptos | `0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3` | Very high source-code fingerprint |
| Aptos | `0x533b2dbcaeff19cd1f799234a27b578d713d8fcaa341b7501e4526106483e0b1` | Very high source-code fingerprint |

Sources: [Socket Packagist report](https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package), [Socket Joyfill report](https://socket.dev/blog/joyfill-npm-beta-releases-compromised).

The Joyfill report additionally lists three 32-byte blockchain identifiers and an EVM address: `0x18a8420f727f2405f9d1805ad887b31029b584b2ff5a7ec0f57c72635183e99d`, `0x7ffb4efddd96e20aec90724be2ac9a71c138a9af697b9fb8224bbf80ea4f22be`, `0xb6c725890be6890fd2c735eedc47e24b85a350301f6c19a3864e43c35e470968`, and `0x9bc1355344b54dedf3e44296916ed15653844509`.

### SHA-256 values from Socket's Packagist investigation

| Artifact | SHA-256 |
|---|---|
| Affected archive | `522b28a2f78771715497ba53729d4ab9a50e982322c391379f3bddf7c8cb363f` |
| `tailwind.js` | `96afdba882046385242cbed46871e41147c8055c5d9eff7460847b2c01a77dc3` |

Source: [Socket Packagist IOC section](https://socket.dev/blog/famous-chollima-targets-php-developers-through-compromised-packagist-package). Confidence: **very high exact match**. The archive hash is most useful for package/cache scans; a repository tree normally contains the file, not the archive.

### SHA-256 values from Socket's Joyfill investigation

| Artifact | SHA-256 |
|---|---|
| `@joyfill/layouts` archive | `adc4af90540d33cd1e98f44b51482ae9250fbeb97d6f8d7841c81b618cb2c6e6` |
| Layouts CommonJS bundle | `8e8b90dedd456ded0c5748119836e1ca1066112bc569c1b41ca70eb931d1d4dc` |
| Layouts ESM bundle | `5f6a92006ca2ea4b464d66fb41af777edce7296939a7c6ee491e2b3cbfe09848` |
| `@joyfill/components` archive | `bcc93dc55bc7daedf4ca57254f0e7a7f1c40e09851eab98fe10cde801982db17` |
| Components `dist/index.js` | `1352ad22c99983d91e600348b7cbf58235131b1ee34cea9f09623206d5b7dea7` |
| Components `dist/index.esm.js` | `67c6ef602cc850f10d935fee53fa40440df841adf081563bf4fc2631a71249ce` |
| Components `dist/joyfill.min.js` | `c5742ea1875ecd2360022624149994909cd0546e221e4203dffd01f48de45469` |
| In-process first payload | `cb46f12d70824ea24ed1f8bcf45bf3f86680e02a9089aafc03b27f691be57be3` |
| Decoded tier-two resolver | `f452f9cfa539f4a1fe25187a99a484391290d5dbaa422ba455edf6b04f81b7d1` |
| Detached second payload | `78f0de8682e0e894a5784eb7e95db4da6088f528918ca3107dd1e76f80a561d8` |
| Decoded detached bootstrap | `ae7565109fd01b88d82acf7f73ab20709cbc2c9f26fdea13e429ccc87a55d4fb` |
| Final `clientCode` RAT | `26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18` |
| Preserved `/$/boot` body | `26e679eaf1e9baeb7c55eb48db482301171d4d26e1728544b23734a90dc70e1b` |
| Preserved `/$/boot` body | `2cfede38fb121a71a2f3607474aa8cd588a99f51b37e5e6f0d8cb789fa275032` |
| Preserved Python stealer | `36ff00b45e67baa7e3674b0c80f48e88737264c61e5c6b3b091200972de8157c` |

Source: [Socket Joyfill IOC section](https://socket.dev/blog/joyfill-npm-beta-releases-compromised). Confidence: **very high exact match**. Several hashes refer to decoded or remotely captured stages and therefore are unlikely to occur in an ordinary checked-out repository; they are still useful when scanning caches or preserved incident artifacts.

The exact affected Joyfill versions are `@joyfill/layouts@0.1.2-2773.beta.0` and `@joyfill/components@4.0.0-rc24-2773-beta.4`. Socket says the malicious code occurs in layouts `dist/index.cjs.js`, `dist/index.es.js`, and components `dist/index.js`, `dist/index.esm.js`, `dist/joyfill.min.js`.

### OpenSourceMalware variant and propagation fingerprints

OpenSourceMalware's first-party research repository publishes a scanner/YARA rule and an update distinguishing two active loader variants as of 2026-04-11. [OpenSourceMalware PolinRider research](https://github.com/OpenSourceMalware/PolinRider)

- V1 exact features: `rmcej%otb%`, numeric seeds `2857687` and `2667686`, `_$_1e42`, and `global['!']`.
- V2 exact features: `Cot%3t=shtP`, numeric seeds `1111436` and `3896884`, decoder/function name `MDy` (including `function MDy(f)`), and campaign globals such as `global['_V']='8-...`.
- Common behavior: aliases equivalent to `global['r'] = require` and `global['m'] = module`, then runtime decoding/execution. A generic `global.r` or `global.m` alone is not unique; combine it with a variant marker/seed/decoder.

The same research identifies attacker propagation/cover-up artifacts:

- `temp_auto_push.bat` and `temp_interactive_push.bat`; the former was a 100% true-positive filename in OpenSourceMalware's hunt.
- `config.bat` plus matching `.gitignore` entries is supporting evidence, but `config.bat` alone is too generic.
- Strong internal cluster: `LAST_COMMIT_DATE`, `LAST_COMMIT_TIME`, `git commit --amend --no-verify`, and `git push -uf` in the batch file.
- Exact weaponized take-home identifier: `e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9`.

OpenSourceMalware also ties the VS Code task vector to these domains: `260120.vercel.app`, `default-configuration.vercel.app`, `vscode-settings-bootstrap.vercel.app`, `vscode-settings-config.vercel.app`, `vscode-bootstrapper.vercel.app`, and `vscode-load-config.vercel.app`, with URL shapes like `/settings/(mac|linux|win)?flag=N`. These are much stronger inside a `folderOpen` download/execute task than as uncontextualized text.

Important implementation note: OpenSourceMalware's published scanner is useful evidence but is not a sufficient implementation to copy unchanged. Its original scope is narrower than the later campaign evidence: it can miss V2, task/font delivery, recursive/nested monorepo configs, exact hashes, and the evolving Socket package list. The new scanner should implement the union of the evidence in this note.

### Downstream persistence/code markers

Socket's Joyfill analysis publishes exact DEV#POPPER persistence tags: `/*C250617A*/`, `/*C250618A*/`, `/*C250619A*/`, `/*C250620A*/`, `/*C260511A*/`, `/*C260512A*/`, and `/*RS260605*/`. It reports injection targets including `@vscode/deviceid` beneath VS Code/Cursor/Antigravity, GitHub Desktop's `resources/app/main.js`, Discord Desktop's core module, and the global npm CLI at `node_modules/npm/lib/cli.js`. It also publishes the command vocabulary `ss_info`, `ss_ip`, `ss_cb`, `ss_upf`, `ss_upd`, `ss_dir`, `ss_fcd`, `ss_stop`, `ss_inz`, `ss_inzx`, `ss_connect`, `ss_eval`, `ss_eval64`, `ss_exit`, and `ss_exit_f`. One `ss_*` token can collide; multiple commands together with `Sec-V` or `/$/boot` are high-confidence. [Socket Joyfill analysis](https://socket.dev/blog/joyfill-npm-beta-releases-compromised)

Related path/protocol strings are `/u/f`, `/u/e`, `/0x/js?_V=`, `/verify-human/`, `/snv`, `/$/boot`, `/d/python.zip`, `/d/7zr.exe`, and `/d/python.7z`. Score them as a cluster or alongside the known IP/header/key; short paths such as `/u/f` are not unique alone.

### Related DEV#POPPER / OmniStealer hashes

eSentire's first-party analysis of a related Contagious Interview chain publishes these SHA-256 values: `70b7877644ae04860be5a5eb32e8459fedd0d1c9eef79a0b5173660e2ae4b888`, `55b53de91c7442873d6670036bf5f8fc3292fe048a45707db1b8ddc3127dcd3c`, `5877c397a6c8e7bac9606ec41bfed1ac549eb0a2769de19ce82ef588d7ff31d0`, `4ec542049554f21aeb25a6bc3b3b482bb8027ea7e7e07626a2ee9f3e8c214841`, `fe90dcbbdcb16ba979ce73df5881d568126a77d0943ab496bac0eb3e6ba9644f`, `207b5feb80c67f02023a07c7271b48c1d8b07ea5b59d76f98c1b0b357fbabfb1`, `d0a60ec67bce77c181f48e01f6f9f06ea47f51028ee391791dd334f162c7d24a`, `2b2e56fcf3105b7d84ee90b1338775830b8728993202fec0c3aac68f891a3fde`, and `e0a56a3a7f0d41cdf34b217b3ea51afd6838384e64dbb62e8a89831375814fb2`. [eSentire analysis](https://www.esentire.com/blog/north-korean-apt-malware-analysis-dev-popper-rat-and-omnistealer-everyday-im-shufflin), [eSentire IOC file](https://github.com/eSentire/iocs/blob/main/DEV%23POPPER/DEV%23POPPER-DPRK-IoCs-02-20-2026.txt)

These are **related-family exact hashes**, not proof that every sample is PolinRider. Give exact matches critical severity but label the rule/result as DEV#POPPER/OmniStealer / Contagious Interview rather than misattributing it to PolinRider.

### Broader Contagious Interview static shapes (separate rules)

Microsoft documented a Next.js developer-targeting chain in which `.vscode/tasks.json` ran a `folderOpen` task that launched `.vscode/env-setup.js`; other loaders decoded a Base64 URL from a trojanized `jquery.min.js`, or read a Base64 endpoint from `.env` and executed a response through `new Function('require', response.data)(require)`. These are useful related-family detections but should not be labeled as exact PolinRider IOCs. [Microsoft developer-targeting campaign](https://www.microsoft.com/en-us/security/blog/2026/02/24/c2-developer-targeting-campaign/)

Microsoft's broader Contagious Interview analysis also provides hunting clusters (not single-string verdicts), such as `axios` + `socket.io` + clipboard collection, recursive scanning/exclusion logic plus a `curl` upload, and agent-code handlers with `AgentId`/`SERVER_IP`. [Microsoft Contagious Interview analysis](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)

### Additional widely circulated fake-font hashes

[Nextron Research](https://x.com/nextronresearch/status/2069802303817679083) publicly associated these SHA-256 values with `fa-solid-400.woff2`/known PolinRider payload content:

- `53abf37710d6f2e35694fbe7cfaf1108127cbc001ce3e6bf994d0486cae5a0e8`
- `13e9a3c41e038bf9d8fcb0831305819819e4f7f4452bc20a04b9bf2756ee22e8`

These values are corroborated by vendor/community reporting, but the original source is a social post rather than a durable first-party analysis/IOC table. Treat them as **high-confidence but source-chain weaker than the Socket hash tables**, and record that limitation in code comments rather than presenting every exact hash as equivalent evidence. A secondary page that reproduces the two values is [Gurucul's IOC summary](https://community.gurucul.com/articles/ThreatResearch/PolinRider-Caused-Dozens-of-npm-Go-3-8-2026).

## Safe scanner behavior and verdict model

The scanner should report “no known indicators detected,” not “malware-free.” Hashes are exact but brittle; the loader is mutable and the live affected-package list continues to grow.

Suggested severity model:

| Severity | Examples |
|---|---|
| Critical | Exact published SHA-256; exact affected package+version; `folderOpen` task that runs Node on a fake/invalid font; multiple direct campaign source-code fingerprints in executable/config content |
| High | Direct marker/key/wallet match; fake font containing JavaScript/campaign strings; downloader-pipe auto-task; config injection with campaign infrastructure and dynamic execution |
| Medium | `folderOpen` alone; `task.allowAutomaticTasks: "on"`; invalid font magic alone; long whitespace plus generic obfuscation; one public RPC hostname alone |
| Informational | Affected package name at a different version; presence of a commonly targeted config filename without suspicious content |

Implementation safety requirements:

1. Use `lstat` and skip symbolic links, sockets, devices, and FIFOs. Do not follow directory symlinks or allow a link to escape the scan root.
2. Hash files by streaming them in bounded chunks. Apply a configurable size cap to content-pattern scanning, but allow full streaming SHA-256 so exact large-file matches remain possible.
3. Parse JSON as data only. Tolerate JSON-with-comments for VS Code files without invoking Node or an editor; if strict parsing fails, fall back to text rules and report a parse warning.
4. Never run package managers, build tools, linters, test suites, repository hooks, or suspect commands.
5. Skip `.git` object contents in the default working-tree scan. If an optional existing-history scan is implemented, use read-only Git plumbing against an already-present repository and make clear that a normal GitHub Actions checkout fetches only one commit by default.
6. Avoid self-detection. If IOC literals are embedded in the scanner, explicitly exclude the scanner file, its generated SARIF/JSON output, the research note, test fixtures, and other designated security documentation—or store fingerprints encoded and compare decoded values in memory. Documentation/source copies of IOCs should be classified differently from executable/config content.
7. Deduplicate results by stable rule ID, repository-relative path, line/byte location, and matched indicator. Cap emitted findings to prevent a maliciously repetitive file from exhausting memory or producing an oversized SARIF file.
8. Keep scans deterministic and offline by default. If an update option fetches the Socket CSV, require explicit user action, use only HTTPS and the fixed Socket origin, cache it as data, and never fetch package artifacts or repositories.

## GitHub Actions design

Use an unprivileged `pull_request` workflow for untrusted PR content. Do not use `pull_request_target` to check out and scan a fork's head: GitHub warns that `pull_request_target` and `workflow_run` are privileged and must not explicitly check out untrusted code. [GitHub secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use)

The scan job should:

- declare minimum token permissions (`contents: read`; add `security-events: write` only to a separate SARIF-upload job/step where supported);
- contain no repository or organization secrets;
- avoid dependency installation and avoid running anything from the checked-out tree;
- invoke a trusted copy of the scanner (for example, a reviewed script already in the base branch or an immutable external action), because a PR can modify a scanner stored in the PR checkout;
- use `persist-credentials: false` when checkout does not need later authenticated Git operations. The official checkout action says credentials are persisted by default and documents the opt-out. [actions/checkout README](https://github.com/actions/checkout/blob/main/README.md)
- pin third-party actions to full commit SHAs where operationally feasible. GitHub says a full-length commit SHA is the only immutable way to reference an action. [GitHub secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use)

Exit codes should be documented and stable, for example:

- `0`: completed and no finding at/above the configured failure threshold
- `1`: findings at/above the threshold
- `2`: scanner/configuration/IO error or incomplete scan

GitHub treats every nonzero exit code as job failure. [GitHub exit-code documentation](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/set-exit-codes) To both upload SARIF and fail the check, capture the scanner status, run SARIF upload with an `always()`-style condition, then finish with the captured status. Do not hide a malware finding with unconditional `|| true` unless a later step reliably restores the failure.

## SARIF guidance

GitHub accepts SARIF 2.1.0 and recommends stable rule IDs, consistent repository-relative paths, physical locations, and partial fingerprints to avoid duplicate alerts. `level` values are `note`, `warning`, and `error`; a security rule can also supply `properties.security-severity` (0.1–10.0) and precision. [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)

For this scanner:

- Use stable rule IDs such as `polinrider/hash-match`, `polinrider/vscode-folderopen-asset`, `polinrider/fake-font-js`, `polinrider/source-fingerprint`, and `polinrider/affected-dependency`.
- Emit repository-relative POSIX paths and a start line where text is available. For binary/hash-only findings, associate the result with line 1.
- Give direct hash/package matches `error`, contextual combinations `warning`, and weak single signals `note` unless the user raises the fail threshold.
- Generate a stable fingerprint from rule ID + normalized repository-relative path + indicator identity, not an absolute temp path.
- Keep output below GitHub's limits: compressed SARIF is limited to 10 MB; a run accepts at most 25,000 results, with only the top 5,000 displayed. Deduplication and caps are therefore required.

Uploading with `github/codeql-action/upload-sarif` requires `security-events: write`; private repositories also require `actions: read` and `contents: read` in GitHub's example. Code scanning is available for public repositories and for eligible organization-owned repositories with GitHub Code Security enabled. [GitHub SARIF upload documentation](https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/integrate-with-existing-tools/uploading-a-sarif-file-to-github)

SARIF upload is optional. The scanner should always produce useful terminal/JSON output and a meaningful exit code so it works in repositories where code scanning is unavailable or token permissions prevent upload.

## Limitations and non-findings

- Static absence of known indicators is not evidence that the host is uncompromised. PolinRider can fetch mutable second stages, and post-compromise artifacts may live outside the repository.
- Public blockchain RPC domains are legitimate services. A hostname alone should not produce a “confirmed malware” verdict.
- `folderOpen`, hidden tasks, dynamic JavaScript, and long lines can all have legitimate uses. Context combinations are essential.
- Exact hashes miss even one-byte variants. Behavioral rules and updated package/version intelligence are required alongside hashes.
- The scanner described here is repository/artifact static analysis, not EDR. It will not prove whether a payload executed, whether credentials were exfiltrated, or whether Git history was previously rewritten and later cleaned.
- Socket advises teams that installed affected versions to treat the environment as potentially compromised, preserve evidence, rebuild from known-good lockfiles, and rotate exposed secrets from a clean machine. A scanner result must not substitute for incident response. [Socket defensive guidance](https://socket.dev/blog/polinrider-north-korea-linked-supply-chain-campaign-expands)
- No stable first-party evidence was found for a separate GitHub-Actions-native PolinRider payload variant. Workflow scanning is still warranted because workflows are executable configuration and because the scanner itself runs in Actions, but claims should stay within the evidence above.
