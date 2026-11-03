# devsecops-pipeline-demo

A GitHub Actions pipeline that builds and security-tests a deliberately vulnerable Node/Express API, then reports what each stage found and what it missed.

The target is [`auto_fix_mcp`](https://github.com/zubair-ulhasan/auto_fix_mcp), a multi-tenant REST API with six planted flaw classes: broken function-level authorization (BFLA), cross-tenant broken object-level authorization (BOLA), mass assignment, privilege escalation, excessive data exposure and expired-token acceptance. Its [`VULNERABILITIES.md`](https://github.com/zubair-ulhasan/auto_fix_mcp/blob/main/VULNERABILITIES.md) is the answer key. This repo contains only the pipeline; the target is checked out at a pinned commit (`e1e275a`) on every run and is never modified.

Results below are as of 4 November 2026. Advisory data is live, so counts can drift on identical code.

## Results at a glance

**The six planted flaw classes: one was caught by any stage.**

| Planted flaw class | Caught by | Why |
|---|---|---|
| Mass assignment | **Semgrep** (`index.js:58`) | A code pattern that a rule exists for |
| Privilege escalation (a role set from the request body) | Nothing | A direct code pattern, but no rule in the pinned rule set matches it |
| Expired-token acceptance (`ignoreExpiration: true`) | Nothing | A textbook pattern, but no JWT rule in the pinned JavaScript rule set mentions it |
| Function-level authorization (BFLA) | Nothing | A missing check, not a code pattern; a DAST scan has no role model |
| Cross-tenant object authorization (BOLA) | Nothing | Same, and only one credential was tested |
| Excessive data exposure | Nothing | Responses return too much; no scanner knows what they should hide |

**What the stages did find (not planted):**

| Stage | Result |
|---|---|
| Secrets (gitleaks v8.30.1) | 1 of the 6 seeded secret values (`generic-api-key`). The hard-coded fallback JWT secret and the seeded plaintext passwords are not matched by the default rules |
| Dependencies (OSV-Scanner v2.7.0) | 81 packages scanned; 3 vulnerable (`proxy-addr`, `body-parser`, `qs`), 6 advisories, all arriving through `express` |
| Image (Trivy v0.76.1) | 0 findings in the OS packages; the same 6 application findings as OSV-Scanner, matching by package and count |
| DAST (ZAP 2.17.0, passive) | Baseline scan: 0 High, 3 Medium (security headers on the static page), 6 Low. Authenticated API scan driven by the OpenAPI spec: 0 High, 0 Medium, 3 Low. The `X-Powered-By` leak and missing headers are real but minor |

## Before and after: keeping npm out of the image

The first image scan found 25 vulnerabilities, 19 of them in the npm that ships inside the `node` base image. The app runs `node index.js` and never calls npm, so a multi-stage build now installs dependencies in one stage and copies only the Node binary and the app into a plain Alpine runtime.

| | Single stage (`node:24-alpine`) | Multi-stage (Alpine + Node binary) |
|---|---|---|
| Trivy findings | 25 (1 critical, 7 high, 15 medium, 2 low) | 6 (1 critical, 1 high, 3 medium, 1 low) |
| In the npm bundled with the base image | 19 | 0 |
| In the app's own dependencies | 6 | 6 (unchanged) |
| SBOM components | 562 (248 libraries) | 268 (101 libraries) |
| npm packages in the image | 229 | 83 |
| Image size | 181.7 MB | 147.6 MB |
| Smoke test, ZAP results, quality gate | Pass | Pass, ZAP results identical |

The six that remain are the application's real dependencies; fixing them means updating the target, which this repo does not do. This change cuts noise and attack surface. It does not prove the 19 were exploitable, because nothing here measures reachability. The one non-app npm component left in the SBOM is probably the app's own `package.json`; I did not check.

## What the scanners can and cannot tell you

- **Scanner limitations (by design).** Trivy and OSV-Scanner report that a vulnerable version is present, not whether it is reachable. A passive DAST scan has no model of who is allowed to see what, so access-control flaws look like ordinary 200 responses. An image scan sees what is installed, not what the lockfile says. Counting conventions differ between tools (81 distinct packages vs 82 install paths, because `ms@2.1.3` is installed twice; 562 SBOM components vs 248 libraries, because 312 are file entries).
- **Rule-set gaps.** Semgrep caught 1 of the 3 code-level planted patterns. The rules have no match for role assignment from the request body and none for `ignoreExpiration`; a custom rule would close both. The default secret rules miss low-structure secrets.
- **Scope choices (mine).** The DAST scans are passive only, with no active attack rules, and use one low-privilege credential, so no cross-tenant or role-comparison test was run. Trivy ran its vulnerability scanner only (no image secret or Dockerfile checks). The SBOM's format, version and contents are checked, but it is not validated against the CycloneDX JSON schema.
- **Not pinnable.** Advisory data (OSV, the Trivy database), the add-ons ZAP updates at start-up, and the Alpine `libstdc++` package version installed at build time. The scanners, rule set, actions and base images are pinned; the data they read is not.

The gap that no stage here fills is authorization testing across roles and tenants, which is where most of the planted flaws sit.

## Mistakes the logs caught

- **A green authenticated scan that tested nothing.** The first API scan passed, but ZAP had sent every request malformed: HTTP 400 on every URL, including `/health`, which needs no login. ZAP splits its `-z` option on spaces, which tore `Bearer <token>` apart. A direct probe (the same endpoint with and without the token: 200 vs 401) showed the token was fine; a hook script (`scripts/zap_hooks.py`) now sets the header. A green job and "0 findings" do not prove the scan reached the app, so the pipeline logs the status codes behind ZAP's alerts.
- **A scanner that could not unpack the image.** The Syft container has no writable `/tmp` for a non-root user. The scanner containers now get an in-memory `/tmp`.

## Supply-chain choices

- Actions are pinned to commit SHAs, scanner images and base images to digests, and the Semgrep rule set to a commit. The workflow token is read-only.
- Trivy is pulled by digest, never by tag, and its GitHub Action is not used. In March 2026 a Trivy release, two Docker Hub images and most `trivy-action` tags were briefly malicious ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)); images referenced by digest were not affected. The pinned release is immutable and newer than the fix for a later path-traversal advisory.
- Scanners read an exported image tarball from a read-only mount, so none of them gets the Docker socket. Telemetry is off.
- DAST safety: the API spec may list a hosted instance as a server, so the workflow rewrites every server entry to `localhost` and fails if any other server URL is left. The test password is read at run time from the target's own answer key and the token is masked and checked absent from every report kept, so no credential is stored here.

## The quality gate

Stages 2 to 4 are report-only. The `quality gate` job reads every report and fails the build when a rule in `gate/policy.json` trips:

| Rule | Fails when |
|---|---|
| `scan-integrity` | Any report is missing or a scan covered nothing |
| `secrets-any` | gitleaks finds anything |
| `sast-error` | Semgrep reports a finding at severity ERROR |
| `sca-critical` | A dependency advisory scores 9.0 or higher |
| `image-critical-fixable` | Trivy finds a CRITICAL with a published fix |
| `dast-high` | ZAP reports a High-risk alert |

The target is deliberately vulnerable, so three known findings are waived in `gate/accepted.json` (the seeded secret, and `proxy-addr@2.0.7` as seen by both the dependency scan and the image scan). Each waiver has a reason, an owner and an expiry date, and an expired waiver trips its rule again. To check that the gate really blocks, a test pull request removed the waivers and the build failed; that PR was closed unmerged. Semgrep is gated at ERROR and images at CRITICAL for now; HIGH is to be revisited now that the multi-stage build has removed most of the noise.

## Changing this repo

Make changes on a branch and open a pull request, so the pipeline (all five checks, including the quality gate) runs before anything reaches `main`; direct pushes to `main` are no longer the workflow. `main` is protected: a pull request is required, and all five checks, including the quality gate, must pass before it can merge. The rule applies to admins too.

To scan newer target code, set `TARGET_REF` at the top of the workflow to a new commit SHA of `auto_fix_mcp` in a commit of its own, so the change in results is traceable.

## Status

| Stage | What it does | State |
|---|---|---|
| 1. Build and smoke test | Builds the target into a container (multi-stage, non-root user, lockfile install) and checks that `/health` answers | Done |
| 2. Secrets scan | Scans the target for committed secrets (gitleaks) | Done |
| 3. SAST and SCA | Static analysis (Semgrep) and a dependency vulnerability scan (OSV-Scanner) | Done |
| 4. Image scan and SBOM | Scans the container image (Trivy) and produces a CycloneDX SBOM (Syft) | Done |
| 5. DAST and quality gate | ZAP baseline and authenticated OpenAPI scans (passive), plus an enforcing quality gate | Done |
| 6. Write-up | The results above, including the multi-stage before/after | Done |

## Not covered yet

A time-capped active ZAP scan; authorization testing across roles and tenants; HIGH-severity gating after the dependency updates the target would need; schema validation of the SBOM; Trivy's secret and Dockerfile scanners; signature verification of the scanner images.

## Run the same steps locally

Requires Docker.

```bash
git clone https://github.com/zubair-ulhasan/auto_fix_mcp.git target
git -C target checkout <the TARGET_REF commit>
docker build -f docker/Dockerfile.target -t auto-fix-mcp-target:ci .
docker run -d --name target -p 3000:3000 auto-fix-mcp-target:ci
bash scripts/smoke-test.sh http://localhost:3000/health
```

## License

MIT, see [LICENSE](LICENSE). The target app and the Semgrep rules it is scanned with are separate projects under their own licences; the rules are fetched at run time and are not included here.

## Warning

The target is intentionally insecure. Run it only in a sandbox and never with real data.
