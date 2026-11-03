# devsecops-pipeline-demo

A GitHub Actions pipeline that builds and security-tests a deliberately vulnerable Node/Express API.

The target is [`auto_fix_mcp`](https://github.com/zubair-ulhasan/auto_fix_mcp), a multi-tenant REST API with planted flaws (broken function-level and object-level authorization, mass assignment, privilege escalation, excessive data exposure, expired-token acceptance). Its [`VULNERABILITIES.md`](https://github.com/zubair-ulhasan/auto_fix_mcp/blob/main/VULNERABILITIES.md) is the answer key: the pipeline is meant to catch what it can and the README will show what each stage finds and misses.

This repo contains only the pipeline. The target is checked out at a pinned commit on every run and is never modified.

## Status

| Stage | What it does | State |
|---|---|---|
| 1. Build and smoke test | Builds the target into a container (non-root user, lockfile install) and checks that `/health` answers | Done (first run passed) |
| 2. Secrets scan | Scans the target for committed secrets (gitleaks, report-only) | Done |
| 3. SAST and SCA | Static code analysis (Semgrep) and a dependency vulnerability scan (OSV-Scanner), report-only | Done |
| 4. Image scan and SBOM | Scans the container image (Trivy) and produces a CycloneDX SBOM (Syft) as a build artifact, report-only | Done |
| 5. DAST and quality gate | ZAP baseline and authenticated OpenAPI scans (passive) against the running container, plus an enforcing quality gate (`gate/policy.json`, waivers in `gate/accepted.json`) | Gate live and enforcing; awaiting sign-off |
| 6. Write-up | Before/after results against the answer key, including a multi-stage build that drops npm from the image (planned: removes 19 of the 25 Trivy findings) | Planned |

## How it works

- `.github/workflows/pipeline.yml` runs on every push to `main`, on pull requests and on demand.
- Actions are pinned to commit SHAs and the workflow token is read-only.
- `docker/Dockerfile.target` builds the checked-out target (`./target`) into an image.
- `scripts/smoke-test.sh` waits for the container to answer and fails the build if it never returns HTTP 200.

## Changing this repo

`main` is protected: the pipeline (all five checks, including the quality gate) must pass before anything merges, and direct pushes to `main` are no longer the workflow. Make changes on a branch and open a pull request.

The gate (`gate/policy.json`) fails the build on: a missing or empty scan report, any secret, a Semgrep ERROR, a dependency advisory scoring 9.0 or higher, a CRITICAL image vulnerability with a fix, or a High-risk ZAP alert. Known findings in the deliberately vulnerable target are waived in `gate/accepted.json`, each with a reason and an expiry date; an expired waiver trips its rule again.

## Updating the target

The target commit is pinned in `TARGET_REF` at the top of the workflow. To scan newer code, set it to a new commit SHA of `auto_fix_mcp` in a commit of its own, so the change in results is traceable.

## Run the same steps locally

Requires Docker.

```bash
git clone https://github.com/zubair-ulhasan/auto_fix_mcp.git target
git -C target checkout <the TARGET_REF commit>
docker build -f docker/Dockerfile.target -t auto-fix-mcp-target:ci .
docker run -d --name target -p 3000:3000 auto-fix-mcp-target:ci
bash scripts/smoke-test.sh http://localhost:3000/health
```

## Warning

The target is intentionally insecure. Run it only in a sandbox and never with real data.
