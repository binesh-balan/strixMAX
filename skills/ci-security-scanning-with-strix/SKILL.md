---
name: ci-security-scanning-with-strix
description: Add security scanning to CI/CD with Strix — GitHub Actions, GitLab CI, or any pipeline — so every pull request gets a diff-scoped AI pentest that blocks vulnerable code before it merges, with results as PR comments and SARIF uploaded to code scanning. Covers both the self-hosted open-source CLI (runs in your runner) and the managed app.strix.ai platform (GitHub/GitLab app or API, no runner infra). Use when the user asks to add security scanning, SAST/DAST, pentesting, vulnerability checks, or automated security review to their CI pipeline, pre-merge gate, or PR workflow.
license: Apache-2.0
metadata:
  author: usestrix
  homepage: https://docs.strix.ai
---

# Set up Strix in CI/CD

You can gate PRs two ways — pick based on the environment, or combine them:

- **Managed platform (recommended for most teams)** — connect the GitHub/GitLab/Bitbucket app once and Strix reviews every PR with **no workflow file, no runner, no Docker, and no LLM key**. Results post as PR comments and land in the team dashboard. Best when you want zero CI maintenance, central tracking, or your runners lack Docker. See "Managed platform" below and the **managed-pentesting-with-strix** skill.
- **Self-hosted OSS CLI in your runner** — run a diff-scoped scan as a pipeline step. Fully in your infra, free (BYO LLM key), no external account. Requires Docker on the runner. Best for air-gapped/self-hosted CI or when you do not want scans leaving your environment.

Both fail the build on validated findings and both emit SARIF 2.1.0, so you can start with one and add the other later.

---

# Option A — Self-hosted OSS CLI in the runner

Run a diff-scoped Strix scan on every PR: only changed files are tested, `quick` mode keeps it fast, and exit code `2` fails the build when validated vulnerabilities are found.

## GitHub Actions

Create `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  pull_request:

permissions:
  contents: read

jobs:
  strix-scan:
    # Secrets are not passed to fork PRs on `pull_request`; skip them explicitly
    # rather than running without a key. Never switch to `pull_request_target`
    # to "fix" this — it would run untrusted fork code with your LLM key.
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262  # v4.4.0
        with:
          fetch-depth: 0   # required for diff-scope resolution
          persist-credentials: false

      - name: Install Strix (pinned version)
        run: pipx install strix-agent==1.7.0

      - name: Run Security Scan
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: strix -n -t ./ --scan-mode quick --max-budget 10

      # Don't fail open: a run that hits the hard budget stop exits 0 but leaves
      # run.json status "stopped", not "completed". Enforce completion explicitly.
      # This does not catch an agent that wrapped up early on a budget *warning*
      # (it still calls finish_scan and records "completed"), so size the budget.
      - name: Fail unless the scan completed
        run: |
          run_json=$(ls -t strix_runs/*/run.json | head -1)
          status=$(jq -r .status "$run_json")
          if [ "$status" != "completed" ]; then
            echo "Strix run status is '$status' — the scan did not complete (likely budget exhausted). Raise --max-budget." >&2
            exit 1
          fi
```

Then tell the user to add two repository secrets: `STRIX_LLM` (model id, for example `openai/gpt-5.4`) and `LLM_API_KEY` (the provider key). Do not create these values yourself.

Notes:
- **Keep LLM keys away from untrusted code.** Run the scan only on `pull_request` events from branches in the same repository (the `if:` above), never on `pull_request_target` or `workflow_run` with a fork's code checked out. If fork PRs must be scanned, gate the job behind a protected environment with required reviewers (`environment: strix-scan`) so a maintainer approves each run after reading the diff. Give the key its own provider spend limit.
- **Pin everything.** Actions are pinned to full commit SHAs with a version comment (let Dependabot/Renovate bump them), `persist-credentials: false` keeps the `GITHUB_TOKEN` out of `.git/config` where the scanned code could read it, and the Strix version is pinned (`strix-agent==1.7.0`) — bump it deliberately. To use the standalone binary instead, see "Installing without `curl | bash`" below.
- In CI/headless runs Strix automatically scopes to the PR's changed files (`--scope-mode auto`). If diff resolution fails, keep `fetch-depth: 0` or set `--diff-base` to the PR's actual base branch — use `origin/${{ github.base_ref }}` in GitHub Actions rather than a hard-coded `origin/main`, since repos use different default branches.
- Exit codes: `0` pass, `2` vulnerabilities found (fails the job), `1` setup error. Add `--fail-on high` to fail only on high/critical findings; lower ones are still reported, so a passing job is not a finding-free report.
- The runner needs Docker (default GitHub-hosted Ubuntu runners have it).
- **Size the budget so the scan completes — do not let it fail open.** A `0` exit means "no validated vulnerabilities in what was analyzed"; if `--max-budget` is hit before the diff is fully covered, the scan wraps up early and can still exit `0`. The "Fail unless the scan completed" step above narrows the gap: `strix_runs/<run>/run.json` is `"stopped"` when the scan was cut off at the hard budget limit without a final report. It is not a complete guard — the agents get graduated wrap-up warnings before that limit, and a run that wraps up on a warning still calls `finish_scan` and records `"completed"` with partial coverage. So keep that step in any pipeline that gates merges **and** give the scan real headroom (compare `run.json`'s `llm_usage.cost` against `--max-budget`; if it ran right up to the cap, raise it). For a `quick` diff-scoped PR scan `--max-budget 10` is usually ample, raise it for large diffs.

### Optional: upload findings to GitHub code scanning

Strix writes SARIF 2.1.0 to `strix_runs/<run>/findings.sarif`:

```yaml
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@48870fdd6b42ee6474ec4207209ff87609271a5e  # v4.39.0
        with:
          sarif_file: strix_runs
```

This step needs `security-events: write`; grant it on the `strix-scan` job only (`permissions: { contents: read, security-events: write }`), not workflow-wide.

## Installing without `curl | bash`

Do not pipe a remote script into a shell in CI. Either install the pinned package:

```bash
pipx install strix-agent==1.7.0      # or: uv tool install strix-agent==1.7.0
```

or download the installer, review it, and run it pinned to a version (the installer verifies the release archive against the release's `SHA256SUMS` and aborts if no checksum is published):

```bash
curl -fsSL -o strix-install.sh https://strix.ai/install
less strix-install.sh                 # review before running; or diff against a reviewed copy
# Optionally pin the reviewed script: echo "<sha256>  strix-install.sh" | sha256sum -c -
STRIX_VERSION=1.7.0 bash strix-install.sh
```

## Other CI systems

Any pipeline works the same way — install a pinned version, set the two env vars, run headless. Expose the LLM key only to pipelines for trusted branches (for example GitLab protected variables), never to merge requests from forks:

```bash
pipx install strix-agent==1.7.0
# Resolve the PR's base branch robustly (use your CI's base-branch variable if it
# has one, for example GitHub Actions: origin/${{ github.base_ref }}). Avoid piping the
# git lookup into another command — a failed lookup would otherwise be masked.
BASE_BRANCH="${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}"   # GitLab MR target
if [ -z "$BASE_BRANCH" ]; then
  BASE_BRANCH=$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null)
  BASE_BRANCH="${BASE_BRANCH#origin/}"
fi
DIFF_BASE="origin/${BASE_BRANCH:-main}"
# Fail loudly rather than silently narrowing scope (for example, to HEAD~1, which on a
# multi-commit branch would scan only the last commit and let earlier ones pass).
if ! git rev-parse --verify --quiet "$DIFF_BASE" >/dev/null; then
  echo "Cannot resolve diff base '$DIFF_BASE'. Fetch the base branch (git fetch origin <base>) or set --diff-base explicitly." >&2
  exit 1
fi
strix -n -t ./ --scan-mode quick --scope-mode diff --diff-base "$DIFF_BASE" --max-budget 10
```

Gate the pipeline on the exit code (see the budget/fail-open caveat above — give the scan enough budget to finish). Schedule `standard` scans nightly and `deep` scans for release candidates.

---

# Option B — Managed platform (no runner infra)

No workflow file, no Docker, no LLM key. Three ways to use it:

1. **PR-review app (zero code):** the user installs the Strix GitHub/GitLab/Bitbucket app and enables PR reviews for the repo in the app.strix.ai dashboard. Every PR is then reviewed automatically, with findings posted as PR comments. Nothing to add to the repo. This is the lowest-effort path — recommend it first when the user just wants PR gating.

2. **CLI-triggered from any pipeline:** if you want to trigger from an existing pipeline (or a system without the SCM app), use the same `strix` binary with a token that has `pr_reviews:write`. Store the token as a CI secret and ask the user to create it at **Settings → API Access**. Read the repository's `provider` and `installation_id` once with `strix cloud repos list`. Example GitHub Actions step:

   ```yaml
   - name: Strix PR review (managed)
     if: github.event_name == 'pull_request'
     env:
       STRIX_API_TOKEN: ${{ secrets.STRIX_API_TOKEN }}
     run: |
       pipx install strix-agent==1.7.0
       strix cloud pr-reviews start \
         --provider github \
         --installation-id "${{ vars.STRIX_INSTALLATION_ID }}" \
         --repository-full-name "${{ github.repository }}" \
         --pr-number "${{ github.event.pull_request.number }}"
   ```

   Output is JSON when stdout is not a terminal, and there are no prompts without a TTY. To gate the build on results, poll `strix cloud pr-reviews get <id> --json` and fail on unresolved criticals or highs. The raw REST endpoint (`POST /api/v1/pr-reviews/start`) works too when the pipeline cannot install the CLI.

3. **Source upload from a pipeline without an SCM app:** upload the checked-out tree as a cloud code review (`scans:write` and `uploads:write`). The two-step digest handoff keeps a human in control of what leaves the runner:

   ```bash
   strix cloud scans start --source . --dry-run --show-files --json   # review, capture source.archive_sha256
   strix cloud scans start --source . --approve-sha256 "$SOURCE_SHA256" --wait
   ```

   Exit codes: `0` success, `4` auth or plan limit, `5` payment required. Non-Enterprise scans consume credits.

Full CLI coverage (PR reviews, scans, SARIF export, schedules) is in the **managed-pentesting-with-strix** skill.

Recommend Option B for most teams (no maintenance, central dashboard); use Option A when scans must stay entirely within your own infrastructure.
