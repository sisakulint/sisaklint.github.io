---
title: "Artifact Poisoning Rule（Critical）"
weight: 8
---

This page describes sisakulint [v0.3.7](https://github.com/sisaku-security/sisakulint/releases/tag/v0.3.7).

## Overview

`artifact-poisoning-critical` reports steps whose `uses:` begins with
`actions/download-artifact@`, and only where three conditions hold together. The job checks out the repository. The job can run under a trigger this
rule treats as a risk signal, or the step is configured to reach another run — either one is
enough for that condition. And the destination is one the rule judges unsafe: the workspace, or
an absolute path its list for the runner OS does not accept. The destination alone does not
produce a finding.

If an artifact produced by a less-trusted run overwrites the checked-out source, a later step may
execute it. This rule looks only at where the artifact lands; it never reads its contents.

## Detection Scope

Reported only when all three hold. If any one is missing, nothing is reported.

1. **The job contains `actions/checkout@`.** This narrows the rule to jobs that have a
   checked-out source to overwrite; it does not mean a job without checkout is safe. A workflow that writes a file with `run:`,
   extracts an artifact over the same location, and executes it afterwards is not reported.
2. **The job can run under a trigger this rule treats as a risk signal, or the step is
   configured to reach another run.** Either one is enough.

   - Triggers treated as a risk signal: `workflow_run` / `pull_request_target` / `issue_comment` /
     `issues` / `discussion_comment` / `pull_request_review` / `workflow_call`. Membership says
     what the rule reacts to, not what the run is granted: a `pull_request_review` on a pull
     request from a fork runs with a read-only `GITHUB_TOKEN` and without access to other secrets.
   - The workflow's triggers are read per job. A job-level `if:` that the rule can read as a test
     on the event name narrows the set for that job, so `if: github.event_name == 'push'` takes
     the job off this list even while the workflow also has `pull_request_target`. A condition the
     rule cannot read that way leaves every trigger in place. Which conditions it reads is not
     stated here; run the rule again after changing one and see whether the finding is gone.
   - Reaching another run: **a `github-token` is present, and** `run-id` or `repository` points
     somewhere other than this run.

   Two configurations do not reach another run: a `run-id` with no `github-token`, because the
   action reads only the current run when no token is supplied; and a self-reference such as
   `run-id: ${{ github.run_id }}`. Either is still reported if the job can run under a trigger on
   the list above — that half of the condition is enough on its own.
3. **The destination is unsafe.** `path` is absent, empty, workspace-relative, or judged unsafe
   for the runner OS. Which absolute paths count as unsafe depends on the OS the job runs on;
   the table is under [OS-Aware Path Validation](#os-aware-path-validation) below.

This rule emits no severity. A finding carries the file position, the message, and the rule
name only. (The output format is capable of carrying one: the `artipacked` rule prints
`[Medium]` in the same run.) The `-critical` in the rule name is part of the identifier, not an independent
rating of this rule.

Not examined: the contents of the artifact, the dependencies that produced it, or its
provenance. Supply-chain compromise is outside this rule and belongs to dependency scanning and
provenance verification. Who can produce the artifact is also not examined. The trigger set is
the rule's own risk signal, not a test of what the run is granted. It does not decide whether the
step can reach another run's artifact; that is settled by `github-token` together with `run-id` /
`repository` (see [Security Background](#security-background)).

## Remediation

1. **Extract under `${{ runner.temp }}`.** The runner's own temporary directory is the one
   destination that does not depend on where the runner places the workspace. Only the
   `${{ runner.temp }}` expression is accepted for it; whitespace and letter case inside
   `${{ }}` are ignored, so `${{runner.temp}}` and `${{ RUNNER.TEMP }}` are accepted as well. A
   literal `$RUNNER_TEMP` is reported — `with:` inputs are not shell-expanded, so the action
   receives the string as written. The expression is rejected when a `..` segment follows.

   ```yaml
   - uses: actions/download-artifact@v4
     with:
       name: application-bundle
       path: ${{ runner.temp }}/artifacts
   ```

   Omitting `path` extracts into `$GITHUB_WORKSPACE` (the action's documented default). When
   referencing the destination from `run:`, pass it through `env:` and quote it so shell
   differences do not change the meaning.

   Setting `path` works here because this rule only looks at `actions/download-artifact`, which
   documents the input and reads it. A third-party action need not — that case belongs to
   [`artifact-poisoning-medium`]({{< ref "artifactpoisoningmedium.md" >}}), where `path` does not
   clear the finding for that reason.

2. **If `path` is absent or empty, the autofix applies.** Run `sisakulint -fix on`. A step that
   already has an unsafe `path` is reported but not rewritten (see Auto-fix).

3. **Read from the temporary directory.** Copy into the workspace only what you have verified.
   Moving the destination stops the overwrite; it does not make the artifact trustworthy.

Removing the checkout also clears the finding, but that silences this rule rather than changing
what can happen — Detection Scope's first condition already says a job without a checkout is not
thereby safe. The second condition is an *or*, so clearing that one instead means removing both of
the things that satisfy it: the risk-signal trigger and the cross-run configuration (`run-id` /
`repository` together with `github-token`). For the trigger, either take it out of `on:` or give
the job an `if:` the rule can read as a test on the event name. Each of these changes when the job
runs or what it does (see Detection Scope).

## Auto-fix

What this rule's autofix changes, and what it leaves alone.

- **Changes**: steps whose `path` is absent or empty. Inserts `path: ${{ runner.temp }}/artifacts`.
- **Leaves alone**: steps that already carry an unsafe `path`. Rewriting could break an
  intended layout, so the step is reported only.
- No verification step is generated. Only the destination is changed.

## Example Workflow the Rule Detects

```yaml
name: Deploy Application

on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]

jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      actions: read
      contents: read
    steps:
      - uses: actions/checkout@v4

      # REPORTED: no path, so the artifact lands in the checked-out workspace
      - name: Download build artifacts
        uses: actions/download-artifact@v4
        with:
          name: application-bundle
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - name: Deploy to production
        run: |
          chmod +x ./deploy.sh
          ./deploy.sh
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

## Example Output

```bash
.github/workflows/deploy.yaml:19:9: artifact is downloaded without specifying a safe extraction path at step "Download build artifacts". This may allow artifact poisoning where malicious files overwrite existing files. Consider extracting to a temporary folder like '${{ runner.temp }}/artifacts' to prevent overwriting existing files. See https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningcritical/ [artifact-poisoning-critical]
       19 👈|      - name: Download build artifacts
```

Only this rule's finding is shown; other rules report on the same run. A third line under each
finding (a column pointer, all spaces) is omitted here.

## Example Workflow the Rule Does Not Detect

Condition 3 of Detection Scope no longer holds, so this rule reports nothing. This is the same
workflow as above with only the destination changed to one the rule accepts.

**All this example shows is that the overwrite is stopped.** The artifact itself can still be
produced by a less-trusted party. Checking it against a `checksums.txt` carried inside the same
artifact verifies nothing, because an attacker able to change the contents can change the list
too. Whether the contents can be trusted is handled by other controls, such as signature or
provenance verification, and is outside this rule.

```yaml
name: Deploy Application

on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]

jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      actions: read
      contents: read
    steps:
      - uses: actions/checkout@v4

      # NOT REPORTED: extracted outside the workspace
      - name: Download build artifacts
        uses: actions/download-artifact@v4
        with:
          name: application-bundle
          path: ${{ runner.temp }}/artifacts
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}

      # The deploy script comes from the repository, not from the artifact.
      - name: Deploy to production
        run: |
          chmod +x ./deploy.sh
          ./deploy.sh
        env:
          ARTIFACT_DIR: ${{ runner.temp }}/artifacts
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

## Security Impact

The classification corresponds to CWE-829 and OWASP CICD-SEC-4. The tool emits no severity, so
no number is given here (see Detection Scope).

**The impact is conditional.** A finding means only that the destination is one this rule's list
for the runner OS does not accept — the workspace, or an absolute path off that list. It does
not mean the destination is inside the workspace: a destination plainly outside it is still
reported when it is not on the list, such as `/tmp` on Windows, `C:\artifacts` on any OS, or
`/var/...` when the OS cannot be inferred. This rule does not look at what runs afterwards, nor
at what credentials the job holds. When a later step executes the overwritten file and the job
carries production credentials, the attacker's code runs with those privileges. Deployment
workflows tend to satisfy both, and the artifact appears to originate from the same repository,
which makes it easy to miss. Without those two, a finding means only that the destination is off
the list.

## Security Background

`actions/download-artifact` reads artifacts from the current repository and the current run by
default. Reaching another repository or another run requires a `github-token` — the action's
input documentation states it is required when downloading from a different repository or a
different workflow run. What determines whether another run is reachable is therefore the
combination of `github-token` with `run-id` / `repository`, not the kind of trigger.

The trigger carries a different axis. `workflow_run` and `pull_request_target` can start a
workflow, in response to a pull request from a fork, in a context that holds write permissions
and secrets. The overwrite becomes possible where the two overlap: a privileged context
extracting, into the workspace, an artifact a less-trusted party could have produced.

## Attack Scenario

1. An attacker opens a pull request; CI builds the PR's code and uploads an artifact
2. The artifact contains a tampered `deploy.sh`
3. A deployment workflow started by `workflow_run` downloads that artifact
4. The destination is the workspace, so the legitimate `deploy.sh` is overwritten
5. The deployment workflow executes it with production credentials

## Related Rules

- [permissions]({{< ref "permissions.md" >}}): narrow the workflow's permissions
- [untrusted-checkout]({{< ref "untrustedcheckout.md" >}}): detect checkouts of untrusted code
- [commit-sha]({{< ref "commitsharule.md" >}}): pin actions to a commit SHA

## Rule Specific Guide

Behaviour specific to this rule.

### OS-Aware Path Validation

The runner OS is inferred from the `runs-on` labels, and the safe destinations are decided per
OS.

Matching is case-insensitive, and each row accepts either a prefix or an exact label.

| `runs-on` label | inferred OS |
|---|---|
| `ubuntu-*` (`ubuntu-latest` …), or exactly `ubuntu` or `linux` | linux |
| `windows-*` (`windows-latest` …), or exactly `windows` | windows |
| `macos-*` (`macos-latest` …), or exactly `macos` or `mac` | macos |
| an expression (`${{ matrix.os }}` etc.), or self-hosted with no OS label | unknown |

| destination | Linux / macOS | Windows | unknown |
|---|:---:|:---:|:---:|
| `${{ runner.temp }}/...` | safe | safe | safe |
| `$RUNNER_TEMP/...` | unsafe | unsafe | unsafe |
| `/tmp/...` | safe | unsafe | safe |
| `/var/...` | safe | unsafe | unsafe |
| any other absolute Unix path (`/opt/...`, `/home/runner/work/...`) | unsafe | unsafe | unsafe |
| absolute Windows paths (`C:\...`, `D:/...`) | unsafe | unsafe | unsafe |

Absolute Windows paths are judged unsafe on every OS: no literal Windows form is on the safe
list. When the OS is unknown, only `${{ runner.temp }}` and `/tmp` are treated as safe.

For the spellings it lists, this table states what the implementation treats as safe, not what
has been shown to lie outside the workspace. Allowing `/tmp` and `/var` on Linux and macOS assumes the GitHub-hosted
layout, where the workspace is under `/home/runner/work/...`, and does not hold for a
self-hosted runner. Where a self-hosted runner places its work directory cannot be determined
from the workflow file. In fact `runs-on: [self-hosted, ubuntu-latest]` is inferred as `linux`,
so a path under `/var` is not reported, while `runs-on: [self-hosted]` alone reports the same
path. Only the runner's own temporary directory does not depend on where the runner places the
workspace; the rule accepts the `${{ runner.temp }}` expression for it, ignoring whitespace and
letter case inside `${{ }}`, and rejects it when a `..` segment follows, so
`${{ runner.temp }}/../work` is reported. A literal `$RUNNER_TEMP` is not accepted: `with:`
inputs are not shell-expanded, so the action receives that string as written and resolves it
inside the workspace.

Read the message with the table in mind. For a destination that is on the list under one OS and
off it under another, the message still reads "Workspace-relative paths allow malicious
artifacts to overwrite source code" — `/tmp/artifacts` under `windows-latest` is reported with
that wording even though the path is not workspace-relative. The finding is about the list, not
about a determination that the destination is in the workspace.

### Not taking the artifact at all

Moving the destination stops the overwrite. It does not stop the privileged job from consuming
something a less-trusted run produced; Remediation says as much, and the not-detected example
shows only that the overwrite is gone.

A pipeline can avoid the question instead of answering it. Build and deploy in separate
workflows: the build runs on the pull request without privileges, and the deploy runs from a
trusted ref and builds what it needs from the checked-out source rather than downloading an
artifact a pull request produced. Nothing crosses from the less-trusted run into the privileged
one, and this rule reports nothing because there is no download step left to look at.

This is not something the rule checks, and it is not always available — some pipelines exist
precisely to hand a built artifact to a deploy job, and rebuilding is not free. Where it is
available, it removes the risk rather than relocating it.

## References

- [actions/download-artifact README (`484a0b52`)](https://github.com/actions/download-artifact/blob/484a0b528fb4d7bd804637ccb632e47a0e638317/README.md#inputs)
  — `path` defaults to `$GITHUB_WORKSPACE`; a `github-token` is required to download from a
  different repository or workflow run. Both inputs read the same way in `v4`, which the examples
  above use
- [CodeQL: Artifact Poisoning (Critical)](https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/)
- [GitHub: Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub: Securely using `pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
  — a pull request from a fork runs `pull_request` / `pull_request_review` /
  `pull_request_review_comment` with a read-only `GITHUB_TOKEN` and without other secrets
- [OWASP: CICD-SEC-04 - Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [GitHub: Store and share data with workflow artifacts](https://docs.github.com/en/actions/tutorials/store-and-share-data)
- [GitHub: Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
  — what a build attestation establishes and what it does not. It links an artifact to the source
  and the build instructions that produced it; GitHub states it is not a guarantee that the
  artifact is secure, and leaves the policy criteria to the consumer
- [Rule source (`v0.3.7`)](https://github.com/sisaku-security/sisakulint/blob/v0.3.7/pkg/core/artifactpoisoningcritical.go)
