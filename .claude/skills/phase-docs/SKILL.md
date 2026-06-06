---
name: phase-docs
description: Write the technical journey document for a completed development phase of sentinel-soc, then update README.md and CHANGELOG.md. Use this AFTER a phase's development is finished (code written, tests green) — when the user says a phase is done, asks to "document phase N", or the phase-runner agent invokes it. Produces docs/phases/phaseN.md plus README/CHANGELOG updates.
---

# Phase Documentation Skill

You write the **phase journey document** for one development phase of `sentinel-soc`,
then refresh `README.md` and `CHANGELOG.md`. The reader is the project owner reading
this **months later** to remember what happened. Be **brief, technical, and concrete** —
no marketing fluff, no padding. Every claim must be grounded in what is actually in the
repo, not in the plan in `CLAUDE.md`.

## Inputs

- **Phase number** (1–8) and its name. If not given, infer from `CLAUDE.md`'s phase table
  and the latest work; if still ambiguous, ask the user one short question.
- If a `docs/test-reports/phaseN.md` exists (written by the `phase-test` skill), read it —
  fold its real findings into the "Problems & gotchas" section instead of inventing them.

## Step 1 — Gather real ground truth (do NOT trust the plan)

Run these and read the results before writing a single line:

1. **What changed in this phase.** Prefer a phase tag boundary if one exists:
   - `git tag --list "phase-*"` to see if tags exist.
   - If `phase-{N-1}` tag exists: `git diff --stat phase-{N-1}..HEAD` and
     `git log phase-{N-1}..HEAD --oneline`.
   - If no tags (current repo state): `git log --oneline` and inspect the working tree /
     latest commit. Do **not** silently attribute the entire history to this phase — if you
     cannot cleanly scope the diff to this phase, say which files you are treating as the
     phase's work and why.
2. **Read the actual code** that this phase delivered (the changed `sentinel/...` files).
   Confirm what is genuinely implemented vs. stubbed (look for `not_yet_implemented`,
   `# TODO`, `NotImplementedError`, hardcoded mock returns).
3. **Test reality.** Run `uv run pytest -q` (env: `MOCK_ADAPTERS=true`,
   `POLICY_ENFORCEMENT=false`). Record exact numbers: tests passed/failed and the real
   coverage line (`TOTAL ... NN%`). Never copy a coverage number from the plan.

## Step 2 — Write `docs/phases/phaseN.md`

Create `docs/` and `docs/phases/` if missing. Use this exact skeleton. Keep the whole doc
tight — aim for one screen of substance, expand only where a decision genuinely needs it.

```markdown
# Phase N — <Name>

*Documented: <YYYY-MM-DD>*  ·  *Status: <Complete | Partial — see deferred>*

## Goal
<One or two sentences: what this phase set out to achieve.>

## What was built
<Bulleted, concrete. Name the components/files and what each now does. Mark anything
still stubbed or deferred explicitly — honesty over completeness.>

## How it works
<The key flows and architecture introduced this phase. Use a small diagram or numbered
data-flow where it clarifies. Reference real files as file_path:line.>

## Key decisions & trade-offs
<Each as: **Decision** — why chosen, what was rejected, and the cost/consequence.
Only decisions actually made this phase. This is the most valuable section for future-me.>

## Problems & gotchas
<Real issues hit this phase and how they were resolved. Pull genuine items from
docs/test-reports/phaseN.md if present. If none, say "None significant." Do not invent.>

## Verification
- Tests: <passed>/<total> passing (`uv run pytest`)
- Coverage: <NN>% (real number from this run)
- Lint/type: <ruff / mypy status if run>

## Deferred to later phases
<What was intentionally left for a future phase, and which phase.>
```

Rules:
- **Technical and specific.** "Added circuit breaker to BaseAdapter (`sentinel/adapters/base.py:92`)
  — opens after 5 failures, half-open probe after 30s" beats "improved reliability".
- **No invented metrics.** If you didn't measure it, don't print it.
- **Link code** as `sentinel/...:line` so it stays clickable and verifiable.

## Step 3 — Update README.md

- Refresh the **Current Status** section to this phase (and "Next: Phase N+1 — <name>").
- If this phase added user-visible capability (tools working, transport, auth), update the
  relevant README section so README never claims more than the code delivers.
- Keep README honest: do not advertise features that are still stubbed.

## Step 4 — Update CHANGELOG.md

Prepend (newest first) a real entry — not a one-liner. Example:

```markdown
## Phase N — <Name> (<YYYY-MM-DD>)

### Added
- <concrete capability>
### Changed
- <concrete change>
### Known gaps
- <stub/deferred item>
```

## Step 5 — Report back

Output a 3–5 line summary: the phase doc path, what the README/CHANGELOG changes were, and
the verification numbers. If you discovered the code contradicts `CLAUDE.md`'s stated phase
status, flag it — don't paper over it.

## Hard rules
- Ground every statement in the repo. When unsure, inspect; never guess.
- Brief beats long. Cut anything that doesn't help future-me understand or rebuild.
- Do not touch source code or tests — this skill only writes docs (`docs/`, `README.md`,
  `CHANGELOG.md`).
