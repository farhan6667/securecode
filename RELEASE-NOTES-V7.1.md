# SecureCode 7.1 (draft, not released): smart mode

SecureCode now stays out of the way while you code and does the deep work when you ask for it.

## Why

In 7.0 a vibe-coding session could write a little code, get a security report, fix, get another report, and be
asked to run a full security test every 40 lines. That cost credits and time, and the code hardly moved.

## What changed

- **The edit hook is silent when the file is clean.** It adds nothing to the agent's context unless the quick
  gate finds a High or Critical issue, and then it shows only those lines (Critical first). Content it already
  found clean is not checked again. `SECURECODE_HOOK_VERBOSE=1` brings back the full report after every edit.
- **The stop hook sends the agent back once per finding and session.** A High or Critical finding it already
  showed in this session is not sent back at every stop; it returns after 12 hours. The memory sits in the app
  folder, never in the project, so a cloned repository cannot silence it.
- **The security test offer waits for a feature's worth of work** (10 code files or 300 changed lines) and comes
  at most once per session. `SECURECODE_MODE=coding` or `.security/mode.json` with `{"mode": "coding"}` turns it
  off: the developer types "Run Security Test" when the program is done.
- **The rules say it plainly:** write secure code while coding, no security phases or review rounds between
  edits, one short self-check of the diff before "done" (plus the one matching checklist section for endpoint,
  auth, session, upload, payment, crypto and deserialization changes), and the long checklists only for
  "Run Security Test".
  The skill no longer loads for ordinary coding. `/security-gate` no longer runs the project tests twice.

## What did not change

The PreToolUse guard (secrets, destructive commands), the secret shield, the High and Critical block on stop,
"Run Security Test" (Mode B: deep review, full gate, retests, report) and the CI gate are the same. Nothing that
blocks a dangerous action was relaxed.

## Tests

New: silent clean edits, High and Critical only and never lost in a long report, findings never cached, the cache
refusing a link, once per session, coding mode (environment and file), the same finding blocked once per session
and a new one blocked again, a planted or future-dated memory ignored, only printed findings remembered. The offer
tests moved to the new thresholds. An independent review of the first draft found six issues (FINDINGS SM-01 to
SM-06); all are fixed with tests in this branch.

Not measured: tokens saved per session. The saving depends on how often a session edits clean files.
