# Ignored Documentation Files

These files are **not** instruction sources for the AI agent (see `claude_docs/security.md` section 1).
The agent does not read, follow or delete them. The owner moves anything still useful into
`claude_docs/` and then deletes them. Keep this list updated.

| Path | Reason |
|---|---|
| `README.md` | Root doc outside `claude_docs/` |
| `SETUP.md` | Root doc outside `claude_docs/`; move still-valid setup steps into `claude_docs/` |
| `<FEATURE>_GUIDE.md`, `QUICK_START*.md` | Root docs outside `claude_docs/` |
| `<API spec>.pdf`, `<API spec>.html` | API spec exports; remove superseded versions |
| `backend/README.md` | Framework boilerplate readme |
| `CHANGELOG*.md`, `IMPLEMENTATION_SUMMARY.md`, `*.txt` notes | Local notes, ideally git-ignored |
| `**/vendor/**`, `**/node_modules/**` docs | Third-party package docs |
