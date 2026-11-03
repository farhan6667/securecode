# Approved exceptions (security team only)

In `ci` mode the gate ignores a project's own `config/security-suppressions.yaml`, because a pull
request could add a blanket suppression. Approved exceptions live here instead, one file per project
repository: `<owner>__<repo>.yaml` (the slash replaced by two underscores), in the same format:

```yaml
suppressions:
  - rule: SQL_CONCAT                 # a rule id, or "*" for every rule in that one file
    file: app/Legacy/Report.php      # exact repo-relative path
    reason: "Read-only report, input is an enum allowlist; replaced in Q2"
    owner: security-team@example.org
    expires: "2027-03-31"            # the finding returns by itself after this date
```

Entries without a rule, an exact file, an owner, a reason or an expiry date are ignored.
Changes to this folder go through code review by the security team (CODEOWNERS).
