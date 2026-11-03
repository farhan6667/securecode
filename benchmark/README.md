# Benchmark

`laravel-lab.json` is a tiny Laravel-shaped project with 18 planted security issues, and a list of what
should be found. It is stored as JSON so that nobody deploys it by mistake and so that this repository's
own scans stay clean. `run_lab.py` writes it to a temporary folder, runs the gate there, deletes the
folder and prints a table.

```bash
py -I benchmark/run_lab.py                # built-in checks only
py -I benchmark/run_lab.py --mode full    # plus Semgrep, Trivy and Gitleaks if installed
```

Results and their limits are in [RESULTS.md](RESULTS.md). To add a case, add the file to `files` and an
entry to `expected` with the rule you expect. A case the tools can't catch yet is welcome too; mark it
as a known gap in its description.
