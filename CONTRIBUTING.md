# Contributing

Issues and pull requests are welcome.

## Development setup

```bash
git clone <URL copied from Code → Local → HTTPS>
cd integrity-next
python -m venv .venv
. .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install ".[dev]"
python -m pytest -q
```

Run Ruff for changed Python files:

```bash
python -m ruff check path/to/changed.py
```

Keep changes focused and include tests for behavior changes. Do not weaken
signature, provenance, authority, deadline, cancellation or privacy checks to
make a test pass. Explain the problem, resulting behavior and validation in the
pull request.

The public repository is a closed projection of a larger canonical development
tree. Maintainers handle reconciliation; contributors need no private access.
By submitting a contribution, you agree that it is licensed under Apache-2.0.

Report vulnerabilities through the private channel described in
[`SECURITY.md`](SECURITY.md).
