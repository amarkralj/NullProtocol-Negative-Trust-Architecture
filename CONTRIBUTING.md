# Contributing

Thank you for your interest in NullProtocol Negative Trust.

## Get in touch

The best way to contribute is to write to **contact@xevorislabs.com**. We are especially interested in:

* **Pilots:** organisations willing to run it in shadow mode (it observes and reports, it restricts no one).
* **Research:** questions about the model, the evaluation or the datasets, and ideas for new tests.
* **Data:** public or shareable insider-threat and attack datasets we have not used yet.
* **Commercial licences:** for building it into a closed product or service (see the licence section of the README).

## Issues

You can also open an issue for:

* errors or unclear parts in the documents,
* questions about the results or the method,
* attack paths you think it would miss.

Please do not post security vulnerabilities as issues; see [SECURITY.md](SECURITY.md).

## Pull requests

Pull requests are welcome. Please open an issue or write to us first for anything larger than a small fix, so we can
agree on the approach. Before submitting, run:

```bash
pip install -e ".[dev]" ruff
ruff check --select F,B src scripts tests
pytest -q
npcore selftest
```

**Licence of contributions.** By submitting a pull request you confirm that you wrote the contribution (or have the
right to submit it), and you agree that

* it is licensed under AGPL-3.0-only, like the rest of the repository, and
* you grant the project maintainer (amarkralj) and any legal entity the maintainer creates to continue the project
  a perpetual, worldwide, royalty-free right to also license your contribution under other
  terms, including commercial licences.

The second point keeps the project able to offer commercial licences; you keep the copyright to your contribution.

## Conduct

Be respectful and constructive. Do not post personal data about real employees or incidents that are not public.
