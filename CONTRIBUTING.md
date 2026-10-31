# Contributing

1. Open an issue explaining the intended behavior before large changes.
2. Fork the repository and create a feature branch.
3. Make changes with type hints and focused tests, including negative/adversarial cases.
4. Run `python -m pip install -e .` and `python -m unittest discover -s tests -v`.
5. Never add live credentials, real private data, or potentially dangerous proof-of-concept payloads.
6. Open a pull request describing the threat model impact, portability, and test coverage.

Contributions are reviewed for correctness and safe-by-default behavior; CI passing is necessary but not sufficient.