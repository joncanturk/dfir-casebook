# Contributing

Use synthetic evidence only. Each case needs explicit provenance, a byte-exact manifest, supported parsing, expected outputs, a report with alternative explanations and tests for unsupported correlations.

For an evidence change, document why the original fixture was wrong, update its manifest, and independently review changed expected facts before accepting regenerated outputs. Do not regenerate goldens simply to pass a failing test. Keep source artifacts and derivatives separate.

Run `python -m unittest discover -s tests -v`. Public contributions must not include customer logs, account credentials, real incident identifiers or executable malicious payloads.
