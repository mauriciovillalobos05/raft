# Final test matrix

| Profile | Suite | Scheduled | Passed | Skipped | Seconds |
| --- | --- | ---: | ---: | ---: | ---: |
| policy | security_tests | 26 | 26 | 0 | 3.359 |
| policy | pqc_tests | 24 | 24 | 0 | 19.386 |
| hybrid-preferred | security_tests | 26 | 26 | 0 | 3.305 |
| hybrid-preferred | pqc_tests | 24 | 21 | 3 | 1.187 |
| classical | security_tests | 26 | 26 | 0 | 3.290 |
| classical | pqc_tests | 24 | 19 | 5 | 1.250 |

All six suites passed. The default policy ran all 50 unique cases with zero skips. Across all profiles: 142 passed, 8 expected skips, zero failures/errors.

Strict rejection/isolation tests apply only to policy; the classical profile does not exercise hybrid-only retry or preferred-fallback behavior.

HTTP regression tests also assert server-observed HTTPS evidence is TLS 1.3 with X25519 under every profile.
