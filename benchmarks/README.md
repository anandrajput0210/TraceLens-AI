# TraceLens benchmark starter

## Status

This is a **candidate corpus**, not a scanned or adjudicated benchmark yet. The repository list must be reviewed, each selected repository must be pinned to an immutable commit SHA, and every labeled finding must be independently checked. Do not report benchmark performance until the dataset has been frozen and labels adjudicated.

## Scope for the first benchmark

Evaluate only findings from the detector families TraceLens currently implements:

- SEC-001 / SEC-002: hardcoded credentials and high-entropy strings
- SEC-003: production configuration signals
- SEC-004: debug mode
- SEC-005: permissive CORS
- SEC-006: sensitive endpoints
- SEC-007: Docker user configuration
- SEC-008: CI/CD credential exposure

Do **not** label SQL injection, XSS, dependency CVEs, authentication flaws, or other findings as TraceLens detections unless a future detector actually supports them. OWASP BenchmarkJava and BenchmarkPython include ground-truth test cases for broader SAST categories; use only matching cases for this first version. OWASP describes the Benchmark as a suite intended to assess vulnerability-detection accuracy and speed, with deliberately included cases and scoring utilities.

## Important label separation

The original three labels ("fix first", "fix later", "noise") mix detection correctness with priority. Record two independent judgments:

1. `finding_validity`: `confirmed`, `false_positive`, or `uncertain`.
2. `triage_priority`: `fix_first`, `fix_later`, or `noise`.

A finding can be valid but low priority. A false positive should receive `noise`. Do not count an uncertain finding as a confirmed true positive in the headline precision metric.

## Reproducibility

For every selected repository:

1. Clone a shallow copy and record the exact commit SHA in `repositories.csv`.
2. Record the TraceLens commit SHA and scan timestamp.
3. Run the exact same scanner configuration on every repository.
4. Keep a stable finding identity: repository commit + rule ID + normalized path + line + SHA-256 of redacted evidence.
5. Store only redacted evidence. Never commit live credentials, tokens, private keys, or full secret values to this benchmark.
6. Keep the raw cloned repositories outside this benchmark directory; commit only manifests and redacted annotations.

## Annotation procedure

- Target 100 findings from at least 20 repositories, if the candidate corpus yields enough findings in the supported rule families.
- Reviewers should label findings without seeing the TraceLens contextual score or rank first. This reduces anchoring.
- Record a short rationale and a source URL or file/line evidence for each label.
- Double-label at least 20% of findings. Resolve disagreements with a documented adjudication.
- If a candidate produces no in-scope findings, record that fact; do not invent a finding to fill a quota.
- Include both intentionally vulnerable training applications and maintained production projects, and report their results separately as well as combined. The two cohorts are not interchangeable.

## Comparison protocol

Use the same confirmed findings for both ordering methods:

- **Baseline:** base severity descending (`CRITICAL > HIGH > MEDIUM > LOW > INFO`), then rule ID, path, and line ascending.
- **TraceLens:** contextual score descending, then rule ID, path, and line ascending.

Report at minimum:

- Precision@10 for `fix_first` among the first ten findings.
- False-positive/noise rate in the first ten.
- NDCG@10 with gains: `fix_first = 2`, `fix_later = 1`, `noise = 0`.
- Spearman rank correlation between context score and adjudicated priority.
- Macro-average across repositories, so one very large repository cannot dominate the result.

Split by repository, not by finding: reserve roughly 20% of repositories as a holdout set. Tune scoring weights only on the development repositories. Publish the held-out result once; do not repeatedly tune against the holdout.

## Files

- `repositories.csv`: candidate repository pool; fill commit SHA, license, and selection status after review.
- `findings-template.csv`: one row per adjudicated finding. Keep evidence redacted.
- Do not add actual scan results until each row has been reviewed.

## Candidate-source notes

- OWASP Benchmark: https://owasp.org/projects/benchmark
- OWASP Juice Shop: https://devguide.owasp.org/en/07-training-education/01-vulnerable-apps/01-juice-shop/
- OWASP crAPI: https://owasp.github.io/www-project-crapi/
- OWASP NodeGoat: https://github.com/OWASP/NodeGoat
- OWASP WebGoat: https://github.com/WebGoat/WebGoat
- OWASP RailsGoat: https://github.com/OWASP/railsgoat

Intentionally vulnerable apps are for isolated, authorized testing only. Never deploy these training applications publicly.
