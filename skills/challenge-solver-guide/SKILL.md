---
name: challenge-solver-guide
description: Use for designing and implementing high-score VPN detection submissions for this challenge.
---

# Purpose

Guide agents to solve the FlowRadar challenge with robust VPN detection logic, not brittle one-rule heuristics.

Primary objective:
- maximize F1 score by improving precision/recall balance for VPN classification.

# Quick Start

1. Set up and run challenge services:
   - `./skills/challenge-setup/scripts/setup.sh`
   - `./skills/challenge-setup/scripts/healthcheck.sh`
2. Implement changes only in submission file:
   - `src/flr_challenge/challenge/flowradar/src/submissions.py`
3. Score after each meaningful iteration:
   - `python3 skills/challenge-score/scripts/check_score.py`
4. Inspect diagnostics:
   - `GET /telemetry`, `GET /results`, and container logs.

# Important Files

See full map in:
- `skills/challenge-solver-guide/references/important-files.md`

Core challenge data/input locations:
- dataset used by scoring replay: `volumes/storage/flowradar-challenge/data/metrics.csv`
- required submission implementation file: `src/flr_challenge/challenge/flowradar/src/submissions.py`

Submission location is mandatory for local scoring flow because the score helper reads content from that file.

# Architecture Overview

High-level pipeline:
1. Challenge API `/score` receives your submitted `submissions.py` content.
2. API spins up a flowradar container with the submission mounted.
3. Dataset rows are replayed; each row sends flow metrics via `products` to `/vpn_detector`.
4. `detect_vpn(features)` returns a prediction.
5. API computes final score from classification outcomes.

Implementation implication:
- strong solutions combine multiple flow signals and robust handling of noisy or missing values.

# Scoring System

Current scoring logic (`payload_managers.py`):
- track TP, FP, TN, FN across replayed rows.
- compute precision and recall.
- compute F1 score and round to 3 decimals.

Hard failure behavior:
- if misses exceed `FLR_CHALLENGE_ACCEPTABLE_MISS_COUNT`, scoring stops early.
- excessive misses/timeouts often lower score heavily.

Optimization priority:
- improve both precision and recall together.
- reduce false positives without collapsing recall, and vice versa.

# Solver Workflow

1. Baseline
   - run current score and capture telemetry.
2. Feature strategy
   - identify predictive features from duration, packet length, IAT, and TCP flags.
   - define safe normalization/casting for every used key.
3. Decision strategy
   - combine multiple heuristics/signals into a balanced decision.
   - avoid one-feature hard dependence.
4. Iterate
   - run scoring, inspect errors, compare precision/recall tradeoffs.
5. Harden
   - ensure logic handles missing fields and unexpected values gracefully.

# Investigation Priorities

1. Feature extraction quality in `submissions.py`
   - robust parsing (`int`/`float` coercion, default values, bounds).
2. Signal design
   - packet size asymmetry, packet rates, timing variability, and flag patterns.
3. Threshold tuning
   - use combinations and score-like aggregation instead of brittle single cutoff.
4. Failure resilience
   - never throw for malformed payloads; fallback to safe defaults.

# Common Vulnerability Patterns

- High false-positive pattern:
  - classifying normal asymmetric traffic as VPN too aggressively.
- High false-negative pattern:
  - relying on only one VPN signature and missing alternate patterns.
- Overfitting pattern:
  - thresholds tuned to one narrow traffic distribution.
- Runtime failure pattern:
  - unsafe casts and divide-by-zero paths in feature math.

# Challenge-Specific Hints

- Treat this as binary classification, not identity linking.
- Start from interpretable features and incrementally tune thresholds.
- Balance class decisions with explicit precision/recall tradeoff checks.
- Keep logic lightweight; request failures directly hurt score.

# Do / Don't

See:
- `skills/challenge-solver-guide/references/do-and-dont.md`

# Helper Scripts

- Setup:
  - `./skills/challenge-setup/scripts/setup.sh`
  - `./skills/challenge-setup/scripts/healthcheck.sh`
- Score:
  - `python3 skills/challenge-score/scripts/check_score.py`

# Verification Steps

1. Run scoring script and record float score in `[0, 1]`.
2. Check `GET /telemetry` for runtime, network usage, and reported score.
3. Check `GET /results` to inspect prediction vs expected behavior.
4. Review container logs when behavior is unexpected:
   - `docker compose logs -f challenge-api`
5. Repeat after each strategic change and compare score deltas.

# Troubleshooting

- Score remains near zero:
  - inspect TP/FP/FN balance and retune thresholds.
- Many request errors/timeouts:
  - simplify expensive logic and keep runtime predictable.
- No meaningful improvement after changes:
  - revisit feature combinations and decision calibration.
- Inconsistent local results:
  - reset environment, rerun setup, and validate `.env` + API key.

# Example Requests

- "Analyze current `detect_vpn` logic and propose a precision/recall improvement plan."
- "Implement robust feature normalization for flow metrics and explain each selected signal."
- "Refactor detection logic to combine packet length, IAT, and flag-based evidence."
- "Run score, inspect telemetry, and explain the main bottleneck for higher F1."

# Expected Success States

- score is consistently non-zero and trending upward across iterations.
- misses stay below `FLR_CHALLENGE_ACCEPTABLE_MISS_COUNT`.
- detection logic handles feature noise without frequent unstable flips.
