# Important Files

Use these files first when solving this challenge.

## Submission entry point (your code)

- `src/flr_challenge/challenge/flowradar/src/submissions.py`
  - contains `detect_vpn(features)` used for every replayed row.
  - all solver logic should stay here for submission/scoring compatibility.

## Runtime and API flow

- `src/flr_challenge/challenge/flowradar/src/app.py`
  - `/vpn_detector` request flow.
  - passes `products` payload into `detect_vpn`.
- `src/flr_challenge/challenge/flowradar/src/data_types.py`
  - request/response schema for detector service.

## Scoring and dataset behavior

- `src/flr_challenge/challenge/api/endpoints/challenge/service.py`
  - runs your submission in a container, replays dataset rows, tracks misses/timeouts, computes final score.
- `src/flr_challenge/challenge/api/endpoints/challenge/payload_managers.py`
  - score composition and counters:
    - true/false positives/negatives
    - precision, recall, F1 (final score)
- `src/flr_challenge/challenge/api/core/configs/_challenge.py`
  - challenge config: request timeout, acceptable misses, dataset path template, submission limits.

## Local operations

- `skills/challenge-setup/SKILL.md`
  - setup/run/health checks and environment guidance.
- `skills/challenge-score/SKILL.md`
  - scoring flow and endpoint references.
- `skills/challenge-score/scripts/check_score.py`
  - quick local score command.

## Dataset location

- `volumes/storage/flowradar-challenge/data/metrics.csv`
  - local replay dataset used by scoring service.
