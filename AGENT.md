# AGENT Guide

This repository is a RedTeam FlowRadar VPN Detection challenge.

Use this guide as the default operating playbook for any coding agent working in this repo.

## Challenge Summary

- Goal: detect whether a network flow is VPN traffic.
- Input: each request contains flow-level network features in `products`.
- Output: return a boolean `is_vpn` prediction.
- Score driver:
  - maximize F1 score (precision/recall balance on VPN class).

Core feature columns used by the challenge dataset:

`flow_duration,fwd_num_pkts,bwd_num_pkts,fwd_sum_pkt_len,bwd_sum_pkt_len,fwd_min_pkt_len,fwd_mean_pkt_len,fwd_std_pkt_len,fwd_max_pkt_len,bwd_min_pkt_len,bwd_mean_pkt_len,bwd_std_pkt_len,bwd_max_pkt_len,fwd_min_iat,fwd_mean_iat,fwd_std_iat,fwd_max_iat,bwd_min_iat,bwd_mean_iat,bwd_std_iat,bwd_max_iat,fwd_num_syn_flags,fwd_num_ack_flags,fwd_num_fin_flags,fwd_num_rst_flags,fwd_num_psh_flags,fwd_num_urg_flags,bwd_num_syn_flags,bwd_num_ack_flags,bwd_num_fin_flags,bwd_num_rst_flags,bwd_num_psh_flags,bwd_num_urg_flag`

## Where To Implement

Only this submission file is intended for solver logic:

- `src/flr_challenge/challenge/flowradar/src/submissions.py`

Important:
- keep solver implementation inside this file.
- scoring helpers retrieve submission content from this path.

Challenge dataset used during scoring replay:
- `volumes/storage/flowradar-challenge/data/metrics.csv`

Execution flow:

1. `/score` receives submission file content.
2. challenge API boots flowradar runtime with your submission.
3. each dataset row is sent to `/vpn_detector` as `{"products": row_data}`.
4. your `detect_vpn(features)` returns `True` or `False`.
5. scorer compares predictions vs `is_vpn` labels and computes F1.

## Scoring Behavior (Important)

Scoring is computed from VPN classification outcomes:

- precision = TP / (TP + FP)
- recall = TP / (TP + FN)
- final score = F1 = 2 * (precision * recall) / (precision + recall)

Additional rule:

- if request misses exceed `FLR_CHALLENGE_ACCEPTABLE_MISS_COUNT`, scoring loop stops early and score will usually degrade significantly.

Keep logic efficient and resilient to avoid request failures/timeouts.

## Skills

### 1) challenge-setup

- Location: `skills/challenge-setup/SKILL.md`
- Scripts:
  - `skills/challenge-setup/scripts/setup.sh`
  - `skills/challenge-setup/scripts/healthcheck.sh`
- Use when:
  - preparing local environment
  - validating `.env` and API availability
  - booting challenge services with Docker Compose
- Quick usage:
  - `./skills/challenge-setup/scripts/setup.sh`
  - `./skills/challenge-setup/scripts/setup.sh --build`
  - `./skills/challenge-setup/scripts/healthcheck.sh`

### 2) challenge-score

- Location: `skills/challenge-score/SKILL.md`
- Script: `skills/challenge-score/scripts/check_score.py`
- Use when:
  - running `/score` against current `submissions.py`
  - validating payload/schema expectations
  - checking endpoint-level score behavior quickly
- Quick usage:
  - `python3 skills/challenge-score/scripts/check_score.py`

### 3) challenge-solver-guide

- Location: `skills/challenge-solver-guide/SKILL.md`
- References:
  - `skills/challenge-solver-guide/references/important-files.md`
  - `skills/challenge-solver-guide/references/do-and-dont.md`
- Use when:
  - designing robust VPN detection logic
  - selecting stable predictive flow features
  - iterating toward better precision/recall tradeoff

## Agent Workflow (Recommended)

1. Setup
   - run challenge setup + health check.
2. Baseline
   - run score script and record F1.
3. Analyze
   - inspect `submissions.py` behavior and failure patterns.
4. Implement
   - update feature engineering and decision logic in `detect_vpn`.
5. Re-score
   - run score script after each meaningful change.
6. Diagnose
   - use telemetry/results and logs to understand regressions.
7. Iterate
   - tune thresholds and feature combinations for stronger F1.

## Key Endpoints

- `POST /score` - evaluates current submission.
- `GET /status` - scoring state.
- `GET /results` - stored scoring outcomes.
- `GET /telemetry` - runtime, network, size, score metrics.
- `GET /task` - returns current task input shape.

## Environment Notes

- `FLR_CHALLENGE_API_KEY` is required for protected challenge endpoints.
- `DEBUG=true` increases logs and helps troubleshooting.
- For final production-grade validation, do not alter:
  - `FLR_CHALLENGE_ACCEPTABLE_MISS_COUNT`
  - `FLR_CHALLENGE_SINGLE_REQUEST_TIMEOUT`

## Debugging

- API/container startup issues:
  - `docker compose ps`
  - `docker compose logs -f challenge-api`
- Scoring anomalies:
  - check `/telemetry` and `/results`
  - inspect precision/recall tradeoffs and class bias
- Runtime failures:
  - reduce expensive operations in request path
  - handle missing/malformed fields defensively

## Solver Quality Bar

Avoid simplistic fixed-threshold logic with no feature interaction.

Preferred approach:

- robust feature extraction from packet, duration, timing, and flag signals
- canonical numeric handling (missing values, safe casting, bounded transforms)
- balanced decision rules that improve both precision and recall
- resilience to noisy or partially missing flow metrics
