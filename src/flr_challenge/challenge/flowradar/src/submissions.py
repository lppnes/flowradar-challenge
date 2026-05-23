from typing import Any


_FIELDS = (
    "flow_duration",
    "fwd_num_pkts",
    "bwd_num_pkts",
    "fwd_sum_pkt_len",
    "bwd_sum_pkt_len",
    "fwd_min_pkt_len",
    "fwd_mean_pkt_len",
    "fwd_std_pkt_len",
    "fwd_max_pkt_len",
    "bwd_min_pkt_len",
    "bwd_mean_pkt_len",
    "bwd_std_pkt_len",
    "bwd_max_pkt_len",
    "fwd_min_iat",
    "fwd_mean_iat",
    "fwd_std_iat",
    "fwd_max_iat",
    "bwd_min_iat",
    "bwd_mean_iat",
    "bwd_std_iat",
    "bwd_max_iat",
    "fwd_num_syn_flags",
    "fwd_num_ack_flags",
    "fwd_num_fin_flags",
    "fwd_num_rst_flags",
    "fwd_num_psh_flags",
    "fwd_num_urg_flags",
    "bwd_num_syn_flags",
    "bwd_num_ack_flags",
    "bwd_num_fin_flags",
    "bwd_num_rst_flags",
    "bwd_num_psh_flags",
    "bwd_num_urg_flags",
)

_STUMPS = (
    (5, 60.0, 1.13, -1.0, 1.0),
    (35, 0.482, 0.55, -1.0, 1.0),
    (39, 0.440, 0.36, -1.0, 1.0),
    (8, 1413.5, 0.18, -1.0, 1.0),
    (8, 1800.0, 0.24, -1.0, 1.0),
    (16, 940.0, 0.22, -1.0, 1.0),
    (20, 990.0, 0.24, -1.0, 1.0),
    (24, 1.5, 0.26, -1.0, 1.0),
    (31, 3.5, 0.13, -1.0, 1.0),
    (38, 0.225, 0.16, -1.0, 1.0),
    (39, 0.365, 0.14, -1.0, 1.0),
    (40, 0.185, 0.12, 1.0, -1.0),
    (41, 7.00, 0.18, -1.0, 1.0),
    (42, 8.73, 0.15, 1.0, -1.0),
    (43, 7.30, 0.42, -1.0, 1.0),
    (44, 7.84, 0.17, 1.0, -1.0),
)

_THRESHOLD = -1.18


def _num(features: dict[str, Any], key: str) -> float:
    value = features.get(key, 0.0)
    if value in (None, ""):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _log1p(value: float) -> float:
    if value <= 0.0:
        return 0.0
    x = value / (value + 2.0)
    term = x
    total = 0.0
    n = 1
    while n <= 15:
        total += term / n
        term *= x
        n += 1
    return 2.0 * total


def _features(features: dict[str, Any]) -> tuple[float, ...]:
    raw = [_num(features, key) for key in _FIELDS]
    duration = max(raw[0], 1.0)
    fwd_pkts = raw[1]
    bwd_pkts = raw[2]
    fwd_bytes = raw[3]
    bwd_bytes = raw[4]
    total_pkts = max(fwd_pkts + bwd_pkts, 1.0)
    total_bytes = max(fwd_bytes + bwd_bytes, 1.0)
    derived = (
        total_pkts,
        total_bytes,
        total_bytes / duration,
        total_pkts / duration,
        fwd_bytes / max(fwd_pkts, 1.0),
        bwd_bytes / max(bwd_pkts, 1.0),
        (fwd_pkts - bwd_pkts) / total_pkts,
        (fwd_bytes - bwd_bytes) / total_bytes,
        raw[16] / duration,
        raw[20] / duration,
        raw[24] / max(fwd_pkts, 1.0),
        raw[25] / max(fwd_pkts, 1.0),
        raw[31] / max(bwd_pkts, 1.0),
        raw[29] / max(bwd_pkts, 1.0),
    )
    logs = tuple(_log1p(value) for value in raw[:13] + list(derived))
    return tuple(raw) + derived + logs


def _capsule_score(values: tuple[float, ...]) -> float:
    score = -0.62
    for idx, threshold, weight, below, above in _STUMPS:
        score += weight * (above if values[idx] > threshold else below)

    fwd_max = values[8]
    bwd_max = values[12]
    fwd_iat = values[16]
    bwd_iat = values[20]
    fwd_min = values[5]
    bwd_psh_rate = values[39]
    fwd_rst_rate = values[38]
    bwd_fin_rate = values[40]
    bwd_max_ratio = values[35]

    if fwd_min > 60.0 and fwd_max > 1450.0 and bwd_psh_rate > 0.36:
        score += 0.52
    if max(fwd_iat, bwd_iat) > 1000.0 and bwd_max_ratio < 0.75:
        score += 0.46
    if fwd_rst_rate > 0.13 and fwd_max > 1500.0:
        score += 0.34
    if bwd_fin_rate > 0.18:
        score -= 0.40
    if bwd_max >= 2500.0 and fwd_max <= 1420.0 and max(fwd_iat, bwd_iat) < 300.0:
        score -= 0.42
    if values[0] < 450.0 and values[33] > 18.0:
        score -= 0.28
    return score


def detect_vpn(features: dict[str, Any]) -> bool:
    values = _features(features)
    if values[1] + values[2] <= 0.0 or values[3] + values[4] <= 0.0:
        return False
    return _capsule_score(values) >= _THRESHOLD


__all__ = ["detect_vpn"]
