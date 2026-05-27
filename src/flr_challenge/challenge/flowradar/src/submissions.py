from typing import Any


_RAW_FIELDS = (
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
    "fwd_mean_iat",
    "fwd_std_iat",
    "fwd_max_iat",
    "bwd_mean_iat",
    "bwd_std_iat",
    "bwd_max_iat",
    "fwd_num_syn_flags",
    "fwd_num_ack_flags",
    "fwd_num_fin_flags",
    "fwd_num_rst_flags",
    "fwd_num_psh_flags",
    "bwd_num_syn_flags",
    "bwd_num_ack_flags",
    "bwd_num_fin_flags",
    "bwd_num_rst_flags",
    "bwd_num_psh_flags",
)

_VPN_PROTO = (
    (0.78, 0.17, 0.56, 0.64, 0.70, 0.60, 0.38, 0.74, 0.58, 0.42, 0.25, 0.55),
    (0.66, 0.24, 0.47, 0.73, 0.63, 0.51, 0.55, 0.60, 0.69, 0.36, 0.34, 0.48),
    (0.72, 0.12, 0.63, 0.57, 0.76, 0.66, 0.30, 0.67, 0.50, 0.52, 0.22, 0.62),
)

_BENIGN_PROTO = (
    (0.30, 0.54, 0.25, 0.38, 0.31, 0.35, 0.46, 0.28, 0.24, 0.27, 0.18, 0.22),
    (0.18, 0.72, 0.16, 0.26, 0.24, 0.27, 0.58, 0.18, 0.20, 0.21, 0.12, 0.16),
    (0.42, 0.41, 0.34, 0.30, 0.37, 0.44, 0.34, 0.36, 0.31, 0.18, 0.44, 0.28),
)

_WEIGHTS = (1.2, 0.9, 0.8, 1.0, 0.9, 0.8, 0.7, 0.8, 0.9, 0.5, 0.5, 0.6)


def _num(features: dict[str, Any], key: str) -> float:
    value = features.get(key, 0.0)
    if value in (None, ""):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _sat(value: float, scale: float) -> float:
    if value <= 0.0:
        return 0.0
    return value / (value + scale)


def _clip_ratio(value: float) -> float:
    if value < -1.0:
        return -1.0
    if value > 1.0:
        return 1.0
    return value


def _constellation(features: dict[str, Any]) -> tuple[float, ...]:
    raw = [_num(features, key) for key in _RAW_FIELDS]
    duration = max(raw[0], 1.0)
    fwd_pkts = raw[1]
    bwd_pkts = raw[2]
    fwd_bytes = raw[3]
    bwd_bytes = raw[4]
    total_pkts = max(fwd_pkts + bwd_pkts, 1.0)
    total_bytes = max(fwd_bytes + bwd_bytes, 1.0)
    fwd_ack = raw[20] / max(fwd_pkts, 1.0)
    bwd_ack = raw[25] / max(bwd_pkts, 1.0)
    fwd_push = raw[23] / max(fwd_pkts, 1.0)
    bwd_push = raw[28] / max(bwd_pkts, 1.0)
    burst_iat = max(raw[15], raw[18]) / duration
    mean_iat = max(raw[13], raw[16]) / duration
    pkt_balance = _clip_ratio((fwd_pkts - bwd_pkts) / total_pkts)
    byte_balance = _clip_ratio((fwd_bytes - bwd_bytes) / total_bytes)
    max_pkt = max(raw[8], raw[12])
    std_pkt = max(raw[7], raw[11])
    return (
        _sat(duration, 2200.0),
        _sat(total_pkts / duration, 0.035),
        _sat(total_bytes / duration, 42.0),
        _sat(max_pkt, 2200.0),
        _sat(std_pkt, 720.0),
        _sat(max(raw[15], raw[18]), 1700.0),
        _sat(max(raw[13], raw[16]), 280.0),
        _sat(burst_iat, 0.92),
        _sat(mean_iat, 0.16),
        0.5 + 0.5 * byte_balance,
        0.5 + 0.5 * pkt_balance,
        _sat(abs(fwd_ack - bwd_ack) + abs(fwd_push - bwd_push), 0.8),
    )


def _weighted_distance(point: tuple[float, ...], proto: tuple[float, ...]) -> float:
    total = 0.0
    for idx, value in enumerate(point):
        delta = value - proto[idx]
        total += _WEIGHTS[idx] * delta * delta
    return total


def _nearest_gap(point: tuple[float, ...]) -> float:
    vpn = min(_weighted_distance(point, proto) for proto in _VPN_PROTO)
    benign = min(_weighted_distance(point, proto) for proto in _BENIGN_PROTO)
    return benign - vpn


def _shape_votes(point: tuple[float, ...]) -> int:
    votes = 0
    votes += point[0] > 0.48 and point[7] > 0.42
    votes += point[3] > 0.48 and point[4] > 0.42
    votes += point[8] > 0.38 and point[1] < 0.55
    votes += abs(point[9] - 0.5) > 0.18 and point[11] > 0.30
    votes -= point[1] > 0.70 and point[0] < 0.38
    votes -= point[2] > 0.66 and point[7] < 0.24
    return votes


def detect_vpn(features: dict[str, Any]) -> bool:
    raw_pkts = _num(features, "fwd_num_pkts") + _num(features, "bwd_num_pkts")
    raw_bytes = _num(features, "fwd_sum_pkt_len") + _num(features, "bwd_sum_pkt_len")
    if raw_pkts <= 0.0 or raw_bytes <= 0.0:
        return False

    point = _constellation(features)
    gap = _nearest_gap(point)
    votes = _shape_votes(point)
    if gap > 0.22:
        return True
    if gap > 0.06 and votes >= 2:
        return True
    return gap > -0.02 and votes >= 3 and point[0] > 0.44


__all__ = ["detect_vpn"]
