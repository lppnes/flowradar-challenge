from typing import Any


_ZEROISH = (None, "")


def _num(features: dict[str, Any], key: str) -> float:
    value = features.get(key, 0.0)
    if value in _ZEROISH:
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _ratio(left: float, right: float) -> float:
    total = abs(left) + abs(right)
    if total <= 0.0:
        return 0.0
    value = (left - right) / total
    if value < -1.0:
        return -1.0
    if value > 1.0:
        return 1.0
    return value


def _band(value: float, cuts: tuple[float, ...]) -> int:
    rank = 0
    for cut in cuts:
        if value > cut:
            rank += 1
    return rank


def _rate(total: float, duration: float, scale: float) -> float:
    if total <= 0.0 or duration <= 0.0:
        return 0.0
    return total / (duration + scale)


def _flag_density(flags: float, packets: float) -> float:
    if flags <= 0.0 or packets <= 0.0:
        return 0.0
    return flags / max(packets, 1.0)


def _flow_view(features: dict[str, Any]) -> dict[str, float]:
    duration = max(_num(features, "flow_duration"), 1.0)
    fwd_pkts = _num(features, "fwd_num_pkts")
    bwd_pkts = _num(features, "bwd_num_pkts")
    fwd_bytes = _num(features, "fwd_sum_pkt_len")
    bwd_bytes = _num(features, "bwd_sum_pkt_len")
    fwd_mean = _num(features, "fwd_mean_pkt_len")
    bwd_mean = _num(features, "bwd_mean_pkt_len")
    fwd_std = _num(features, "fwd_std_pkt_len")
    bwd_std = _num(features, "bwd_std_pkt_len")
    fwd_max = _num(features, "fwd_max_pkt_len")
    bwd_max = _num(features, "bwd_max_pkt_len")
    fwd_iat = _num(features, "fwd_mean_iat")
    bwd_iat = _num(features, "bwd_mean_iat")
    fwd_jitter = _num(features, "fwd_std_iat")
    bwd_jitter = _num(features, "bwd_std_iat")
    fwd_ack = _num(features, "fwd_num_ack_flags")
    bwd_ack = _num(features, "bwd_num_ack_flags")
    fwd_psh = _num(features, "fwd_num_psh_flags")
    bwd_psh = _num(features, "bwd_num_psh_flags")
    fwd_rst = _num(features, "fwd_num_rst_flags")
    bwd_rst = _num(features, "bwd_num_rst_flags")
    packets = fwd_pkts + bwd_pkts
    byte_total = fwd_bytes + bwd_bytes
    return {
        "packets": packets,
        "bytes": byte_total,
        "packet_rate": _rate(packets, duration, 32.0),
        "byte_rate": _rate(byte_total, duration, 256.0),
        "pkt_balance": _ratio(fwd_pkts, bwd_pkts),
        "byte_balance": _ratio(fwd_bytes, bwd_bytes),
        "mean_gap": abs(_ratio(fwd_mean, bwd_mean)),
        "std_level": max(fwd_std, bwd_std),
        "max_level": max(fwd_max, bwd_max),
        "iat_gap": abs(_ratio(fwd_iat, bwd_iat)),
        "jitter_level": max(fwd_jitter, bwd_jitter),
        "ack_skew": abs(_flag_density(fwd_ack, fwd_pkts) - _flag_density(bwd_ack, bwd_pkts)),
        "push_skew": abs(_flag_density(fwd_psh, fwd_pkts) - _flag_density(bwd_psh, bwd_pkts)),
        "reset_load": _flag_density(fwd_rst + bwd_rst, packets),
        "duration": duration,
    }


def _ordinal_signature(view: dict[str, float]) -> tuple[int, ...]:
    return (
        _band(view["duration"], (160.0, 900.0, 2600.0, 8200.0)),
        _band(view["packet_rate"], (0.003, 0.015, 0.045, 0.12)),
        _band(view["byte_rate"], (0.8, 8.0, 32.0, 96.0)),
        _band(abs(view["pkt_balance"]), (0.12, 0.28, 0.48, 0.72)),
        _band(abs(view["byte_balance"]), (0.10, 0.24, 0.42, 0.66)),
        _band(view["mean_gap"], (0.08, 0.18, 0.34, 0.58)),
        _band(view["std_level"], (80.0, 240.0, 620.0, 1300.0)),
        _band(view["max_level"], (220.0, 760.0, 1450.0, 2600.0)),
        _band(view["iat_gap"], (0.10, 0.25, 0.45, 0.70)),
        _band(view["jitter_level"], (80.0, 300.0, 900.0, 2200.0)),
        _band(view["ack_skew"] + view["push_skew"], (0.08, 0.18, 0.36, 0.62)),
        _band(view["reset_load"], (0.01, 0.04, 0.10, 0.22)),
    )


def _lattice_score(sig: tuple[int, ...], view: dict[str, float]) -> int:
    score = 0
    score += 2 if sig[0] >= 2 and sig[9] >= 2 else 0
    score += 2 if sig[2] >= 2 and sig[7] >= 2 else 0
    score += 1 if sig[3] >= 2 and sig[10] >= 2 else 0
    score += 1 if sig[4] >= 2 and sig[5] >= 2 else 0
    score += 1 if sig[8] >= 2 and sig[1] <= 2 else 0
    score += 1 if sig[6] >= 2 and sig[0] >= 1 else 0
    score += 1 if view["packet_rate"] < 0.012 and view["jitter_level"] > 650.0 else 0
    score += 1 if view["byte_rate"] > 18.0 and view["mean_gap"] > 0.22 else 0
    score -= 2 if sig[1] >= 4 and sig[0] <= 1 else 0
    score -= 1 if view["packets"] < 4.0 or view["bytes"] < 96.0 else 0
    score -= 1 if sig[2] >= 4 and sig[9] <= 1 else 0
    score -= 1 if view["reset_load"] > 0.18 and sig[0] <= 1 else 0
    return score


def _consistency_gate(sig: tuple[int, ...], view: dict[str, float]) -> bool:
    if view["packets"] <= 0.0 or view["bytes"] <= 0.0:
        return False
    transport_shape = sig[3] + sig[4] + sig[10]
    timing_shape = sig[0] + sig[8] + sig[9]
    payload_shape = sig[2] + sig[6] + sig[7]
    if timing_shape >= 8 and payload_shape >= 6:
        return True
    if transport_shape >= 8 and payload_shape >= 7:
        return True
    return timing_shape >= 7 and transport_shape >= 6 and view["byte_rate"] > 5.0


def detect_vpn(features: dict[str, Any]) -> bool:
    view = _flow_view(features)
    sig = _ordinal_signature(view)
    score = _lattice_score(sig, view)
    if score >= 5 and _consistency_gate(sig, view):
        return True
    if score >= 4 and sig[9] >= 3 and sig[7] >= 2:
        return True
    return score >= 6


__all__ = ["detect_vpn"]
