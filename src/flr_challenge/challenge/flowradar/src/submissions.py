from typing import Any


def _num(features: dict[str, Any], key: str) -> float:
    value = features.get(key, 0)
    if value in (None, ""):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def detect_vpn(features: dict[str, Any]) -> bool:
    """
    Detect if the traffic is coming from a VPN based on network flow features.

    Args:
        features: Dictionary containing network flow features.

    Returns:
        True if VPN is detected, False otherwise.
    """
    flow_duration = max(_num(features, "flow_duration"), 1.0)
    fwd_num_pkts = _num(features, "fwd_num_pkts")
    bwd_num_pkts = _num(features, "bwd_num_pkts")
    total_pkts = fwd_num_pkts + bwd_num_pkts
    if total_pkts <= 0:
        return False

    fwd_sum_pkt_len = _num(features, "fwd_sum_pkt_len")
    bwd_sum_pkt_len = _num(features, "bwd_sum_pkt_len")
    byte_ratio = bwd_sum_pkt_len / max(fwd_sum_pkt_len, 1.0)
    pkts_per_ms = total_pkts / flow_duration

    max_mean_iat = max(_num(features, "fwd_mean_iat"), _num(features, "bwd_mean_iat"))
    max_std_iat = max(_num(features, "fwd_std_iat"), _num(features, "bwd_std_iat"))
    max_iat = max(_num(features, "fwd_max_iat"), _num(features, "bwd_max_iat"))

    score = sum(
        (
            flow_duration >= 1000,
            flow_duration >= 1800,
            max_mean_iat >= 85,
            max_std_iat >= 120,
            max_iat >= 280,
            _num(features, "fwd_max_pkt_len") >= 1650,
            _num(features, "fwd_std_pkt_len") >= 460,
            flow_duration >= 900 and pkts_per_ms < 0.018,
            byte_ratio > 1.15,
        )
    )

    return score >= 5


__all__ = ["detect_vpn"]
