import sys
import logging
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Body, HTTPException, Request

from data_types import VPNDetectionInput, VPNDetectionOutput
from submissions import detect_vpn

logger = logging.getLogger(__name__)
VPN_INPUT_BODY = Body(...)
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S %z",
    format="[%(asctime)s | %(levelname)s | %(filename)s:%(lineno)d]: %(message)s",
)


app = FastAPI()


def _request_id_from_headers(request: Request) -> str:
    if "X-Request-ID" in request.headers:
        return request.headers.get("X-Request-ID") or uuid4().hex
    if "X-Correlation-ID" in request.headers:
        return request.headers.get("X-Correlation-ID") or uuid4().hex
    return uuid4().hex


def _features_from_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, VPNDetectionInput):
        return payload.products
    if isinstance(payload, dict):
        products = payload.get("products")
        if isinstance(products, dict):
            return products
        return payload
    return {}


def _solve(request: Request, payload: Any) -> VPNDetectionOutput:
    logger.info("Processing FlowRadar request...")
    request_id = _request_id_from_headers(request)
    try:
        return VPNDetectionOutput(
            is_vpn=detect_vpn(_features_from_payload(payload)),
            request_id=request_id,
        )
    except Exception as err:
        logger.error(f"Failed to process FlowRadar request: {str(err)}")
        raise HTTPException(status_code=500, detail="Failed to process request.") from err


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/solve", response_model=VPNDetectionOutput)
def solve(request: Request, payload: dict[str, Any] = VPN_INPUT_BODY) -> VPNDetectionOutput:
    return _solve(request, payload)


@app.post("/vpn_detector", response_model=VPNDetectionOutput)
def fingerprint(
    request: Request, vpn_input: VPNDetectionInput = VPN_INPUT_BODY
) -> VPNDetectionOutput:
    return _solve(request, vpn_input)


__all__ = ["app"]
