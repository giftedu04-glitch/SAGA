"""Shared protocol helpers for SAGA.

Implements length-prefixed JSON framing and optional HMAC signing.

Frame format:
- 4-byte big-endian length (unsigned)
- JSON payload bytes (UTF-8)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any


class FrameTooLarge(ValueError):
    pass


def canonical_json_bytes(obj: Any) -> bytes:
    # Stable canonicalization for signing.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def encode_frame(obj: Any, *, max_frame_bytes: int = 16 * 1024 * 1024) -> bytes:
    payload = canonical_json_bytes(obj)
    if len(payload) > max_frame_bytes:
        raise FrameTooLarge(f"Frame payload {len(payload)} exceeds limit {max_frame_bytes}")
    return len(payload).to_bytes(4, "big") + payload


def decode_frame_from_bytes(buf: bytes, *, max_frame_bytes: int = 16 * 1024 * 1024) -> tuple[Any, bytes]:
    if len(buf) < 4:
        raise ValueError("buffer too small")
    n = int.from_bytes(buf[:4], "big")
    if n > max_frame_bytes:
        raise FrameTooLarge(f"Frame payload {n} exceeds limit {max_frame_bytes}")
    if len(buf) < 4 + n:
        raise ValueError("incomplete frame")
    payload = buf[4 : 4 + n]
    rest = buf[4 + n :]
    return json.loads(payload.decode("utf-8")), rest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def sign_message(message: dict[str, Any], token: str, *, ts: int | None = None, nonce: str | None = None) -> dict[str, Any]:
    # Return a shallow-copied message with an auth block.
    if ts is None:
        ts = int(time.time())
    if nonce is None:
        nonce = _b64url(secrets.token_bytes(16))

    msg = dict(message)

    # Include ts/nonce in the signed payload; exclude the signature itself.
    auth_no_sig = {"ts": int(ts), "nonce": str(nonce)}
    msg_for_sig = dict(msg)
    msg_for_sig["auth"] = auth_no_sig

    mac = hmac.new(token.encode("utf-8"), canonical_json_bytes(msg_for_sig), hashlib.sha256).digest()
    auth = dict(auth_no_sig)
    auth["sig"] = _b64url(mac)

    msg["auth"] = auth
    return msg


def verify_message(message: dict[str, Any], token: str, *, max_skew_s: int | None = 300) -> bool:
    try:
        auth = message.get("auth")
        if not isinstance(auth, dict):
            return False

        ts = auth.get("ts")
        nonce = auth.get("nonce")
        sig = auth.get("sig")
        if not isinstance(ts, int) or not isinstance(nonce, str) or not isinstance(sig, str):
            return False

        if max_skew_s is not None:
            now = int(time.time())
            if abs(now - ts) > int(max_skew_s):
                return False

        msg_for_sig = dict(message)
        msg_for_sig["auth"] = {"ts": ts, "nonce": nonce}

        expected = hmac.new(
            token.encode("utf-8"), canonical_json_bytes(msg_for_sig), hashlib.sha256
        ).digest()
        got = _b64url_decode(sig)
        return hmac.compare_digest(expected, got)
    except Exception:
        return False