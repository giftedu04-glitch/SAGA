"""SAGA civilian client.

Sends location/status/images to a SAGA server over an asyncio TCP connection.

Security notes:
- Use TLS if your server supports it.
- Optionally attach an HMAC signature to each message via SAGA_TOKEN/--token.

Compatibility notes:
- Many servers expect an initial name line terminated by "\n". Keep --legacy-name-line
  enabled unless your server supports the framed hello message (--framed-hello).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import os
import ssl
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from saga_protocol import encode_frame, sign_message


STATUS_OPTIONS: dict[str, str] = {
    "1": "OK, need directions out",
    "2": "Injured, can move",
    "3": "Injured, cannot move",
    "4": "Others with me need help",
    "5": "Medical emergency",
}


@dataclass(frozen=True)
class ClientConfig:
    host: str
    port: int
    connect_timeout_s: float
    retries: int
    retry_backoff_s: float
    token: str | None
    tls: bool
    cafile: str | None
    tls_insecure: bool
    max_image_bytes: int
    legacy_name_line: bool
    framed_hello: bool


async def ainput(prompt: str) -> str:
    # Non-blocking input() so the event loop stays responsive.
    return await asyncio.to_thread(input, prompt)


def _build_ssl_context(cfg: ClientConfig) -> ssl.SSLContext | None:
    if not cfg.tls:
        return None

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    if cfg.cafile:
        ctx.load_verify_locations(cafile=cfg.cafile)

    if cfg.tls_insecure:
        # For development only.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    return ctx


async def connect(cfg: ClientConfig) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    last_exc: Exception | None = None
    ssl_ctx = _build_ssl_context(cfg)

    for attempt in range(cfg.retries + 1):
        try:
            async with asyncio.timeout(cfg.connect_timeout_s):
                return await asyncio.open_connection(cfg.host, cfg.port, ssl=ssl_ctx)
        except Exception as e:
            last_exc = e
            if attempt >= cfg.retries:
                break
            await asyncio.sleep(cfg.retry_backoff_s * (2**attempt))

    raise RuntimeError(f"Cannot connect to server {cfg.host}:{cfg.port}: {last_exc}")


async def send_msg(writer: asyncio.StreamWriter, msg: dict[str, Any], *, token: str | None) -> None:
    if token:
        msg = sign_message(msg, token)
    writer.write(encode_frame(msg))
    await writer.drain()


def _now_ts() -> float:
    return datetime.now().timestamp()


async def _send_hello(
    writer: asyncio.StreamWriter,
    *,
    name: str,
    token: str | None,
    legacy_name_line: bool,
    framed_hello: bool,
) -> None:
    name = name.strip()

    if legacy_name_line:
        # Backward compatible handshake: server reads until "\n".
        writer.write((name + "\n").encode("utf-8"))
        await writer.drain()

    if framed_hello:
        await send_msg(
            writer,
            {
                "type": "hello",
                "timestamp": _now_ts(),
                "payload": {"name": name},
            },
            token=token,
        )


def _warn_config(cfg: ClientConfig) -> None:
    if cfg.port < 1024:
        print(f"Warning: port {cfg.port} is < 1024; prefer a non-privileged port when possible.")

    if not cfg.tls:
        print("Warning: TLS is disabled; messages may be readable/modifiable on-path.")
    if not cfg.token:
        print("Warning: no token configured; messages are unauthenticated.")


def _read_file_bytes(path: Path, *, max_bytes: int) -> bytes:
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"File too large ({size} bytes). Max allowed is {max_bytes} bytes.")
    return path.read_bytes()


async def run_client(cfg: ClientConfig) -> int:
    _warn_config(cfg)

    try:
        _reader, writer = await connect(cfg)
    except Exception as e:
        print(str(e))
        return 2

    try:
        name = await ainput("Enter your name: ")
        try:
            await _send_hello(
                writer,
                name=name,
                token=cfg.token,
                legacy_name_line=cfg.legacy_name_line,
                framed_hello=cfg.framed_hello,
            )
        except (OSError, ConnectionError) as e:
            print(f"Connection error while sending hello: {e}")
            return 3

        while True:
            print("\n1) Send location")
            print("2) Send status")
            print("3) Send image")
            print("4) Exit")

            choice = (await ainput("> ")).strip()

            if choice == "1":
                loc = await ainput("Enter your location: ")
                try:
                    await send_msg(
                        writer,
                        {
                            "type": "location",
                            "timestamp": _now_ts(),
                            "payload": {"description": loc.strip()},
                        },
                        token=cfg.token,
                    )
                except (OSError, ConnectionError) as e:
                    print(f"Connection error while sending location: {e}")
                    return 3
                print("Location sent.")

            elif choice == "2":
                print("\nYour status:")
                for key, label in STATUS_OPTIONS.items():
                    print(f"  {key}) {label}")

                status_choice = (await ainput("> ")).strip()
                if status_choice not in STATUS_OPTIONS:
                    print("Invalid choice, status not sent.")
                    continue

                status_label = STATUS_OPTIONS[status_choice]
                extra = (await ainput("Extra details (or press Enter to skip): ")).strip()

                try:
                    await send_msg(
                        writer,
                        {
                            "type": "status",
                            "timestamp": _now_ts(),
                            "payload": {
                                "code": status_choice,
                                "condition": status_label,
                                "details": extra if extra else None,
                            },
                        },
                        token=cfg.token,
                    )
                except (OSError, ConnectionError) as e:
                    print(f"Connection error while sending status: {e}")
                    return 3
                print(f"Status sent: {status_label}")

            elif choice == "3":
                raw_path = (await ainput("Image path: ")).strip().strip('"')
                path = Path(os.path.expanduser(raw_path))
                if not path.exists():
                    print(f"File not found: {path}")
                    print("Tip: On Windows: C:\\Users\\YourName\\Downloads\\photo.jpg")
                    print("     On Mac/Linux: ~/Downloads/photo.jpg")
                    continue

                try:
                    data = _read_file_bytes(path, max_bytes=cfg.max_image_bytes)
                except Exception as e:
                    print(f"Cannot read image: {e}")
                    continue

                print("Sending image, please wait...")
                encoded = base64.b64encode(data).decode("ascii")
                ext = path.suffix or ".jpg"

                try:
                    await send_msg(
                        writer,
                        {
                            "type": "image",
                            "timestamp": _now_ts(),
                            "payload": {
                                "data": encoded,
                                "filename": path.name,
                                "ext": ext,
                                "bytes": len(data),
                            },
                        },
                        token=cfg.token,
                    )
                except (OSError, ConnectionError) as e:
                    print(f"Connection error while sending image: {e}")
                    return 3
                print(f"Image sent: {path.name}")

            elif choice == "4":
                print("Exiting...")
                return 0

            else:
                print("Invalid choice, try again.")

    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.")
        return 130
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def parse_args(argv: list[str] | None = None) -> ClientConfig:
    p = argparse.ArgumentParser(description="SAGA civilian client")

    p.add_argument("--host", default=os.getenv("SAGA_SERVER_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.getenv("SAGA_SERVER_PORT", "5050")))
    p.add_argument("--connect-timeout", type=float, default=5.0, dest="connect_timeout_s")
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--retry-backoff", type=float, default=0.5, dest="retry_backoff_s")

    p.add_argument("--token", default=os.getenv("SAGA_TOKEN"))

    p.add_argument("--tls", action="store_true", help="Use TLS (server must support it)")
    p.add_argument("--cafile", default=os.getenv("SAGA_TLS_CAFILE"))
    p.add_argument("--tls-insecure", action="store_true", help="Disable TLS verification (not recommended)")

    p.add_argument("--max-image-bytes", type=int, default=2 * 1024 * 1024)

    p.add_argument(
        "--legacy-name-line",
        dest="legacy_name_line",
        action="store_true",
        default=True,
        help="Send initial name as a newline-terminated line (default on)",
    )
    p.add_argument(
        "--no-legacy-name-line",
        dest="legacy_name_line",
        action="store_false",
        help="Do not send a newline-terminated name line (requires server support)",
    )
    p.add_argument(
        "--framed-hello",
        action="store_true",
        default=False,
        help="Also send a framed hello message (requires server support)",
    )

    ns = p.parse_args(argv)

    if ns.port <= 0 or ns.port > 65535:
        raise SystemExit("Invalid --port; must be in 1..65535")

    if ns.max_image_bytes <= 0:
        raise SystemExit("Invalid --max-image-bytes; must be > 0")

    return ClientConfig(
        host=str(ns.host),
        port=int(ns.port),
        connect_timeout_s=float(ns.connect_timeout_s),
        retries=int(ns.retries),
        retry_backoff_s=float(ns.retry_backoff_s),
        token=str(ns.token) if ns.token else None,
        tls=bool(ns.tls),
        cafile=str(ns.cafile) if ns.cafile else None,
        tls_insecure=bool(ns.tls_insecure),
        max_image_bytes=int(ns.max_image_bytes),
        legacy_name_line=bool(ns.legacy_name_line),
        framed_hello=bool(ns.framed_hello),
    )


def main() -> int:
    cfg = parse_args()
    return asyncio.run(run_client(cfg))


if __name__ == "__main__":
    raise SystemExit(main())
