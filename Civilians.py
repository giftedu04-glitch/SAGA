import asyncio
import json
import base64
from datetime import datetime
import os
import logging
import sys

LOG_LEVEL = logging.DEBUG
LOG_FILE = "civilian_client.log"

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("CivilianClient")

SERVER_IP = "172.20.10.3"   # 🔑 LAN IP OF SERVER COMPUTER
SERVER_PORT = 4              # Must match server

STATUS_OPTIONS = {
    "1": "OK, need directions out",
    "2": "Injured, can move",
    "3": "Injured, cannot move",
    "4": "Others with me need help",
    "5": "Medical emergency",
}


async def ainput(prompt: str) -> str:
    """Non-blocking input() — runs in a thread so the event loop stays free."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: input(prompt))


async def send_msg(writer, msg):
    data = json.dumps(msg).encode()
    writer.write(len(data).to_bytes(4, "big") + data)
    await writer.drain()


async def main():
    # ── Connect to server ────────────────────────────────────────────────────
    try:
        reader, writer = await asyncio.open_connection(SERVER_IP, SERVER_PORT)
        logger.info(f"Connected to server {SERVER_IP}:{SERVER_PORT}")
    except Exception as e:
        logger.error(f"Failed to connect to server: {e}")
        print(f"Cannot connect to server: {e}")
        return

    # ── Send name with \n so server's readuntil(b"\n") completes cleanly ────
    name = await ainput("Enter your name: ")
    writer.write((name.strip() + "\n").encode())
    await writer.drain()
    logger.info(f"Registered with name: {name.strip()}")

    # ── Menu loop ────────────────────────────────────────────────────────────
    while True:
        print("\n1) Send location")
        print("2) Send status")
        print("3) Send image")
        print("4) Exit")
        choice = (await ainput("> ")).strip()

        if choice == "1":
            loc = await ainput("Enter your location: ")
            await send_msg(writer, {
                "type": "location",
                "timestamp": datetime.now().timestamp(),
                "payload": {"description": loc.strip()},
            })
            logger.info(f"Location sent: {loc.strip()}")
            print("Location sent.")

        elif choice == "2":
            # ── Option C: preset choices + optional free text ────────────────
            print("\nYour status:")
            for key, label in STATUS_OPTIONS.items():
                print(f"  {key}) {label}")

            status_choice = (await ainput("> ")).strip()

            if status_choice not in STATUS_OPTIONS:
                logger.warning(f"Invalid status choice: {status_choice}")
                print("Invalid choice, status not sent.")
                continue

            status_label = STATUS_OPTIONS[status_choice]
            extra = (await ainput("Extra details (or press Enter to skip): ")).strip()

            await send_msg(writer, {
                "type": "status",
                "timestamp": datetime.now().timestamp(),
                "payload": {
                    "code": status_choice,
                    "condition": status_label,
                    "details": extra if extra else None,
                },
            })
            logger.info(f"Status sent: [{status_choice}] {status_label} | Details: {extra if extra else 'None'}")
            print(f"Status sent: {status_label}")

        elif choice == "3":
            raw_path = (await ainput("Image path: ")).strip()
            path = os.path.expanduser(raw_path)
            if not os.path.exists(path):
                logger.warning(f"File not found: {path}")
                print(f"File not found: {path}")
                print("Tip: On Windows: C:\\Users\\YourName\\Downloads\\photo.jpg")
                print("     On Mac/Linux: ~/Downloads/photo.jpg")
                continue
            logger.info(f"Sending image: {os.path.basename(path)}")
            print("Sending image, please wait...")
            with open(path, "rb") as f:
                encoded = base64.b64encode(f.read()).decode()
            ext = os.path.splitext(path)[1] or ".jpg"
            await send_msg(writer, {
                "type": "image",
                "timestamp": datetime.now().timestamp(),
                "payload": {"data": encoded, "filename": os.path.basename(path), "ext": ext},
            })
            logger.info(f"Image sent successfully: {os.path.basename(path)}")
            print(f"Image sent: {os.path.basename(path)}")

        elif choice == "4":
            logger.info("User exited the application")
            print("Exiting...")
            break

        else:
            logger.warning(f"Invalid menu choice: {choice}")
            print("Invalid choice, try again.")

    writer.close()
    await writer.wait_closed()
    logger.info("Connection closed")


if __name__ == "__main__":
    asyncio.run(main())