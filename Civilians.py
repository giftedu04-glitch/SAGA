import asyncio
import json
import base64
from datetime import datetime
import os

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
    except Exception as e:
        print(f"Cannot connect to server: {e}")
        return

    # ── Send name with \n so server's readuntil(b"\n") completes cleanly ────
    name = await ainput("Enter your name: ")
    writer.write((name.strip() + "\n").encode())
    await writer.drain()

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
            print("Location sent.")

        elif choice == "2":
            # ── Option C: preset choices + optional free text ────────────────
            print("\nYour status:")
            for key, label in STATUS_OPTIONS.items():
                print(f"  {key}) {label}")

            status_choice = (await ainput("> ")).strip()

            if status_choice not in STATUS_OPTIONS:
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
            print(f"Status sent: {status_label}")

        elif choice == "3":
            raw_path = (await ainput("Image path: ")).strip()
            path = os.path.expanduser(raw_path)
            if not os.path.exists(path):
                print(f"File not found: {path}")
                print("Tip: On Windows: C:\\Users\\YourName\\Downloads\\photo.jpg")
                print("     On Mac/Linux: ~/Downloads/photo.jpg")
                continue
            print("Sending image, please wait...")
            with open(path, "rb") as f:
                encoded = base64.b64encode(f.read()).decode()
            ext = os.path.splitext(path)[1] or ".jpg"
            await send_msg(writer, {
                "type": "image",
                "timestamp": datetime.now().timestamp(),
                "payload": {"data": encoded, "filename": os.path.basename(path), "ext": ext},
            })
            print(f"Image sent: {os.path.basename(path)}")

        elif choice == "4":
            print("Exiting...")
            break

        else:
            print("Invalid choice, try again.")

    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())