"""
server_app.py  —  Rescue Server Dashboard
Run with: python server_app.py
Requires: Python 3.8+ (tkinter is built-in)
"""

import asyncio
import threading
import json
import base64
import socket
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ── Constants ─────────────────────────────────────────────────────────────────
SERVER_PORT        = 5006
BROADCAST_PORT     = 5005
BROADCAST_INTERVAL = 2
IMAGE_DIR          = "received_images"
os.makedirs(IMAGE_DIR, exist_ok=True)

connected_clients = {}   # name -> writer
loop_ref          = [None]

# ── Network helpers ───────────────────────────────────────────────────────────

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def broadcast_presence(lan_ip, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = json.dumps({
        "type": "rescue_server",
        "ip": lan_ip,
        "port": SERVER_PORT,
    }).encode()
    while not stop_event.is_set():
        try:
            sock.sendto(message, ("<broadcast>", BROADCAST_PORT))
        except Exception:
            pass
        stop_event.wait(BROADCAST_INTERVAL)
    sock.close()


async def send_msg(writer, msg):
    data = json.dumps(msg).encode()
    writer.write(len(data).to_bytes(4, "big") + data)
    await writer.drain()

# ── Main App ──────────────────────────────────────────────────────────────────

class ServerApp:
    def __init__(self, root):
        self.root   = root
        self.root.title("🚨 Rescue — Server Dashboard")
        self.root.geometry("860x680")
        self.root.configure(bg="#0d1117")

        self.stop_event = threading.Event()
        self.lan_ip     = get_lan_ip()

        self._build_ui()
        self._start_server()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        BG     = "#0d1117"
        PANEL  = "#161b22"
        BORDER = "#30363d"
        ACCENT = "#238636"
        RED    = "#da3633"
        BLUE   = "#1f6feb"
        TEXT   = "#c9d1d9"
        MUTED  = "#8b949e"
        FONT   = ("Segoe UI", 10)
        FONT_B = ("Segoe UI", 10, "bold")

        self.colors = dict(bg=BG, panel=PANEL, accent=ACCENT,
                           red=RED, blue=BLUE, text=TEXT, muted=MUTED)

        # ── Top bar ───────────────────────────────────────────────────────────
        top = tk.Frame(self.root, bg=RED, pady=10)
        top.pack(fill="x")
        tk.Label(top, text="🚨  RESCUE SERVER DASHBOARD",
                 font=("Segoe UI", 14, "bold"),
                 bg=RED, fg="white").pack(side="left", padx=16)
        self.ip_label = tk.Label(top,
            text=f"LAN: {self.lan_ip}  |  Port: {SERVER_PORT}",
            font=("Segoe UI", 9), bg=RED, fg="#ffcdd2")
        self.ip_label.pack(side="right", padx=16)

        # ── Status strip ──────────────────────────────────────────────────────
        self.status_bar = tk.Label(self.root,
            text="  ⬤  Starting server...",
            font=("Segoe UI", 9), bg=PANEL, fg=MUTED,
            anchor="w", pady=5)
        self.status_bar.pack(fill="x")

        # ── Main layout (left: civilian list | right: message feed) ───────────
        main = tk.Frame(self.root, bg=BG)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        # Left panel — connected civilians
        left = tk.Frame(main, bg=PANEL, width=200, relief="flat",
                        highlightthickness=1, highlightbackground=BORDER)
        left.pack(side="left", fill="y", padx=(0,8))
        left.pack_propagate(False)

        tk.Label(left, text="Connected Civilians",
                 font=FONT_B, bg=PANEL, fg=TEXT,
                 pady=10).pack(fill="x", padx=10)

        tk.Frame(left, bg=BORDER, height=1).pack(fill="x")

        self.civilian_list = tk.Listbox(left,
            font=("Segoe UI", 10), bg=PANEL, fg=TEXT,
            selectbackground=BLUE, selectforeground="white",
            relief="flat", bd=0, highlightthickness=0,
            activestyle="none")
        self.civilian_list.pack(fill="both", expand=True, padx=4, pady=4)

        self.count_label = tk.Label(left,
            text="0 online", font=("Segoe UI", 8),
            bg=PANEL, fg=MUTED, pady=4)
        self.count_label.pack()

        # Right panel — message feed + reply bar
        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        # Message feed
        feed_frame = tk.Frame(right, bg=PANEL,
                              highlightthickness=1, highlightbackground=BORDER)
        feed_frame.pack(fill="both", expand=True)

        tk.Label(feed_frame, text="  Incoming Messages",
                 font=FONT_B, bg=PANEL, fg=TEXT,
                 pady=8, anchor="w").pack(fill="x")
        tk.Frame(feed_frame, bg=BORDER, height=1).pack(fill="x")

        self.feed = scrolledtext.ScrolledText(feed_frame,
            font=("Consolas", 9), bg="#0d1117", fg=TEXT,
            insertbackground=TEXT, relief="flat", bd=0,
            state="disabled", wrap="word")
        self.feed.pack(fill="both", expand=True, padx=6, pady=6)

        # Tag colours
        self.feed.tag_config("location", foreground="#58a6ff")
        self.feed.tag_config("status_ok",  foreground="#3fb950")
        self.feed.tag_config("status_warn", foreground="#d29922")
        self.feed.tag_config("status_bad",  foreground="#f85149")
        self.feed.tag_config("image",    foreground="#bc8cff")
        self.feed.tag_config("answer",   foreground="#79c0ff")
        self.feed.tag_config("system",   foreground=MUTED)
        self.feed.tag_config("sent",     foreground="#3fb950")
        self.feed.tag_config("header",   foreground="white")

        # ── Reply bar ─────────────────────────────────────────────────────────
        reply_frame = tk.Frame(right, bg=PANEL, pady=10, padx=10,
                               highlightthickness=1, highlightbackground=BORDER)
        reply_frame.pack(fill="x", pady=(8,0))

        top_row = tk.Frame(reply_frame, bg=PANEL)
        top_row.pack(fill="x", pady=(0,6))

        tk.Label(top_row, text="To:", font=FONT_B, bg=PANEL, fg=TEXT
                 ).pack(side="left", padx=(0,6))

        self.target_var = tk.StringVar()
        self.target_entry = tk.Entry(top_row, textvariable=self.target_var,
            font=FONT, bg="#0d1117", fg=TEXT,
            insertbackground=TEXT, relief="flat", bd=0,
            highlightthickness=1, highlightbackground=BORDER,
            width=16)
        self.target_entry.pack(side="left", ipady=5, padx=(0,10))

        self.msg_type_var = tk.StringVar(value="reply")
        tk.Radiobutton(top_row, text="Reply",
                       variable=self.msg_type_var, value="reply",
                       font=FONT, bg=PANEL, fg=TEXT,
                       selectcolor=PANEL, activebackground=PANEL,
                       activeforeground=TEXT
                       ).pack(side="left", padx=4)
        tk.Radiobutton(top_row, text="Question",
                       variable=self.msg_type_var, value="question",
                       font=FONT, bg=PANEL, fg=TEXT,
                       selectcolor=PANEL, activebackground=PANEL,
                       activeforeground=TEXT
                       ).pack(side="left", padx=4)

        bottom_row = tk.Frame(reply_frame, bg=PANEL)
        bottom_row.pack(fill="x")

        self.reply_var = tk.StringVar()
        reply_entry = tk.Entry(bottom_row, textvariable=self.reply_var,
            font=("Segoe UI", 11), bg="#0d1117", fg=TEXT,
            insertbackground=TEXT, relief="flat", bd=0,
            highlightthickness=1, highlightbackground=BORDER)
        reply_entry.pack(side="left", fill="x", expand=True, ipady=7, padx=(0,8))
        reply_entry.bind("<Return>", lambda e: self._send_reply())

        tk.Button(bottom_row, text="Send ▶",
                  font=FONT_B, bg=ACCENT, fg="white",
                  activebackground="#2ea043",
                  relief="flat", bd=0, cursor="hand2",
                  padx=16, pady=7,
                  command=self._send_reply
                  ).pack(side="right")

        # Click civilian list to auto-fill "To:" field
        self.civilian_list.bind("<<ListboxSelect>>", self._on_civilian_select)

        # Hint label
        tk.Label(reply_frame,
                 text="💡 Click a civilian name on the left to select them, then type and press Send",
                 font=("Segoe UI", 8), bg=PANEL, fg=MUTED
                 ).pack(anchor="w", pady=(6,0))

    # ── Server startup ────────────────────────────────────────────────────────

    def _start_server(self):
        threading.Thread(
            target=broadcast_presence,
            args=(self.lan_ip, self.stop_event),
            daemon=True
        ).start()

        server_thread = threading.Thread(target=self._run_server, daemon=True)
        server_thread.start()

    def _run_server(self):
        loop = asyncio.new_event_loop()
        loop_ref[0] = loop
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._async_server())

    async def _async_server(self):
        server = await asyncio.start_server(
            self._handle_client, host="0.0.0.0", port=SERVER_PORT)
        self.root.after(0, lambda: self._set_status(
            f"⬤  Server running on {self.lan_ip}:{SERVER_PORT}  |  "
            f"Broadcasting for auto-connect", "#3fb950"))
        self._log(f"Server started. LAN IP: {self.lan_ip}  Port: {SERVER_PORT}", "system")
        async with server:
            await server.serve_forever()

    # ── Client handler ────────────────────────────────────────────────────────

    async def _handle_client(self, reader, writer):
        addr = writer.get_extra_info("peername")
        name = "unknown"

        try:
            try:
                name_bytes = await asyncio.wait_for(
                    reader.readuntil(b"\n"), timeout=10)
                name = name_bytes.decode().strip()
            except asyncio.LimitOverrunError:
                name_bytes = await reader.read(100)
                name = name_bytes.decode().strip()
            except asyncio.TimeoutError:
                writer.close()
                await writer.wait_closed()
                return

            connected_clients[name] = writer
            self.root.after(0, lambda n=name: self._on_client_join(n))

            while True:
                try:
                    length_bytes = await reader.readexactly(4)
                    length       = int.from_bytes(length_bytes, "big")
                    data_bytes   = await reader.readexactly(length)
                    msg          = json.loads(data_bytes.decode())
                    self.root.after(0, lambda m=msg, n=name: self._on_message(n, m))

                except asyncio.IncompleteReadError:
                    break
                except json.JSONDecodeError:
                    continue

        except Exception as e:
            self.root.after(0, lambda: self._log(f"Error with {name}: {e}", "system"))
        finally:
            connected_clients.pop(name, None)
            self.root.after(0, lambda n=name: self._on_client_leave(n))
            writer.close()
            await writer.wait_closed()

    # ── Client events ─────────────────────────────────────────────────────────

    def _on_client_join(self, name):
        self.civilian_list.insert("end", f"  {name}")
        self._update_count()
        self._log(f"✅ {name} connected from LAN", "system")

    def _on_client_leave(self, name):
        items = self.civilian_list.get(0, "end")
        for i, item in enumerate(items):
            if item.strip() == name:
                self.civilian_list.delete(i)
                break
        self._update_count()
        self._log(f"🔌 {name} disconnected", "system")

    def _on_civilian_select(self, event):
        sel = self.civilian_list.curselection()
        if sel:
            name = self.civilian_list.get(sel[0]).strip()
            self.target_var.set(name)

    def _update_count(self):
        n = len(connected_clients)
        self.count_label.config(text=f"{n} online")

    # ── Incoming messages ─────────────────────────────────────────────────────

    def _on_message(self, name, msg):
        msg_type  = msg.get("type")
        payload   = msg.get("payload", {})
        timestamp = datetime.fromtimestamp(
            msg.get("timestamp", datetime.now().timestamp())
        ).strftime("%H:%M:%S")

        self._log(f"━━━  {name}  [{timestamp}]  ━━━", "header")

        if msg_type == "location":
            desc = payload.get("description", "")
            self._log(f"  📍 LOCATION: {desc}", "location")

        elif msg_type == "status":
            code      = payload.get("code", "?")
            condition = payload.get("condition", "")
            details   = payload.get("details")
            icons     = {"1":"🟢","2":"🟡","3":"🟠","4":"🟠","5":"🔴"}
            icon      = icons.get(code, "⚪")
            tag = "status_ok" if code == "1" else \
                  "status_warn" if code in ("2","3","4") else "status_bad"
            self._log(f"  {icon} STATUS: {condition}", tag)
            if details:
                self._log(f"     Details: {details}", tag)

        elif msg_type == "image":
            original = payload.get("filename", "unknown")
            ext      = payload.get("ext", ".jpg")
            try:
                image_data = base64.b64decode(payload["data"])
                filename   = f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
                path       = os.path.join(IMAGE_DIR, filename)
                with open(path, "wb") as f:
                    f.write(image_data)
                self._log(f"  🖼  IMAGE received: {original}", "image")
                self._log(f"     Saved → {path}", "image")
            except Exception as e:
                self._log(f"  ❌ Image save error: {e}", "system")

        elif msg_type == "answer":
            answer = payload.get("answer", "")
            self._log(f"  💬 ANSWER: {answer}", "answer")

        else:
            self._log(f"  ⚠️  Unknown type: {msg_type}", "system")

        # Auto-fill the "To:" field with the sender
        self.target_var.set(name)

    # ── Send reply ────────────────────────────────────────────────────────────

    def _send_reply(self):
        target  = self.target_var.get().strip()
        message = self.reply_var.get().strip()
        mtype   = self.msg_type_var.get()

        if not target:
            messagebox.showwarning("No target", "Select or type a civilian name in the 'To:' field.")
            return
        if not message:
            return
        if target not in connected_clients:
            messagebox.showerror("Not connected",
                f"'{target}' is not connected. Check /list for online civilians.")
            return

        if mtype == "reply":
            msg = {"type": "reply", "timestamp": datetime.now().timestamp(),
                   "payload": {"message": message}}
            label = f"  ✅ Reply sent to {target}: {message}"
        else:
            msg = {"type": "question", "timestamp": datetime.now().timestamp(),
                   "payload": {"question": message}}
            label = f"  ❓ Question sent to {target}: {message}"

        loop = loop_ref[0]
        if loop:
            asyncio.run_coroutine_threadsafe(
                send_msg(connected_clients[target], msg), loop)
        self._log(label, "sent")
        self.reply_var.set("")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _set_status(self, text, colour):
        self.status_bar.config(text=f"  {text}", fg=colour)

    def _log(self, text, tag="system"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.feed.config(state="normal")
        if tag == "header":
            self.feed.insert("end", f"\n{text}\n", tag)
        else:
            self.feed.insert("end", f"  {text}\n", tag)
        self.feed.see("end")
        self.feed.config(state="disabled")

    def on_close(self):
        self.stop_event.set()
        self.root.destroy()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app  = ServerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
