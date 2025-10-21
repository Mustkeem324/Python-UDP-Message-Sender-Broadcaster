# lan_popup_client_hacker.py
# Hacker-themed LAN popup client
# Listens for UDP messages on port 50000 and shows stylized popups with typewriter effect.
# Use only on devices you own or have explicit permission to notify.

import socket
import threading
import queue
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkfont
import time
import platform
import sys
import pyperclip  # optional, used for copy-to-clipboard; install with `pip install pyperclip`

# ===== CONFIG =====
LISTEN_PORT = 50000
BUFFER_SIZE = 4096
TYPE_DELAY = 0.015   # seconds between characters when typing
MAX_WINDOW_WIDTH = 760
MAX_WINDOW_HEIGHT = 300
# ==================

msg_queue = queue.Queue()

def safe_beep(root):
    """Try to make a short beep without platform-specific dependencies."""
    try:
        # On Windows this will play default beep
        if platform.system().lower() == "windows":
            import winsound
            winsound.MessageBeep()
        else:
            # use Tk bell as fallback
            root.bell()
    except Exception:
        try:
            root.bell()
        except Exception:
            pass

def create_hacker_popup(root, title_text, message_text):
    """Create a stylized popup window with typewriter text."""
    w = tk.Toplevel(root)
    w.configure(bg="#000000")
    w.wm_title("")  # hide title
    w.resizable(False, False)

    # Center the window relative to root
    root.update_idletasks()
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    width = min(MAX_WINDOW_WIDTH, int(sw * 0.6))
    height = min(MAX_WINDOW_HEIGHT, int(sh * 0.22))
    x = (sw - width) // 2
    y = (sh - height) // 3
    w.geometry(f"{width}x{height}+{x}+{y}")

    # Make borderless look (still allow dragging)
    try:
        w.overrideredirect(True)  # remove native window frame
    except Exception:
        pass

    # Container frame with subtle border
    frame = tk.Frame(w, bg="#071016", bd=2, relief="ridge")
    frame.pack(expand=True, fill="both")

    # Title bar
    title_bar = tk.Frame(frame, bg="#071016")
    title_bar.pack(fill="x", padx=6, pady=(6, 0))

    title_label = tk.Label(title_bar, text=title_text, bg="#071016", fg="#39ff14",
                           font=("Consolas", 12, "bold"))
    title_label.pack(side="left")

    # Close / ACK button
    def on_close():
        try:
            w.destroy()
        except Exception:
            pass

    ack_btn = tk.Button(title_bar, text="ACK", command=on_close,
                        bg="#0b3b0b", fg="#cfeecd", bd=0, padx=10, pady=4,
                        activebackground="#1a631a", font=("Consolas", 10, "bold"))
    ack_btn.pack(side="right", padx=(0,4))

    # Copy button
    def copy_text():
        try:
            pyperclip.copy(message_text)
        except Exception:
            # fallback fallback
            try:
                root.clipboard_clear()
                root.clipboard_append(message_text)
            except Exception:
                pass

    cbtn = tk.Button(title_bar, text="Copy", command=copy_text,
                     bg="#0b2435", fg="#cfeecd", bd=0, padx=8, pady=4,
                     activebackground="#16364a", font=("Consolas", 10))
    cbtn.pack(side="right", padx=(0,6))

    # Make the popup draggable (since we removed titlebar)
    def start_move(event):
        w.x_start = event.x
        w.y_start = event.y
    def stop_move(event):
        w.x_start = None
        w.y_start = None
    def do_move(event):
        dx = event.x - (w.x_start or 0)
        dy = event.y - (w.y_start or 0)
        x = w.winfo_x() + dx
        y = w.winfo_y() + dy
        w.geometry(f"+{x}+{y}")

    title_bar.bind("<ButtonPress-1>", start_move)
    title_bar.bind("<ButtonRelease-1>", stop_move)
    title_bar.bind("<B1-Motion>", do_move)

    # Content area: canvas background with label overlay
    content = tk.Frame(frame, bg="#000000")
    content.pack(expand=True, fill="both", padx=10, pady=8)

    # monospaced font
    mono = ("Consolas", 12) if "Consolas" in tkfont.families() else ("Courier New", 12)

    # text widget (read-only-like)
    txt = tk.Text(content, bg="#000000", fg="#39ff14", bd=0, wrap="word",
                  font=mono, highlightthickness=0)
    txt.pack(expand=True, fill="both")
    txt.configure(state="disabled")

    # small status/footer
    footer = tk.Label(frame, text="LAN Monitor · secure & consensual", bg="#071016", fg="#8ff89b",
                      font=("Consolas", 9))
    footer.pack(fill="x", pady=(0,6))

    # Typewriter animation
    def typewriter(text, delay=TYPE_DELAY):
        txt.configure(state="normal")
        txt.delete("1.0", "end")
        for ch in text:
            txt.insert("end", ch)
            txt.see("end")
            txt.update_idletasks()
            time.sleep(delay)
        txt.configure(state="disabled")

    # show quickly but animate on separate thread to avoid blocking GUI responsiveness
    def animate_and_beep():
        safe_beep(root)
        try:
            typewriter(message_text)
        except Exception:
            # fallback: set text directly
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            txt.insert("end", message_text)
            txt.configure(state="disabled")

    t = threading.Thread(target=animate_and_beep, daemon=True)
    t.start()

    # Auto-close after some time (optional)
    def schedule_auto_close(sec=25):
        root.after(int(sec*1000), on_close)
    schedule_auto_close(30)

    return w

# GUI app runner that handles multiple queued messages
def gui_runner():
    root = tk.Tk()
    root.withdraw()  # hide main root window
    root.after(200, lambda: process_queue(root))
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass

def process_queue(root):
    """Check queue for incoming messages and spawn popups."""
    try:
        while not msg_queue.empty():
            src_ip, message = msg_queue.get_nowait()
            title = f"[{src_ip}] INTRNL"
            # create popup
            create_hacker_popup(root, title, message)
    except Exception:
        pass
    # check again later
    root.after(400, lambda: process_queue(root))

# Network listener thread
def listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # allow reuse; bind to all interfaces
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(('', LISTEN_PORT))
    except Exception as e:
        print("Failed to bind socket:", e)
        return
    print(f"[listener] Hacker-themed popup client listening on UDP port {LISTEN_PORT}...")
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            msg = data.decode('utf-8', errors='replace')
            print(f"[listener] Received from {addr}: {msg}")
            # Put into queue for GUI thread
            msg_queue.put((addr[0], msg))
        except Exception as e:
            print("Listener error:", e)
            break
    sock.close()

# Entrypoint
def main():
    # Start listener thread
    t = threading.Thread(target=listener, daemon=True)
    t.start()

    # Start GUI loop (in main thread)
    try:
        gui_runner()
    except Exception as e:
        print("GUI error:", e)

if __name__ == "__main__":
    # Check optional dependency
    try:
        import pyperclip  # noqa: F401
    except Exception:
        print("Note: `pyperclip` not installed. Copy-to-clipboard will use fallback methods.")
    main()
