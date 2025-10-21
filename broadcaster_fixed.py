#!/usr/bin/env python3
# broadcaster_fixed.py
# Usage examples:
#  python broadcaster_fixed.py 192.168.1.23 "Hi there!"
#  python broadcaster_fixed.py 192.168.1.255 --broadcast "Hello everyone"
#  python broadcaster_fixed.py 192.168.1.23 "Message with spaces and 'quotes'" --port 50000

import sys
import socket
import argparse
import time

DEFAULT_PORT = 50000
TIMEOUT = 2.0

def parse_args():
    p = argparse.ArgumentParser(description="Simple UDP broadcaster/sender")
    p.add_argument("target", help="Target IP (or broadcast address). If --broadcast, can be network broadcast like 192.168.1.255")
    p.add_argument("message", nargs='+', help="Message to send (support spaces)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Destination UDP port (default {DEFAULT_PORT})")
    p.add_argument("--broadcast", action="store_true", help="Enable UDP broadcast socket option")
    p.add_argument("--retries", type=int, default=1, help="Number of send attempts (default 1)")
    return p.parse_args()

def is_valid_ip(addr):
    try:
        socket.inet_aton(addr)
        return True
    except Exception:
        return False

def main():
    args = parse_args()
    target = args.target
    message = " ".join(args.message)
    port = args.port

    if not is_valid_ip(target):
        print(f"Warning: '{target}' does not look like a valid IPv4 address. Attempting to resolve hostname...")
        try:
            target = socket.gethostbyname(target)
            print(f"Resolved to {target}")
        except Exception as e:
            print("Failed to resolve target:", e)
            sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    if args.broadcast:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception as e:
            print("Failed to enable broadcast option:", e)
            # continue - might still work for some routers

    success = False
    for attempt in range(1, max(1, args.retries) + 1):
        try:
            sock.sendto(message.encode('utf-8'), (target, port))
            print(f"[{attempt}] Sent to {target}:{port}")
            success = True
            break
        except Exception as e:
            print(f"[{attempt}] Send failed:", e)
            time.sleep(0.2)

    sock.close()
    if not success:
        print("All attempts failed.")
        sys.exit(2)

if __name__ == "__main__":
    main()
