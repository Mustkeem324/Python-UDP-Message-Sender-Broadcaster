# UDP Broadcaster / Sender

A simple Python script to send UDP messages to a specific IP address or network broadcast. Supports retries, custom ports, and messages with spaces or special characters.

---

## Features

- Send UDP messages to a single target IP or hostname.
- Broadcast messages to a network (e.g., `192.168.1.255`).
- Supports custom UDP ports.
- Supports multiple send attempts (retries).
- Handles messages with spaces and quotes.
- Resolves hostnames automatically if an IP is not provided.

---

## Requirements

- Python 3.x
- Works on Windows, macOS, and Linux

No external dependencies required.

---

## Usage

```bash
# Send a simple message to a specific IP
python broadcaster_fixed.py 192.168.1.23 "Hi there!"

# Send a broadcast message to the network
python broadcaster_fixed.py 192.168.1.255 --broadcast "Hello everyone"

# Send a message with spaces and quotes to a custom port
python broadcaster_fixed.py 192.168.1.23 "Message with spaces and 'quotes'" --port 50000

# Send a message with retries
python broadcaster_fixed.py 192.168.1.23 "Retry this message" --retries 3
````

---

## Arguments

| Argument      | Description                                                                |
| ------------- | -------------------------------------------------------------------------- |
| `target`      | Target IP address or hostname. Can be a broadcast address if `--broadcast` |
| `message`     | Message to send. Supports spaces and quotes                                |
| `--port`      | Destination UDP port (default: `50000`)                                    |
| `--broadcast` | Enable UDP broadcast socket option                                         |
| `--retries`   | Number of send attempts (default: 1)                                       |

---

## Example Output

```text
[1] Sent to 192.168.1.23:50000
```

If the target hostname cannot be resolved:

```text
Warning: 'example.local' does not look like a valid IPv4 address. Attempting to resolve hostname...
Resolved to 192.168.1.42
[1] Sent to 192.168.1.42:50000
```

---

## Notes

* Broadcast messages may not work on all networks due to router/firewall restrictions.
* Running the script on restricted networks may require administrative privileges.
* Timeout for each send attempt is set to 2 seconds by default.

---

## License

MIT License



