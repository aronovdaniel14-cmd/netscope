# NETSCOPE

A terminal tool for scanning your local network — finds devices (phones, TVs, routers, IoT, laptops), their IPs/MACs/vendors, and open ports. Pure Python standard library, no dependencies, no root required.

> ⚠️ Only scan networks you own or have explicit permission to scan.

## Requirements

- Python 3.7+
- That's it — no `pip install` needed.

## Setup

```bash
git clone https://github.com/aronovdaniel14-cmd/netscope.git
cd netscope
```

## Usage

### macOS

Python 3 is usually preinstalled. If not: `brew install python3`.

```bash
python3 netscope.py
```

### Linux

Most distros ship Python 3. If not:

```bash
# Debian/Ubuntu
sudo apt install python3

# Fedora
sudo dnf install python3

# Arch
sudo pacman -S python
```

Then run:

```bash
python3 netscope.py
```

### Windows

1. Install Python from [python.org/downloads](https://python.org/downloads) (check **"Add Python to PATH"** during install).
2. Open Command Prompt or PowerShell in the repo folder.

```powershell
python netscope.py
```

If `python` isn't recognized, try `py netscope.py` instead.

## Examples

```bash
# Auto-detect your LAN and scan it
python3 netscope.py

# Scan a specific range
python3 netscope.py -r 192.168.1.0/24

# Scan a custom port range instead of the default common-port list
python3 netscope.py -r 192.168.1.0/24 -p 1-1024

# Just discover devices, skip port scanning (faster)
python3 netscope.py --no-ports

# Save results
python3 netscope.py -o scan.json
python3 netscope.py -o scan.csv

# Adjust timeout (increase on slow/large networks)
python3 netscope.py -t 2
```

## Options

| Flag | Description |
|---|---|
| `-r`, `--range` | CIDR range to scan (e.g. `192.168.1.0/24`). Auto-detected if omitted. |
| `-p`, `--ports` | Ports to scan, e.g. `22,80,443` or `1-1024`. Defaults to a common-port list. |
| `--no-ports` | Skip port scanning, just find devices. |
| `-t`, `--timeout` | Timeout per host probe in seconds (default `1.0`). |
| `-o`, `--output` | Save results to `.json` or `.csv`. |
| `--no-banner` | Skip the startup banner. |

## Notes

- Scan time and accuracy scale with your `--timeout` — raise it on flaky Wi-Fi.
- Device-type guesses and vendor lookups are heuristic (based on hostname, MAC OUI prefix, and open ports), not guaranteed.
- Firewalled devices may show as offline or with no open ports even if they're on the network.

## License

MIT — do whatever you want with it.
