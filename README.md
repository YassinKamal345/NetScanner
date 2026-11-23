# 📡 NetScanner

A simple **TCP host and port scanner** in a single Python file. It discovers live hosts on a
network range and scans each one for open TCP ports — using plain sockets only: no root, no
raw packets, and no third-party libraries.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Cross--platform-555?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> ⚠️ **Authorized use only.** Scan only hosts and networks that you own or have explicit
> written permission to test. Port scanning systems without authorization may be illegal in
> your jurisdiction. The author takes no responsibility for misuse.

## Usage

```bash
# Discover live hosts on a subnet
python netscanner.py 192.168.1.0/24

# Scan a port range on one host
python netscanner.py 192.168.1.10 -p 1-1024

# Scan specific ports on a hostname
python netscanner.py myserver.local -p 22,80,443

# Discover hosts AND scan a port set on each one
python netscanner.py 192.168.1.0/24 -p 22,80,443
```

Options:

| Flag | Meaning | Default |
|------|---------|---------|
| `-p, --ports` | Ports to scan (`22,80` or `1-1024`) | discovery only for a subnet |
| `-t, --timeout` | Per-connection timeout (seconds) | `0.5` |
| `-w, --workers` | Max concurrent connections | `100` |

## How it works

- **Targets** can be a single IP, a CIDR network (`192.168.1.0/24`) or a hostname — parsed
  with Python's `ipaddress` module and resolved with `socket`.
- **Host discovery** tries a handful of common ports (22, 80, 445, 3389, …) and marks a host
  as *up* if any of them answer.
- **Port scanning** uses a thread pool of non-blocking `connect_ex` calls, and names services
  via `socket.getservbyport`.

Everything is concurrent, so a /24 discovery or a 1–1024 scan finishes in seconds on a LAN.

## Example

```
Scanning 192.168.1.10 (1024 ports) ...
     22/tcp  open  ssh
     80/tcp  open  http
    443/tcp  open  https
```

## License

MIT - see [LICENSE](LICENSE). Author: **Yassin Kamal** ·
[Portfolio](https://portfolio-sand-eight-20.vercel.app) ·
[LinkedIn](https://www.linkedin.com/in/yassin-kamal-simo/)
