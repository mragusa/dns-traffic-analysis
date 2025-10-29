# dns‑traffic‑analysis

[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)  
[![License: BSD‑2‑Clause](https://img.shields.io/badge/License-BSD%202%20Clause-green.svg)](LICENSE)  
[![Status](https://img.shields.io/badge/status-active-success.svg)]()  
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)](https://github.com/mragusa/dns-traffic-analysis/issues)

> Tools for analyzing PCAP files to identify DNS queries with high latency.

---

## 🧭 Overview

When clients report slow DNS resolution or intermittent lookup failures, diving into packet captures can be time‑consuming.  
**dns‑traffic‑analysis** provides command‑line utilities to parse PCAPs, pinpoint slow DNS queries, extract relevant packets, and accelerate root‑cause investigations.

Key capabilities:

- Identify DNS servers, clients, and query volume via PCAP inspection  
- Detect DNS queries whose latency exceeds a configurable threshold  
- Extract individual DNS query/response flows for in‑depth review  
- Parse and display raw DNS packet fields for forensic detail  

---

## ✨ Features

- 🕵️ Identify DNS servers and clients from large PCAPs  
- 🕒 Flag and list DNS queries slower than a user‑specified latency (default: 0.5 s)  
- 🔍 Extract query/response pairs into separate PCAPs for Wireshark review  
- 📦 Display DNS packet contents (headers, flags, questions, answers)  
- 🧰 Lightweight, Python‑based, usable out‑of‑the‑box with minimal dependencies  

---

## 🗂️ Project Structure

```
dns‑traffic‑analysis/
├── src/
│   ├── find‑dns‑server.py        # Identify DNS servers and clients in PCAP
│   ├── traffic‑analysis.py       # Detect slow DNS queries by latency threshold
│   ├── dns‑splitter.py           # Extract PCAP of a single query/response pair
│   └── dns‑packet‑parser.py      # Parse and print DNS packet fields
├── pyproject.toml                # (or requirements.txt) for dependencies
├── requirements.txt
├── LICENSE
└── README.md                     # This file
```

---

## ⚙️ Installation

### Requirements

- Python **3.8+**  
- A traffic capture file (.pcap) containing DNS lookup traffic (e.g., collected via `tcpdump`)  
- Packages: `scapy`, `tqdm` (as used in the tools)  

### Install

```bash
git clone https://github.com/mragusa/dns-traffic-analysis.git
cd dns-traffic-analysis
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Usage

### find‑dns‑server.py  
Determine DNS servers, recursive servers and clients from a PCAP.

```bash
python src/find‑dns‑server.py -f traffic.pcap
```

**Example:**
```bash
python src/find‑dns‑server.py -f last_hour.pcap -d --focus servers -c 10
```

### traffic‑analysis.py  
Detect DNS queries slower than a threshold (default 0.5 s).  
Generates:  
- `query_traffic_count.txt` (summary of all queries)  
- `slow_queries.txt` (each slow query: name, query ID, latency)

```bash
python src/traffic‑analysis.py -f traffic.pcap -s 10.249.12.135 -t 0.5
```

### dns‑splitter.py  
Extract a specific query/response pair into a new PCAP for detailed review (e.g., open in Wireshark).

```bash
python src/dns‑splitter.py -p traffic.pcap -d 7368
```

### dns‑packet‑parser.py  
Parse a PCAP and print detailed DNS packet fields to stdout.

```bash
python src/dns‑packet‑parser.py -f some_capture.pcap
```

---

## 🧠 Tips & Best Practices

- For very large PCAPs (>100 MB), consider splitting into smaller files before analysis:  
  ```bash
  tcpdump -r traffic.cap -w split.cap -C 100
  ```
- Use a latency threshold appropriate to your network environment (e.g., 1 s for high‑latency links).  
- When using `dns‑splitter`, open the resulting PCAP in Wireshark with a display filter like `dns.id == <query_id>` to isolate the exact query/response.  
- Store PCAPs and logs securely—they may contain sensitive DNS traffic data.

---

## 🤝 Contributing

Contributions and feedback are welcome!

To contribute:

1. Fork this repository  
2. Create a new branch (`git checkout -b feature/xyz`)  
3. Add tests or usage examples where appropriate  
4. Submit a pull request  

Please adhere to Python style best practices (e.g., black, flake8) and update this README if you add new scripts or options.

---

## 📜 License

This project is licensed under the [BSD‑2‑Clause License](LICENSE).

---

## 📚 References

- [Scapy](https://scapy.net) — packet manipulation library used for PCAP parsing  
- [Tqdm](https://github.com/tqdm/tqdm) — progress bar support  
- [Tcpdump](https://www.tcpdump.org) — for capturing PCAP files  
- [Wireshark](https://www.wireshark.org) — for detailed packet inspection  

---

## 💬 Support & Issues

If you encounter a bug or have a feature request, please [open an issue](https://github.com/mragusa/dns-traffic-analysis/issues).  
For enterprise use cases or integration into workflows, feel free to contact or propose extended functionality.

> _Maintained by [Mike Ragusa](https://github.com/mragusa)_
