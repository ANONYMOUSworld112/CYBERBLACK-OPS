# CYBERBLACK-OPS v2.2.0

Enterprise-grade CEH · OSINT · Pentesting & Steganography Toolkit

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗      █████╗  ██████╗██╗  ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║     ███████║██║     █████╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██║     ██╔══██║██║     ██╔═██╗
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╗██║  ██╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                               CYBERBLACK-OPS v2.2.0
```

CYBERBLACK-OPS is a modular cybersecurity toolkit for reconnaissance, Wi-Fi testing, password attacks, web application testing, exploitation, OSINT, packet analysis, post-exploitation, vulnerability assessment, digital forensics, **and multimedia steganography / covert operations**.

**Warning:** Use only on targets for which you have explicit authorization. Unauthorized testing is illegal and unethical.

---

## Quickstart

### 1. Clone

```bash
git clone https://github.com/ANONYMOUSworld112/CYBERBLACK-OPS.git
cd CYBERBLACK-OPS
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install the package

```bash
pip install -e .
```

### 4. Run CyberBlack or StegoForge

```bash
# Launch CyberBlack-Ops Interactive Console
cyberblack

# Or launch StegoForge directly
stegoforge
```

---

## Features

- **40+ tools across 11 categories** — networking, Wi-Fi, password attacks, web testing, exploitation, OSINT, MITM, post-exploitation, vulnerability assessment, forensics, and **steganography & covert operations**
- **StegoForge Steganography Engine:**
  - Multi-carrier steganography (PNG, BMP, GIF, JPEG DCT, WAV PCM, PDF, DOCX, ZIP, EOF Append)
  - Memory-hard **Argon2id + AES-256-GCM / ChaCha20** authenticated encryption
  - Multi-payload bundling with deterministic manifest and per-file SHA-256 verification
  - Pre-encryption compression (Auto, Deflate, LZMA, BZIP2, None)
  - Defensive forensic steganalysis (Shannon entropy, Block entropy variance, Chi-Square PoV LSB test, trailing bytes, risk scoring 0–100)
  - Cryptographic HMAC-SHA256 digital watermarking
  - Stego Lab comparative benchmark matrix (Capacity, PSNR dB, SSIM, Latency)
- **Install status detection** — cached `which`-style checks with `is_installed()`
- **Safe command execution** — confirmation gate for free-form commands; trusted commands for installs and examples
- **Audit logging** — JSONL log at `~/.cyberblack/run_log.jsonl`
- **Live network monitor** — real-time per-interface bandwidth, active connections, listening ports, CPU/RAM
- **Rich terminal UI** — color-coded risk badges, status badges, syntax-highlighted tables via `rich`
- **YAML-driven data** — categories and tool definitions in `cyberblack/data/categories/*.yaml`

---

## Categories

1. **Network Scanning** (Nmap, Masscan, Rustscan, Zmap)
2. **Wi-Fi & Wireless Attacks** (Aircrack-ng, Wifite, Kismet, Bully)
3. **Password & Hash Attacks** (Hashcat, John the Ripper, Hydra, Medusa)
4. **Web Application Testing** (Nikto, SQLmap, Gobuster, FFuF, WPScan)
5. **Exploitation Frameworks** (Metasploit, Searchsploit)
6. **OSINT & Reconnaissance** (theHarvester, Recon-ng, Amass, Spiderfoot, Sherlock)
7. **Packet Analysis & MITM** (Wireshark/TShark, Bettercap, Ettercap, Tcpdump)
8. **Post-Exploitation** (Mimikatz, Empire, Evil-WinRM)
9. **Vulnerability Assessment** (OpenVAS/GVM, Nuclei)
10. **Forensics & Analysis** (Binwalk, Foremost, Exiftool, Volatility)
11. **Steganography & Covert Ops** (StegoForge Core, StegoForge Steganalysis, StegoForge Watermark, StegoForge Stego Lab, Steghide, OpenStego, Zsteg)

---

## Testing

Run all 105 automated unit and integration tests:

```bash
pytest
```
