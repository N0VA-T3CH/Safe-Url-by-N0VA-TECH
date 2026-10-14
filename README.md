# Safe-URL v1.0.0

**A defensive URL analysis tool by N0VA-T3CH.** Safe-URL is a command-line scanner that checks URL structure, public DNS/IP information, HTTP redirects, HTTPS/TLS, page metadata, and common phishing indicators.

> **Important:** The risk score is heuristic, not a guarantee. Safe-URL does not query VirusTotal, Google Safe Browsing, or other reputation databases. A low score does not prove that a URL is safe.

## 1. Download the project

### Option A — Clone with Git

Install Git, then run:

```bash
git clone https://github.com/N0VA-T3CH/Safe-Url-by-N0VA-TECH.git
cd Safe-Url-by-N0VA-TECH
```

The repository may contain the project in a subfolder. Change into the folder containing `safe_url.py` and `requirements.txt` before continuing.

### Option B — Download ZIP (no Git needed)

1. Open the repository on GitHub.
2. Select **Code → Download ZIP**.
3. Extract the ZIP archive.
4. Open a terminal in the folder containing `safe_url.py` and `requirements.txt`.

## 2. Windows (easiest)

1. Install Python 3 from <https://www.python.org/downloads/windows/>. Enable **Add Python to PATH** if the installer offers it.
2. Extract the project ZIP.
3. Double-click `install_windows.bat`.
4. When installation finishes, double-click `run_windows.bat`.

To scan a URL from PowerShell or Command Prompt, run:

```powershell
py -m pip install -r requirements.txt
py safe_url.py https://example.com
```

If `py` is not available, use `python` instead.

## 3. Linux (Ubuntu, Debian, Kali)

Install Python, Git, and virtual-environment support:

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv
```

Clone the repository or extract the ZIP, then enter the folder containing the project files. Recommended setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python safe_url.py https://example.com
```

To see all options:

```bash
python safe_url.py --help
```

## 4. Android (Termux)

1. Install Termux from a trusted source, such as F-Droid or the official Termux GitHub releases.
2. Open Termux and run:

```bash
pkg update
pkg install -y python git
git clone https://github.com/N0VA-T3CH/Safe-Url-by-N0VA-TECH.git
cd Safe-Url-by-N0VA-TECH
```

If the project files are inside a subfolder, enter the folder containing `safe_url.py` and `requirements.txt`. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python safe_url.py https://example.com
```

Some packages or network checks may behave differently on Android.

## 5. Docker

Install Docker Desktop (Windows/macOS) or Docker Engine (Linux): <https://docs.docker.com/get-docker/>.

Build the image from the directory containing the included `Dockerfile`:

```bash
docker build -t safe-url-v1 .
```

Scan a URL:

```bash
docker run --rm safe-url-v1 https://example.com
```

Show help:

```bash
docker run --rm safe-url-v1 --help
```

## Commands

```bash
python safe_url.py https://example.com
python safe_url.py -v https://example.com
python safe_url.py --no-color https://example.com
python safe_url.py --help
python safe_url.py --version
```

The URL argument is optional; if omitted, Safe-URL prompts you to enter one.

## What it checks

- URL structure and suspicious patterns (including punycode, direct IPs, URL shorteners, and sensitive keywords)
- Public DNS and IP information
- HTTP status and redirects
- HTTPS/TLS certificate information
- Basic HTML metadata, links, forms, scripts, iframes, and related phishing indicators
- An explainable heuristic risk score

## Safety and limitations

- Use Safe-URL only on URLs you are authorized to analyze.
- It refuses private/non-public destinations and handles redirects with a limit, but no scanner can guarantee protection against every DNS or network trick.
- It is not a reputation database and cannot prove that a site is safe or malicious.
- Do not enter passwords, API keys, or other secrets into untrusted software.
