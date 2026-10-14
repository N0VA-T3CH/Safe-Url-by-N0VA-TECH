# Safe-URL v1.1.0 — by N0VA-T3CH

A defensive command-line tool that inspects a public URL for common warning signs. It checks URL structure, DNS results, HTTP status and redirects, TLS certificate details, and basic page metadata such as forms, password fields, scripts, iframes, and external links.

> **Important:** Safe-URL uses heuristics, not a verdict engine. It does not query VirusTotal, Google Safe Browsing, or commercial threat-intelligence databases. A low score does not prove a site is safe, and a high score is not proof of malicious activity.

## Quick start (Windows — easiest)

1. Download the ZIP from GitHub (**Code → Download ZIP**) or use the ZIP you already have.
2. Extract the ZIP. Do not run the Python file from inside the compressed archive.
3. Install Python 3 from <https://www.python.org/downloads/windows/>. If the installer offers **Add Python to PATH**, enable it.
4. Open the extracted `safe-url-cli` folder.
5. Double-click **`install_windows.bat`** and wait for it to finish.
6. Double-click **`run_windows.bat`**. Enter a URL such as `https://example.com` and press Enter.

The launcher keeps the terminal open so you can read error messages. If Windows says Python is not installed, install Python 3 and retry.

### Run a URL directly from a terminal

Open Command Prompt or PowerShell **inside the folder containing `safe_url.py`**, then run:

```powershell
py safe_url.py https://example.com
```

If `py` is not recognized, try:

```powershell
python safe_url.py https://example.com
```

Install dependencies once if needed:

```powershell
py -m pip install -r requirements.txt
```

## Quick start (Linux / Kali / Ubuntu / Debian)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python safe_url.py https://example.com
```

If Python or venv support is missing on Debian-based systems:

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
```

## Android (Termux)

Install Termux from a trusted source, then, from the extracted project folder:

```bash
pkg update
pkg install python
python -m pip install -r requirements.txt
python safe_url.py https://example.com
```

Some network checks can behave differently on Android.

## Docker

Build from the directory containing the Dockerfile:

```bash
docker build -t safe-url .
docker run --rm safe-url https://example.com
```

## Features

- URL normalization and validation; supports HTTP and HTTPS.
- Blocks non-public/private destinations as a basic defensive safeguard.
- DNS address lookup for public hostnames.
- HTTP status and redirect-chain inspection, with redirect limits.
- TLS certificate validation and certificate expiry details for HTTPS.
- Basic HTML inspection: title, forms, password fields, scripts, iframes, meta refresh, and external links.
- Heuristic flags for suspicious URL patterns, punycode, IP-based URLs, URL shorteners, sensitive terms, and certain redirect/page patterns.
- A readable report with a heuristic score and findings.
- Batch scanning from a text file.
- Plain-text or JSON report export.
- Timeout control and color-free output for compatibility.

## Examples

### Scan one URL

```bash
python safe_url.py https://example.com
```

### Show more detail

```bash
python safe_url.py -v https://example.com
```

### Disable terminal colors

```bash
python safe_url.py --no-color https://example.com
```

### Set a timeout (1–60 seconds)

```bash
python safe_url.py --timeout 15 https://example.com
```

### Scan several URLs

Create a file called `urls.txt`, with one URL per line. Blank lines and lines starting with `#` are ignored:

```text
https://example.com
https://www.python.org
# Add more URLs below
https://www.wikipedia.org
```

Then run:

```bash
python safe_url.py --batch urls.txt
```

### Save a readable report

```bash
python safe_url.py https://example.com --output report.txt
```

### Save JSON output

```bash
python safe_url.py https://example.com --json --output report.json
```

For a batch JSON report:

```bash
python safe_url.py --batch urls.txt --json --output results.json
```

### Get help or version

```bash
python safe_url.py --help
python safe_url.py --version
```

## Common problems

- **`requirements.txt` not found:** the terminal is in the wrong folder. Use the folder that contains both `safe_url.py` and `requirements.txt`.
- **`python` or `py` not found:** install Python 3 and reopen the terminal. On Windows, `py` often works even when `python` does not.
- **`ModuleNotFoundError` for `requests` or `bs4`:** run `py -m pip install -r requirements.txt` on Windows or `python -m pip install -r requirements.txt` elsewhere.
- **The terminal closes immediately:** run `run_windows.bat` or open a terminal in the project folder and launch the script from there so the error remains visible.
- **DNS/connection error:** the hostname may be unavailable, the network may block the request, or the URL may not resolve publicly.
- **TLS error:** the site may have a certificate issue, the system clock may be wrong, or an HTTPS inspection proxy may interfere.

## Safety, privacy, and limitations

- Only scan public URLs you are authorized to inspect.
- Safe-URL makes network requests to the URL being scanned. Do not use it on internal/private systems.
- It does not submit URLs to external reputation services, but the destination website will see the scan request.
- It is not a substitute for browser protection, professional incident response, or a dedicated threat-intelligence service.
- Do not enter passwords, API keys, or other secrets into untrusted software.

## Project files

- `safe_url.py` — scanner source code.
- `requirements.txt` — Python dependencies.
- `install_windows.bat` / `run_windows.bat` — Windows setup and launcher.
- `install_unix.sh` — Linux/Unix dependency setup helper.
- `Dockerfile` — optional container image.

## License

No license file is included in this archive. Add a license before redistributing the project if you want to specify reuse terms.
