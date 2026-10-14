#!/usr/bin/env python3
"""Safe-URL CLI: heuristic URL and page-security analysis. Not a verdict engine."""
from __future__ import annotations
import argparse, ipaddress, re, socket, ssl, sys, time, json
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
import requests
from bs4 import BeautifulSoup

VERSION = "1.1.0"  # SAFE-URL V1
RED = "\033[94m"; BRIGHT_RED = "\033[1;94m"; YELLOW = "\033[96m"; GREEN = "\033[96m"; CYAN = "\033[96m"; WHITE = "\033[97m"; DIM = "\033[2m"; RESET = "\033[0m"

BANNER = r'''
███████╗ █████╗ ███████╗███████╗      ██╗   ██╗██████╗ ██╗
██╔════╝██╔══██╗██╔════╝██╔════╝      ██║   ██║██╔══██╗██║
███████╗███████║█████╗  █████╗        ██║   ██║██████╔╝██║
╚════██║██╔══██║██╔══╝  ██╔══╝        ██║   ██║██╔══██╗██║
███████║██║  ██║██║     ███████╗      ╚██████╔╝██║  ██║██║
╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝       ╚═════╝ ╚═╝  ╚═╝╚═╝
                         by N0VA-T3CH  |  V1.1.0
'''

SUSPICIOUS_WORDS = ("login", "signin", "verify", "verification", "password", "wallet", "secure", "account", "update", "support", "confirm", "banking", "free-gift", "gift-card", "webscr", "recover", "auth")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.su", "is.gd", "cutt.ly", "shorturl.at", "rb.gy", "ow.ly", "buff.ly", "rebrand.ly"}
RISKY_TLDS = {".zip", ".mov", ".click", ".country", ".gq", ".tk", ".work", ".support", ".top"}
HEADERS = {"User-Agent": "Safe-URL-CLI/1.0 (defensive URL inspection; contact: local user)"}

class ScanError(Exception): pass

def color(text, c, enabled=True): return f"{c}{text}{RESET}" if enabled else str(text)
def public_host(host):
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_global
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError, UnicodeError):
            return False
        if not infos: return False
        try:
            for info in infos:
                ip = ipaddress.ip_address(info[4][0].split("%",1)[0])
                if not ip.is_global: return False
        except (ValueError, IndexError, TypeError):
            return False
        return True

def normalize_url(raw):
    # Accept both example.com and full URLs such as https://example.com.
    # Remove accidental surrounding quotes/spaces copied from terminals or chats.
    raw = raw.strip().strip('"\'<>').strip()
    if not raw: raise ScanError("Empty URL.")
    if raw in {"--help", "-h"}:
        raise ScanError("HELP_REQUEST")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"): raise ScanError("Only http:// and https:// URLs are supported.")
    if not p.hostname: raise ScanError("Invalid hostname.")
    if p.username or p.password: raise ScanError("URLs containing embedded usernames or passwords are not allowed.")
    try:
        port = p.port
    except ValueError:
        raise ScanError("Invalid port in URL.")
    if port is not None and port not in (80, 443):
        raise ScanError("Only standard HTTP/HTTPS ports 80 and 443 are allowed.")
    if not public_host(p.hostname): raise ScanError("Host is not public or DNS resolution failed. Scan blocked to avoid targeting a private network.")
    return raw

def fetch_checked(url, timeout=10, max_redirects=8):
    session = requests.Session(); current = url; redirects = []; response = None
    for _ in range(max_redirects + 1):
        current = normalize_url(current)
        try: response = session.get(current, headers=HEADERS, timeout=timeout, allow_redirects=False, stream=True, verify=True)
        except requests.exceptions.SSLError as e: raise ScanError(f"TLS/certificate error: {e}")
        except requests.RequestException as e: raise ScanError(f"Connection failed: {e}")
        if response.is_redirect or response.is_permanent_redirect:
            loc = response.headers.get("Location")
            response.close()
            if not loc: break
            nxt = urljoin(current, loc); redirects.append({"from":current,"to":nxt,"status":response.status_code})
            current = nxt; continue
        # Read a limited amount of HTML to avoid downloading large files.
        chunks=[]; total=0
        try:
            for chunk in response.iter_content(8192):
                if not chunk: continue
                chunks.append(chunk); total += len(chunk)
                if total >= 1_000_000: break
        finally:
            response.close()
        body = b"".join(chunks)
        return response.status_code, response.headers, body, current, redirects
    raise ScanError(f"Too many redirects (limit {max_redirects}).")

def tls_details(host, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host,port),timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert=s.getpeercert(); exp=cert.get("notAfter")
                expiry=datetime.strptime(exp,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if exp else None
                return {"ok":True,"issuer":dict(x[0] for x in cert.get("issuer",[])),"expires":expiry.isoformat() if expiry else "unknown","days_left":(expiry-datetime.now(timezone.utc)).days if expiry else None,"version":s.version()}
    except Exception as e: return {"ok":False,"error":str(e)}

def scan(raw, timeout=10):
    start=time.time(); url=normalize_url(raw); p=urlparse(url); host=p.hostname.lower().rstrip(".")
    findings=[]; score=0
    def flag(points, severity, message):
        nonlocal score
        score += points; findings.append((severity,message,points))
    if p.scheme != "https": flag(12,"MEDIUM","The site uses unencrypted HTTP.")
    if "@" in p.netloc: flag(20,"HIGH","An @ symbol appears in the URL authority section.")
    if len(url)>180: flag(8,"LOW","Very long URL (>180 characters).")
    if len(host.split("."))>=5: flag(7,"LOW","Many subdomains (at least four levels).")
    if "xn--" in host: flag(12,"MEDIUM","Punycode domain: check for lookalike characters.")
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}",host): flag(18,"HIGH","The URL uses an IPv4 address instead of a domain name.")
    if host in SHORTENERS: flag(10,"MEDIUM","URL shortener detected: the destination is hidden until redirected.")
    if any(host.endswith(tld) for tld in RISKY_TLDS): flag(5,"LOW","This top-level domain is sometimes abused; this alone is not proof of danger.")
    hits=[w for w in SUSPICIOUS_WORDS if w in (host + p.path + "?" + p.query).lower()]
    if hits: flag(min(16,3*len(hits)),"MEDIUM","Sensitive words in URL: " + ", ".join(hits[:8]))
    if host.count("-")>=3: flag(5,"LOW","The hostname contains many hyphens.")
    try:
        infos=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM); ips=sorted({i[4][0] for i in infos})
    except socket.gaierror: ips=[]
    if not ips: flag(15,"HIGH","The hostname did not resolve through DNS.")
    try:
        status, headers, body, final_url, redirects=fetch_checked(url,timeout=timeout)
    except ScanError as e:
        return {"url":url,"host":host,"score":min(score,100),"findings":findings,"error":str(e),"ips":ips,"elapsed":round(time.time()-start,2)}
    final=urlparse(final_url)
    if redirects:
        if len(redirects)>=3: flag(6,"MEDIUM",f"Long redirect chain: {len(redirects)} redirects.")
        if any(urlparse(r["to"]).hostname != host for r in redirects): flag(8,"MEDIUM","A redirect changes the hostname; verify the final destination.")
        if any(urlparse(r["to"]).scheme=="http" for r in redirects): flag(10,"MEDIUM","At least one redirect uses HTTP.")
    if final.scheme!="https": flag(10,"MEDIUM","The final destination does not use HTTPS.")
    ctype=headers.get("Content-Type","")
    soup=None; html=""
    if "html" in ctype.lower() or body.lstrip().lower().startswith((b"<!doctype html",b"<html",b"<head",b"<body")):
        soup=BeautifulSoup(body,"html.parser"); html=body.decode("utf-8",errors="replace")
    page={"title":"(not detected)","links":0,"external_links":0,"forms":0,"password_fields":0,"iframes":0,"scripts":0,"meta_refresh":False,"external_domains":[],"html_bytes":len(body)}
    if soup:
        if soup.title and soup.title.string: page["title"]=" ".join(soup.title.string.split())[:180]
        links=[a.get("href") for a in soup.find_all("a",href=True)]
        page["links"]=len(links); ext=set()
        for link in links:
            dest=urlparse(urljoin(final_url,link))
            if dest.hostname and dest.hostname.lower()!=final.hostname.lower(): ext.add(dest.hostname.lower())
        page["external_links"]=sum(1 for link in links if (urlparse(urljoin(final_url,link)).hostname or "").lower()!=final.hostname.lower())
        page["external_domains"]=sorted(ext)[:20]
        forms=soup.find_all("form"); page["forms"]=len(forms)
        page["password_fields"]=len(soup.select('input[type="password"]'))
        page["iframes"]=len(soup.find_all("iframe")); page["scripts"]=len(soup.find_all("script"))
        page["meta_refresh"]=bool(soup.find("meta",attrs={"http-equiv":re.compile("refresh",re.I)}))
        if page["password_fields"] and final.scheme!="https": flag(20,"HIGH","A password field appears on a page without HTTPS.")
        if page["password_fields"]: flag(3,"INFO",f"The page contains {page['password_fields']} password field(s); verify the site is legitimate.")
        if page["iframes"]>=4: flag(5,"LOW",f"High iframe count: {page['iframes']}.")
        if page["meta_refresh"]: flag(6,"MEDIUM","HTML meta-refresh redirect detected.")
        if page["external_links"]>=20: flag(3,"INFO",f"High number of external links: {page['external_links']}.")
        if re.search(r"(verify your account|account suspended|confirm your password|urgent action required)",html,re.I): flag(8,"MEDIUM","Text commonly associated with phishing attempts was detected.")
    else:
        flag(2,"INFO","The response does not appear to be HTML; content analysis is limited.")
    tls=tls_details(host) if p.scheme=="https" else {"ok":False,"error":"Initial URL uses HTTP"}
    if p.scheme=="https" and not tls["ok"]: flag(10,"MEDIUM","Could not validate the initial hostname TLS certificate.")
    if tls.get("days_left") is not None and tls["days_left"]<0: flag(15,"HIGH","The TLS certificate appears to be expired.")
    score=min(100,score)
    if score>=50: level="VERY HIGH"; col=BRIGHT_RED
    elif score>=30: level="HIGH"; col=RED
    elif score>=15: level="MODERATE"; col=YELLOW
    else: level="LOW (heuristic)"; col=GREEN
    return {"url":url,"host":host,"final_url":final_url,"status":status,"headers":dict(headers),"ips":ips,"redirects":redirects,"tls":tls,"page":page,"score":score,"level":level,"color":col,"findings":findings,"elapsed":round(time.time()-start,2)}

def print_report(r, no_color=False, verbose=False):
    c=lambda s, col: color(s, col, not no_color)
    print("\n"+c("═"*68,RED)); print(c("  SAFE-URL REPORT",BRIGHT_RED)+f"  |  Heuristic score: {r['score']}/100")
    if r.get("level"): print("  Risk level: "+c(r['level'],r['color']))
    print(c("═"*68,RED)); print(f"URL        : {r['url']}"); print(f"Hostname   : {r['host']}")
    if r.get("final_url"): print(f"Final URL: {r['final_url']}\nHTTP status : {r['status']}")
    print("DNS IP address(es): "+(", ".join(r.get("ips",[])) or "no DNS resolution"))
    if r.get("redirects"):
        print(f"Redirects ({len(r['redirects'])}) :")
        for x in r["redirects"]: print(f"  [{x['status']}] {x['from']} -> {x['to']}")
    if r.get("tls"):
        t=r["tls"]; print("TLS        : "+(f"OK ({t.get('version','?')}); expires: {t.get('expires','inconnue')}" if t.get("ok") else "not validated — "+t.get("error","unknown")))
    if r.get("page"):
        p=r["page"]; print("\nPAGE ANALYSIS"); print(f"  Title: {p['title']}"); print(f"  Links: {p['links']} (external: {p['external_links']})"); print(f"  Forms: {p['forms']} | password fields: {p['password_fields']}"); print(f"  Iframes: {p['iframes']} | scripts: {p['scripts']} | meta-refresh: {'oui' if p['meta_refresh'] else 'non'}"); print(f"  HTML read: {p['html_bytes']} bytes (limited to ~1 MB)")
        if p["external_domains"]: print("  External hostnames: "+", ".join(p["external_domains"]))
    print("\nFINDINGS")
    if r.get("findings"):
        for sev,msg,pts in r["findings"]:
            co=BRIGHT_RED if sev=="HIGH" else YELLOW if sev=="MEDIUM" else CYAN if sev=="INFO" else WHITE
            print(f"  {c('['+sev+']',co)} {msg} {c('+'+str(pts),DIM)}")
    else: print(c("  No heuristic indicators were found. This does NOT prove the site is safe.",GREEN))
    if r.get("error"): print(c("\nERREUR : "+r["error"],RED))
    print(f"\nElapsed time: {r.get('elapsed',0)} s")
    print(c("Note: this is a heuristic score, not a certified reputation check. A phishing site may trigger no indicators.",YELLOW))

def main():
    parser = argparse.ArgumentParser(
        prog="safe-url",
        description="Defensive URL scanner for DNS, TLS, redirects, page metadata, and common phishing indicators.",
        epilog="Examples:\n  python safe_url.py https://example.com\n  python safe_url.py -v example.com\n  python safe_url.py --batch urls.txt --output results.json --json\n  python safe_url.py --no-color https://example.com",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="URL to scan (http:// or https://; https:// is assumed if omitted)")
    parser.add_argument("-v", "--verbose", action="store_true", help="show additional report details")
    parser.add_argument("--timeout", type=int, default=10, help="request timeout in seconds (default: 10; maximum: 60)")
    parser.add_argument("--no-color", action="store_true", help="disable terminal colors")
    parser.add_argument("--batch", metavar="FILE", help="scan URLs listed in a text file (one URL per line; blank lines and # comments ignored)")
    parser.add_argument("-o", "--output", metavar="FILE", help="save the report to a file; JSON when --json is used, otherwise plain text")
    parser.add_argument("--json", action="store_true", help="write machine-readable JSON output (use with --output or batch mode)")
    parser.add_argument("--version", action="version", version=f"Safe-URL {VERSION}")
    args = parser.parse_args()
    if args.timeout < 1 or args.timeout > 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    if not args.no_color:
        print(color(BANNER, BRIGHT_RED))
    else:
        print(BANNER)
    print("  ANALYZE | DETECT | PROTECT  |  SAFE-URL V1  |  by N0VA-T3CH")
    print("  Defensive checks only. No reputation database is queried.\n")

    interactive = not args.url and not args.batch and not args.output and not args.json
    while True:
        urls = []
        if args.batch:
            try:
                with open(args.batch, "r", encoding="utf-8-sig") as handle:
                    urls = [line.strip() for line in handle if line.strip() and not line.lstrip().startswith("#")]
            except OSError as exc:
                print(f"Could not read batch file: {exc}", file=sys.stderr)
                return 2
            if not urls:
                print("The batch file contains no URLs.", file=sys.stderr)
                return 2
        elif args.url:
            urls = [args.url]
        else:
            try:
                raw = input(color("  N0VA-TECH@SAFE-URL > Enter URL (example.com or https://example.com): ", BRIGHT_RED)).strip()
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled.")
                return 130
            if raw in {"--help", "-h"}:
                parser.print_help()
                return 0
            if raw.lower() in {"q", "quit", "exit"}:
                return 0
            if not raw:
                print("No URL provided. Use --help.", file=sys.stderr)
                return 2
            urls = [raw]

        results = []
        from contextlib import redirect_stdout
        from io import StringIO
        for index, raw in enumerate(urls, start=1):
            if args.batch:
                print(f"[{index}/{len(urls)}] Scanning: {raw}")
            try:
                result = scan(raw, timeout=args.timeout)
            except ScanError as exc:
                if str(exc) == "HELP_REQUEST":
                    parser.print_help()
                    return 0
                result = {"url": raw, "score": 0, "findings": [], "error": str(exc), "elapsed": 0}
            except KeyboardInterrupt:
                print("\nScan interrupted.")
                return 130
            except Exception as exc:
                result = {"url": raw, "score": 0, "findings": [], "error": f"Unexpected error ({type(exc).__name__}): {exc}", "elapsed": 0}
            results.append(result)
            if not args.json and not args.output:
                print_report(result, args.no_color, args.verbose)
            elif args.batch and not args.output:
                print_report(result, args.no_color, args.verbose)

        if args.output:
            try:
                if args.json:
                    with open(args.output, "w", encoding="utf-8") as handle:
                        json.dump(results if args.batch else results[0], handle, indent=2, ensure_ascii=False)
                        handle.write("\n")
                else:
                    with open(args.output, "w", encoding="utf-8") as handle:
                        for result in results:
                            buf = StringIO()
                            with redirect_stdout(buf):
                                print_report(result, no_color=True, verbose=args.verbose)
                            handle.write(buf.getvalue() + "\n")
                print(f"Report saved to: {args.output}")
            except OSError as exc:
                print(f"Could not save report: {exc}", file=sys.stderr)
                return 2
        elif args.json:
            print(json.dumps(results if args.batch else results[0], indent=2, ensure_ascii=False))
        status = 1 if any(item.get("error") for item in results) else 0
        if not interactive:
            return status
        print("\n  Scan complete. Enter another URL, or type --help for help.")


if __name__=="__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"Startup error ({type(e).__name__}): {e}")
        try: input("Press Enter to close...")
        except (EOFError, KeyboardInterrupt): pass
