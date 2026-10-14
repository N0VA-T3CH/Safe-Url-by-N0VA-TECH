#!/usr/bin/env python3
"""Safe-URL CLI: heuristic URL and page-security analysis. Not a verdict engine."""
from __future__ import annotations
import argparse, ipaddress, re, socket, ssl, sys, time
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
import requests
from bs4 import BeautifulSoup

VERSION = "1.0.0"  # SAFE-URL V1
RED = "\033[94m"; BRIGHT_RED = "\033[1;94m"; YELLOW = "\033[96m"; GREEN = "\033[96m"; CYAN = "\033[96m"; WHITE = "\033[97m"; DIM = "\033[2m"; RESET = "\033[0m"

BANNER = r'''
███████╗ █████╗ ███████╗███████╗      ██╗   ██╗██████╗ ██╗
██╔════╝██╔══██╗██╔════╝██╔════╝      ██║   ██║██╔══██╗██║
███████╗███████║█████╗  █████╗        ██║   ██║██████╔╝██║
╚════██║██╔══██║██╔══╝  ██╔══╝        ██║   ██║██╔══██╗██║
███████║██║  ██║██║     ███████╗      ╚██████╔╝██║  ██║██║
╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝       ╚═════╝ ╚═╝  ╚═╝╚═╝
                         by N0VA-T3CH  |  V1.0.0
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
        except socket.gaierror:
            return False
        if not infos: return False
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split("%",1)[0])
            if not ip.is_global: return False
        return True

def normalize_url(raw):
    raw = raw.strip()
    if not raw: raise ScanError("URL vide.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw): raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"): raise ScanError("Seuls http:// et https:// sont acceptés.")
    if not p.hostname: raise ScanError("Nom de domaine invalide.")
    if p.username or p.password: raise ScanError("Les URL contenant un identifiant/mot de passe sont refusées.")
    if not public_host(p.hostname): raise ScanError("Hôte non public ou résolution DNS impossible : analyse bloquée pour éviter de viser un réseau privé.")
    return raw

def fetch_checked(url, timeout=10, max_redirects=8):
    session = requests.Session(); current = url; redirects = []; response = None
    for _ in range(max_redirects + 1):
        current = normalize_url(current)
        try: response = session.get(current, headers=HEADERS, timeout=timeout, allow_redirects=False, stream=True, verify=True)
        except requests.exceptions.SSLError as e: raise ScanError(f"Erreur TLS/certificat : {e}")
        except requests.RequestException as e: raise ScanError(f"Connexion impossible : {e}")
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
    raise ScanError(f"Trop de redirections (limite {max_redirects}).")

def tls_details(host, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host,port),timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert=s.getpeercert(); exp=cert.get("notAfter")
                expiry=datetime.strptime(exp,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if exp else None
                return {"ok":True,"issuer":dict(x[0] for x in cert.get("issuer",[])),"expires":expiry.isoformat() if expiry else "inconnue","days_left":(expiry-datetime.now(timezone.utc)).days if expiry else None,"version":s.version()}
    except Exception as e: return {"ok":False,"error":str(e)}

def scan(raw, timeout=10):
    start=time.time(); url=normalize_url(raw); p=urlparse(url); host=p.hostname.lower().rstrip(".")
    findings=[]; score=0
    def flag(points, severity, message):
        nonlocal score
        score += points; findings.append((severity,message,points))
    if p.scheme != "https": flag(12,"MOYEN","Le site utilise HTTP sans chiffrement.")
    if "@" in p.netloc: flag(20,"ÉLEVÉ","Présence de @ dans la partie hôte de l’URL.")
    if len(url)>180: flag(8,"FAIBLE","URL très longue (>180 caractères).")
    if len(host.split("."))>=5: flag(7,"FAIBLE","Sous-domaines nombreux (au moins 4 niveaux).")
    if "xn--" in host: flag(12,"MOYEN","Nom de domaine international encodé en punycode : vérifier les caractères ressemblants.")
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}",host): flag(18,"ÉLEVÉ","L’URL utilise une adresse IPv4 plutôt qu’un domaine.")
    if host in SHORTENERS: flag(10,"MOYEN","Service de raccourcissement d’URL : destination masquée avant redirection.")
    if any(host.endswith(tld) for tld in RISKY_TLDS): flag(5,"FAIBLE","Extension de domaine parfois abusée ; ce n’est pas une preuve de danger.")
    hits=[w for w in SUSPICIOUS_WORDS if w in (host + p.path + "?" + p.query).lower()]
    if hits: flag(min(16,3*len(hits)),"MOYEN","Mots sensibles dans l’URL : " + ", ".join(hits[:8]))
    if host.count("-")>=3: flag(5,"FAIBLE","Beaucoup de tirets dans le nom de domaine.")
    try:
        infos=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM); ips=sorted({i[4][0] for i in infos})
    except socket.gaierror: ips=[]
    if not ips: flag(15,"ÉLEVÉ","Le nom d’hôte ne se résout pas en DNS.")
    try:
        status, headers, body, final_url, redirects=fetch_checked(url,timeout=timeout)
    except ScanError as e:
        return {"url":url,"host":host,"score":min(score,100),"findings":findings,"error":str(e),"ips":ips,"elapsed":round(time.time()-start,2)}
    final=urlparse(final_url)
    if redirects:
        if len(redirects)>=3: flag(6,"MOYEN",f"Chaîne de redirections longue : {len(redirects)} redirections.")
        if any(urlparse(r["to"]).hostname != host for r in redirects): flag(8,"MOYEN","Une redirection change de domaine ; vérifiez la destination finale.")
        if any(urlparse(r["to"]).scheme=="http" for r in redirects): flag(10,"MOYEN","Au moins une redirection passe par HTTP.")
    if final.scheme!="https": flag(10,"MOYEN","La destination finale n’utilise pas HTTPS.")
    ctype=headers.get("Content-Type","")
    soup=None; html=""
    if "html" in ctype.lower() or body.lstrip().lower().startswith((b"<!doctype html",b"<html",b"<head",b"<body")):
        soup=BeautifulSoup(body,"html.parser"); html=body.decode("utf-8",errors="replace")
    page={"title":"(non détecté)","links":0,"external_links":0,"forms":0,"password_fields":0,"iframes":0,"scripts":0,"meta_refresh":False,"external_domains":[],"html_bytes":len(body)}
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
        if page["password_fields"] and final.scheme!="https": flag(20,"ÉLEVÉ","Champ de mot de passe sur une page non HTTPS.")
        if page["password_fields"]: flag(3,"INFO",f"La page contient {page['password_fields']} champ(s) de mot de passe : vérifiez que le site est bien celui attendu.")
        if page["iframes"]>=4: flag(5,"FAIBLE",f"Nombre élevé d’iframes : {page['iframes']}.")
        if page["meta_refresh"]: flag(6,"MOYEN","Redirection HTML via meta refresh détectée.")
        if page["external_links"]>=20: flag(3,"INFO",f"Nombre élevé de liens externes : {page['external_links']}.")
        if re.search(r"(verify your account|account suspended|confirm your password|urgent action required)",html,re.I): flag(8,"MOYEN","Texte fréquemment associé à des tentatives d’hameçonnage détecté.")
    else:
        flag(2,"INFO","La réponse n’est pas reconnue comme une page HTML ; l’analyse de contenu est limitée.")
    tls=tls_details(host) if p.scheme=="https" else {"ok":False,"error":"URL initiale en HTTP"}
    if p.scheme=="https" and not tls["ok"]: flag(10,"MOYEN","Impossible de valider le certificat TLS du domaine initial.")
    if tls.get("days_left") is not None and tls["days_left"]<0: flag(15,"ÉLEVÉ","Le certificat TLS semble expiré.")
    score=min(100,score)
    if score>=50: level="TRÈS ÉLEVÉ"; col=BRIGHT_RED
    elif score>=30: level="ÉLEVÉ"; col=RED
    elif score>=15: level="MODÉRÉ"; col=YELLOW
    else: level="FAIBLE (heuristique)"; col=GREEN
    return {"url":url,"host":host,"final_url":final_url,"status":status,"headers":dict(headers),"ips":ips,"redirects":redirects,"tls":tls,"page":page,"score":score,"level":level,"color":col,"findings":findings,"elapsed":round(time.time()-start,2)}

def print_report(r, no_color=False, verbose=False):
    c=lambda s, col: color(s, col, not no_color)
    print("\n"+c("═"*68,RED)); print(c("  RAPPORT SAFE-URL",BRIGHT_RED)+f"  |  Score heuristique : {r['score']}/100")
    if r.get("level"): print("  Niveau : "+c(r['level'],r['color']))
    print(c("═"*68,RED)); print(f"URL        : {r['url']}"); print(f"Domaine    : {r['host']}")
    if r.get("final_url"): print(f"Destination : {r['final_url']}\nHTTP status : {r['status']}")
    print("IP(s) DNS  : "+(", ".join(r.get("ips",[])) or "aucune résolution"))
    if r.get("redirects"):
        print(f"Redirections ({len(r['redirects'])}) :")
        for x in r["redirects"]: print(f"  [{x['status']}] {x['from']} -> {x['to']}")
    if r.get("tls"):
        t=r["tls"]; print("TLS        : "+(f"OK ({t.get('version','?')}); expire : {t.get('expires','inconnue')}" if t.get("ok") else "non validé — "+t.get("error","inconnu")))
    if r.get("page"):
        p=r["page"]; print("\nANALYSE DE LA PAGE"); print(f"  Titre : {p['title']}"); print(f"  Liens : {p['links']} (externes : {p['external_links']})"); print(f"  Formulaires : {p['forms']} | champs mot de passe : {p['password_fields']}"); print(f"  Iframes : {p['iframes']} | scripts : {p['scripts']} | meta-refresh : {'oui' if p['meta_refresh'] else 'non'}"); print(f"  HTML lu : {p['html_bytes']} octets (limité à ~1 Mo)")
        if p["external_domains"]: print("  Domaines externes : "+", ".join(p["external_domains"]))
    print("\nINDICATEURS")
    if r.get("findings"):
        for sev,msg,pts in r["findings"]:
            co=BRIGHT_RED if sev=="ÉLEVÉ" else YELLOW if sev=="MOYEN" else CYAN if sev=="INFO" else WHITE
            print(f"  {c('['+sev+']',co)} {msg} {c('+'+str(pts),DIM)}")
    else: print(c("  Aucun indicateur heuristique relevé. Cela ne prouve PAS que le site est sûr.",GREEN))
    if r.get("error"): print(c("\nERREUR : "+r["error"],RED))
    print(f"\nDurée : {r.get('elapsed',0)} s")
    print(c("Note : score heuristique, pas une réputation certifiée. Un site de phishing peut ne déclencher aucun indicateur.",YELLOW))

def main():
    parser=argparse.ArgumentParser(prog="safe-url",description="Scanner défensif d’URL en terminal : DNS, HTTPS/TLS, redirections et signaux de phishing.",epilog="Exemples :\n  python safe_url.py https://example.com\n  python safe_url.py -v example.com\n  python safe_url.py --no-color https://example.com",formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("url",nargs="?",help="URL à analyser (http(s):// facultatif)")
    parser.add_argument("-v","--verbose",action="store_true",help="afficher les détails supplémentaires")
    parser.add_argument("--timeout",type=int,default=10,help="délai max par requête en secondes (défaut : 10)")
    parser.add_argument("--no-color",action="store_true",help="désactiver les couleurs")
    parser.add_argument("--version",action="version",version=f"Safe-URL {VERSION}")
    args=parser.parse_args()
    if not args.no_color: print(color(BANNER,BRIGHT_RED))
    else: print(BANNER)
    print("  ◆ ANALYZE  ◆ DETECT  ◆ PROTECT  |  SAFE-URL V1  |  by N0VA-T3CH")
    print("  Tape --help pour l’aide. Aucun site web local n’est lancé.\n")
    raw=args.url
    if not raw:
        try: raw=input(color("  N0VA-T3CH@SAFE-URL >  Select your URL : ",BRIGHT_RED)).strip()
        except (EOFError,KeyboardInterrupt): print("\nArrêt."); return 130
        if raw.lower() in {"q","quit","exit"}: return 0
    if not raw: print("Aucune URL fournie. Utilise --help.",file=sys.stderr); return 2
    try:
        result=scan(raw,max(1,min(args.timeout,60)))
        print_report(result,args.no_color,args.verbose)
        return 0
    except ScanError as e:
        print(color("Erreur : "+str(e),RED)); return 2
    except KeyboardInterrupt:
        print("\nAnalyse interrompue."); return 130

if __name__=="__main__": raise SystemExit(main())
