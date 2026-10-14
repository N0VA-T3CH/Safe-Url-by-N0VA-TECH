# SAFE-URL V1 — by N0VA-T3CH

Version 1.0.0 — terminal CLI, thème bleu.

Version CLI uniquement : aucun serveur web, aucune interface navigateur.

## Installation facile — Windows
1. Extrais le ZIP.
2. Double-clique `install_windows.bat`.
3. Quand c'est terminé, double-clique `run_windows.bat` pour entrer une URL, ou ouvre un terminal dans ce dossier.

## Linux / Kali / Termux
Dans le dossier extrait :
```bash
python3 -m pip install -r requirements.txt
python3 safe_url.py --help
python3 safe_url.py https://example.com
```
Sur certaines distributions Linux, crée d'abord un environnement virtuel si pip l'exige : `python3 -m venv .venv && . .venv/bin/activate` puis installe les dépendances.

## Commandes
```bash
python safe_url.py --help
python safe_url.py https://example.com
python safe_url.py -v https://example.com
python safe_url.py --no-color https://example.com
```
Sans URL en argument, l'outil demande `Select your URL`.

## Contrôles
- Signaux URL : longueur, sous-domaines, punycode, IP directe, raccourcisseurs, mots sensibles.
- DNS et adresse(s) IP publiques.
- HTTP status, redirections et domaine final.
- Certificat TLS pour HTTPS.
- Page HTML : titre, nombre de liens et de domaines externes, formulaires, champs de mot de passe, iframes, scripts et meta-refresh.
- Indicateurs textuels de phishing courants et score heuristique explicable.

## Limites importantes
Ce scanner **n'est pas une base de réputation** et ne prouve pas qu'une URL est saine ou malveillante. Il ne consulte pas VirusTotal, Google Safe Browsing ou des listes noires, n'estime pas de manière fiable l'âge du domaine et ne compte pas les onglets ouverts dans le navigateur (cela n'est pas visible depuis une URL seule). Le score est une heuristique, pas une probabilité. Les pages dynamiques peuvent cacher leur contenu au scanner. Les erreurs TLS peuvent interrompre la récupération plutôt que d'être ignorées.

Le scanner refuse les destinations privées/non publiques et suit les redirections manuellement avec une limite. Cela réduit les risques, mais ne constitue pas une garantie contre toutes les techniques DNS avancées. Utilise-le seulement sur des URL que tu es autorisé à analyser, sans envoyer de secrets ou d'identifiants.
