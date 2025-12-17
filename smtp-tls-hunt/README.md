# smtp-tls-hunt

Script autonome pour valider des endpoints SMTP en TLS, détecter les problèmes de certificat et tenter des sous-domaines énumérés automatiquement.

## Installation

- Pré-requis : Python 3.10+
- Cloner le dépôt ou copier le dossier `smtp-tls-hunt/`.
- Installer la dépendance requise par `sub.py` pour l'énumération des sous-domaines :
  ```
  pip install requests
  ```

## Usage

Exécution minimale (tout est prédéfini dans le script) :
```
python smtp-tls.py
```

Le script utilise par défaut :
- `smtps.txt` situé dans le même dossier (format `smtpserver|port|username|password`).
- L'expéditeur est l'identifiant (`username`) de chaque ligne, et le script vous demande l'adresse email de test destinataire au lancement.

Options (toutes facultatives) :
- `--input` : fichier d'entrées au format `host[:port]` ou `host|port|username|password` (une par ligne, `#` pour les commentaires). Les identifiants présents sur une ligne priment sur ceux fournis en CLI.
- `--from` / `--to` : adresses email utilisées pour les tests d'envoi (si `--to` n'est pas fourni, une invite demandera l'adresse de test).
- `--username` / `--password` : identifiants SMTP (facultatifs, utilisés si la ligne ne fournit pas ses propres identifiants).
- `--ports` : liste de ports à tester (par défaut `465,587,25`).
- `--timeout` : timeout réseau (secondes, par défaut 10).
- `--enum-timeout` : timeout pour l'exécution de `sub.py`.
- `--fallback-plain` : tenter `AUTH PLAIN` sans TLS si aucun endpoint TLS ne fonctionne (par défaut `false`).

## Flux de fonctionnement

1. Lecture de `smtps.txt` et premier test TLS sur chaque entrée.
2. En cas de mismatch TLS (hostname du certificat incorrect), extraction des noms SAN/CN du certificat pour déterminer le domaine visé.
3. Lancement de `python sub.py <domain>` pour énumérer les sous-domaines liés (fichier `<domain>.txt`).
4. Boucle de tests TLS sur le domaine extrait et les sous-domaines énumérés (465 en TLS implicite, 587/25 en STARTTLS) avec envoi d'un email de test.
5. Si aucun endpoint TLS ne fonctionne, option de fallback `AUTH PLAIN` sans TLS (non recommandé).
6. Les endpoints validés sont enregistrés dans `validated_endpoints.txt`.

## Logs

- Les logs sont écrits dans `smtp.log` (même dossier que le script) au format JSONL (1 JSON par ligne).
- Événements principaux : `initial_tls_test`, `extract_cert_names`, `run_sub_enum`, `tls_hunt_endpoints`, `fallback_plain_auth_no_tls`.
- Exemple de ligne JSONL :
```
{"event": "initial_tls_test", "endpoint": "smtp.example.com:465", "status": "failure", "error": "certificate verify failed: hostname 'smtp.example.com' doesn't match 'mail.example.com'"}
```

## Sécurité

L'option `--fallback-plain true` tente une authentification `AUTH PLAIN` sans chiffrement si tous les essais TLS échouent. Utilisez-la uniquement en environnement contrôlé.

Assurez-vous que `sub.py` se trouve dans le même dossier que `smtp_tester.py` / `smtp-tls.py`, car il est exécuté via `python sub.py <domain>` lors de l'énumération.
