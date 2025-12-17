# smtp-tls-hunt

Script unique `smtp-tls-test.py` (Python 3) qui analyse la sécurité TLS des serveurs SMTP à partir d'un fichier d'entrée et tente automatiquement des endpoints alternatifs (CN/SAN puis sous-domaines via `sub.py`) pour trouver un chemin d'envoi sécurisé.

## Installation

- Python 3.10+
- Dépendance requise pour `sub.py` (énumération de sous-domaines) :
  ```bash
  pip install requests
  ```
- OpenSSL doit être disponible dans le PATH (utilisé pour les tests TLS).

## Format d'entrée

`./smtps.txt` (une ligne par serveur) :
```
smtpserver|port|user|password
```
Exemple :
```
smtp.gmail.com|465|goferconfirmation@gmail.com|Mfdn$9136
```

## Utilisation

Lancer simplement :
```bash
python smtp-tls-test.py
```
Le script demande l'adresse email de destination (le champ `From` est l'utilisateur fourni dans `smtps.txt`).

Pour chaque ligne :
1. Test TLS sans authentification via `openssl s_client` sur 587 (STARTTLS) et 465 (SMTPS) avec SNI (`-servername` + `-verify_hostname`).
2. Affiche l'atteignabilité, le `Verify return code`, le statut OK/ERREUR, et, en cas d'échec de vérification, le CN et le SAN du certificat.
3. Tente un envoi sécurisé avec les identifiants fournis et le port spécifié dans le fichier d'entrée.
4. Si l'envoi échoue et qu'un CN/SAN a été extrait, reteste l'envoi en remplaçant le host par ces CN/SAN.
5. Si aucun CN/SAN ne fonctionne, lance `python sub.py <domaine>` (domaine dérivé du CN/SAN) pour récupérer les sous-domaines, puis tente un envoi via chacun.
6. Tout endpoint fonctionnel est enregistré dans `validated_endpoints.txt` au format `endpoint|port|user|password`.

## Fichiers produits

- `validated_endpoints.txt` : endpoints sécurisés trouvés.
- `*.txt` générés par `sub.py` (liste des sous-domaines). Ceux-ci sont ignorés par git.

## Remarques

- Les tests TLS s'exécutent même si le certificat est invalide afin d'extraire CN/SAN.
- Les identifiants sont utilisés tels quels pour des envois de test ; utilisez des comptes dédiés.
