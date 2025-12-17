# smtp-tls-hunt

Script unique `smtp-tls-test.py` pour valider des endpoints SMTP en TLS, gérer les problèmes de certificat et tester automatiquement des sous-domaines.

## Installation

- Python 3.10+
- Installer la dépendance requise par `sub.py` (pour l'énumération) :
  ```bash
  pip install requests
  ```

## Utilisation

1. Placez vos entrées dans `smtps.txt` (même dossier) au format :
   ```
   smtpserver|port|username|password
   ```
   Exemple :
   ```
   smtp.gmail.com|465|goferconfirmation@gmail.com|Mfdn$9136
   ```
2. Lancez :
   ```
   python smtp-tls-test.py
   ```
3. Le script demande l'adresse email de destination pour les envois de test, puis traite chaque ligne :
   - Test TLS avec l'endpoint fourni.
   - En cas d'erreur de certificat/hostname, il récupère les SAN/CN du certificat et les teste comme endpoints.
   - Si aucun SAN ne fonctionne, il lance `python sub.py <domaine_certifie>` pour générer `<domaine_certifie>.txt`, puis teste chaque sous-domaine en TLS.

## Résultats produits

- `validated_endpoints.txt` : endpoints sécurisés trouvés, même format que l'entrée (`endpoint_secure|port|user|pass`).
- `smtp.log` : journal JSONL détaillant les étapes (`initial_tls_test`, `extract_cert_names`, `run_sub_enum`, `tls_hunt_endpoints`).

## Sécurité

Les identifiants sont utilisés tels quels pour les tests d'envoi. Ne placez dans `smtps.txt` que des comptes destinés à ces vérifications.
