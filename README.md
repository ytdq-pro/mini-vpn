# Mini VPN en Python

Tunnel chiffré (AES-256-GCM, clé dérivée d'un mot de passe partagé) avec proxy SOCKS5 local.

## Installation
```
pip install -r requirements.txt
```

## Utilisation
1. Sur la machine serveur (celle dont vous voulez utiliser l'IP) :
   ```
   python server.py --password MON_MOT_DE_PASSE
   ```
   Ouvrez le port 8443 (TCP) dans le pare-feu / la box.

2. Sur votre PC :
   ```
   python client.py --server IP_DU_SERVEUR --password MON_MOT_DE_PASSE
   ```
3. Réglez votre navigateur (ou application) sur le proxy **SOCKS5 127.0.0.1 port 1080**.

Pour un test en local, utilisez `--server 127.0.0.1`.

## Version WebSocket (Render et hébergeurs HTTP)
Pour les hébergeurs qui n'acceptent que le HTTP, utilisez `ws_server.py` et `ws_client.py`.

- Serveur : variables d'environnement `PASSWORD` (obligatoire) et `PORT` (fourni par Render).
  Commande de démarrage : `python ws_server.py`
  Test local : `PASSWORD=test PORT=8765 python ws_server.py`
- Client : `python ws_client.py --url wss://MON-APP.onrender.com --password MON_MOT_DE_PASSE`
  (en local : `--url ws://127.0.0.1:8765`)
- Ensuite, proxy **SOCKS5 127.0.0.1 port 1080** dans le navigateur, comme avant.

Sur l'offre gratuite de Render, le service s'endort après 15 min sans activité :
la première connexion suivante peut prendre environ une minute.

## Limites
Projet éducatif : ce n'est pas un VPN au niveau système (seules les applications
configurées sur le proxy passent par le tunnel), il n'y a pas d'échange de clés
avec confidentialité persistante ni de protection anti-rejeu. Pour un usage
sérieux, préférez WireGuard ou OpenVPN.
