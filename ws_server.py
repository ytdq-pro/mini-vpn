"""Serveur VPN en WebSocket (pour Render et autres hébergeurs HTTP).

Variables d'environnement :
  PASSWORD : mot de passe partagé (obligatoire)
  PORT     : port d'écoute (fourni automatiquement par Render)
"""
import asyncio
import http
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from websockets.asyncio.server import serve

from common import derive_key
from ws_common import relay, seal, unseal


def health_check(connection, request):
    """Répond 200 aux requêtes HTTP normales (vérification de santé Render)."""
    if request.headers.get("Upgrade", "").lower() != "websocket":
        return connection.respond(http.HTTPStatus.OK, "Mini VPN OK\n")
    return None


async def handler(ws, aes):
    peer = ws.remote_address
    try:
        request = unseal(aes, await asyncio.wait_for(ws.recv(), 10)).decode()
        host, port = request.rsplit(":", 1)
        remote_r, remote_w = await asyncio.wait_for(
            asyncio.open_connection(host, int(port)), 10)
    except Exception as e:
        print(f"[!] {peer} refusé/échec : {type(e).__name__}", flush=True)
        try:
            await ws.send(seal(aes, b"\x01"))
            await ws.close()
        except Exception:
            pass
        return
    print(f"[+] {peer} -> {host}:{port}", flush=True)
    await ws.send(seal(aes, b"\x00"))
    await relay(ws, remote_r, remote_w, aes)


async def main():
    password = os.environ.get("PASSWORD")
    if not password:
        sys.exit("Définissez la variable d'environnement PASSWORD.")
    aes = AESGCM(derive_key(password))
    port = int(os.environ.get("PORT", "8765"))
    async with serve(lambda ws: handler(ws, aes), "0.0.0.0", port,
                     process_request=health_check):
        print(f"Serveur VPN WebSocket en écoute sur le port {port}", flush=True)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
