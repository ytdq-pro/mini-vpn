"""Serveur VPN en WebSocket (pour Render et autres hébergeurs HTTP).

Ce fichier est autonome : il ne dépend d'aucun autre fichier du projet.

Variables d'environnement :
  PASSWORD : mot de passe partagé (obligatoire)
  PORT     : port d'écoute (fourni automatiquement par Render)
"""
import asyncio
import hashlib
import http
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from websockets.asyncio.server import serve


def derive_key(password: str) -> bytes:
    """Dérive une clé AES-256 à partir du mot de passe partagé."""
    return hashlib.scrypt(password.encode(), salt=b"mini-vpn-v1",
                          n=2**14, r=8, p=1, dklen=32)


def seal(aes: AESGCM, data: bytes) -> bytes:
    """Chiffre un message : nonce (12 octets) + données chiffrées."""
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, data, None)


def unseal(aes: AESGCM, blob) -> bytes:
    """Déchiffre un message (erreur si le mot de passe est faux)."""
    if isinstance(blob, str) or len(blob) < 28:
        raise ValueError("message invalide")
    return aes.decrypt(bytes(blob[:12]), bytes(blob[12:]), None)


async def relay(ws, reader, writer, aes: AESGCM):
    """Relaie les données entre un socket clair et le WebSocket chiffré."""

    async def clear_to_ws():
        try:
            while True:
                data = await reader.read(32768)
                await ws.send(seal(aes, data))  # message vide = fin
                if not data:
                    break
        except Exception:
            pass

    async def ws_to_clear():
        try:
            async for msg in ws:
                data = unseal(aes, msg)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass

    tasks = [asyncio.create_task(clear_to_ws()),
             asyncio.create_task(ws_to_clear())]
    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in tasks:
        t.cancel()
    try:
        writer.close()
    except Exception:
        pass
    try:
        await ws.close()
    except Exception:
        pass


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
