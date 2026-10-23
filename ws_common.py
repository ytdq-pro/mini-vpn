"""Briques communes pour la version WebSocket (chiffrement + relais)."""
import asyncio
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(password: str) -> bytes:
    """Dérive une clé AES-256 à partir du mot de passe partagé."""
    return hashlib.scrypt(password.encode(), salt=b"mini-vpn-v1",
                          n=2**14, r=8, p=1, dklen=32)


def seal(aes: AESGCM, data: bytes) -> bytes:
    """Chiffre un message : nonce (12 octets) + données chiffrées."""
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, data, None)


def unseal(aes: AESGCM, blob) -> bytes:
    """Déchiffre un message (lève une erreur si le mot de passe est faux)."""
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
