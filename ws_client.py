"""Client VPN WebSocket : proxy SOCKS5 local -> tunnel chiffré -> serveur.

Usage :
  python ws_client.py --url wss://MON-APP.onrender.com --password MOTDEPASSE
Puis réglez le navigateur sur SOCKS5 127.0.0.1:1080
"""
import argparse
import asyncio
import ipaddress
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from websockets.asyncio.client import connect

from common import derive_key
from ws_common import relay, seal, unseal


async def handle(reader, writer, args, aes):
    try:
        # --- Poignée de main SOCKS5 ---
        ver, nmethods = await reader.readexactly(2)
        await reader.readexactly(nmethods)
        if ver != 5:
            return writer.close()
        writer.write(b"\x05\x00")

        ver, cmd, _, atyp = await reader.readexactly(4)
        if cmd != 1:
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return writer.close()
        if atyp == 1:
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
        elif atyp == 3:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode()
        elif atyp == 4:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        else:
            return writer.close()
        (port,) = struct.unpack("!H", await reader.readexactly(2))

        # --- Connexion au serveur (le 1er appel peut durer ~1 min si Render dort) ---
        async with connect(args.url, open_timeout=90) as ws:
            await ws.send(seal(aes, f"{host}:{port}".encode()))
            status = unseal(aes, await asyncio.wait_for(ws.recv(), 20))
            if status != b"\x00":
                writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)
                return writer.close()
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()
            await relay(ws, reader, writer, aes)
    except Exception as e:
        print(f"[!] erreur : {type(e).__name__}: {e}", flush=True)
        try:
            writer.close()
        except Exception:
            pass


async def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True,
                   help="ex : wss://mon-app.onrender.com (ws://127.0.0.1:8765 en local)")
    p.add_argument("--listen-port", type=int, default=1080)
    p.add_argument("--password", default=os.environ.get("PASSWORD"))
    a = p.parse_args()
    if not a.password:
        raise SystemExit("Indiquez --password ou la variable PASSWORD.")
    aes = AESGCM(derive_key(a.password))
    srv = await asyncio.start_server(
        lambda r, w: handle(r, w, a, aes), "127.0.0.1", a.listen_port)
    print(f"Proxy SOCKS5 local : 127.0.0.1:{a.listen_port} -> {a.url}", flush=True)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
