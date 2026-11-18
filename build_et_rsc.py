#!/usr/bin/env python3
"""Compila el feed de IPs comprometidas de Emerging Threats en un `.rsc`.

El router importa el fichero tal cual: no necesita parsear nada, que es
justo lo que RouterOS 6.x no puede hacer (solo expone los primeros 4095
bytes de un fichero).  Cada dia un cron descarga el feed, lo sanea y publica
`et-megatron.rsc`; el router hace `/tool fetch` + `/import` y listo.

Salvaguardas:

* solo redes IPv4 publicas (fuera bogons, RFC1918, multicast y reservadas);
* se colapsan solapamientos y se ordena de forma determinista (diffs limpios);
* si el feed trae menos de ``--min`` o mas de ``--max`` redes, el script
  falla y **no** publica nada, asi el router conserva la lista anterior.

Todo lo generado lleva el sello ``realizado por megatron``.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

FEED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
TAG = "realizado por megatron"
LIST_A = "ips_megatron_et_a"
LIST_B = "ips_megatron_et_b"
MIN_ENTRIES = 100
MAX_ENTRIES = 5000
USER_AGENT = "ips-megatron-et-feed/1.0 (+routeros)"


# --------------------------------------------------------------------------
# Parseo
# --------------------------------------------------------------------------


def clean_line(raw: str) -> str:
    """Quita comentarios y espacios de una linea del feed."""
    line = raw.strip().lstrip("\ufeff")
    if not line or line.startswith(("#", ";", "//", "!")):
        return ""
    for marker in ("#", ";", "//", ","):
        index = line.find(marker)
        if index != -1:
            line = line[:index]
    return line.strip().strip("\"'")


def _usable(net: ipaddress.IPv4Network) -> bool:
    return (
        net.version == 4
        and net.is_global
        and not net.is_multicast
        and not net.is_private
        and not net.is_reserved
        and not net.is_loopback
        and not net.is_link_local
    )


def parse_feed(text: str) -> set[ipaddress.IPv4Network]:
    """Devuelve el conjunto de redes IPv4 publicas del feed."""
    networks: set[ipaddress.IPv4Network] = set()
    for raw in text.splitlines():
        line = clean_line(raw)
        if not line:
            continue
        token = line.split()[0]
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if _usable(network):
            networks.add(network)
    return networks


def normalize(
    networks: Iterable[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    """Colapsa solapamientos y devuelve un orden estable."""
    collapsed = ipaddress.collapse_addresses(sorted(networks))
    return sorted(collapsed, key=lambda net: (int(net.network_address), net.prefixlen))


# --------------------------------------------------------------------------
# Generacion del .rsc
# --------------------------------------------------------------------------


def build_rsc(
    networks: Iterable[ipaddress.IPv4Network],
    *,
    stamp: str,
    source: str = FEED_URL,
) -> str:
    """Genera el script RouterOS que llena la lista en espera."""
    ordered = normalize(networks)
    count = len(ordered)
    lines = [
        f"# IPS-MEGATRON ET compromised - {TAG}",
        f"# fuente: {source}",
        f"# generado: {stamp}",
        f"# entradas: {count}",
        f"# destino: {LIST_A} o {LIST_B} (se elige la lista vacia al importar)",
        f':global ipsEtTarget "{LIST_A}"',
        (
            f':if ([:len [/ip firewall address-list find where list="{LIST_A}"]] > 0) '
            f'do={{ :set ipsEtTarget "{LIST_B}" }}'
        ),
        "/ip firewall address-list remove [find where list=$ipsEtTarget]",
    ]
    for network in ordered:
        lines.append(f"/ip firewall address-list add list=$ipsEtTarget address={network}")
    lines.extend(
        [
            "",
            f"# {TAG}",
            "# se escriben al final: si la importacion se corta, el router lo detecta",
            f':global ipsEtGenerated "{stamp}"',
            f':global ipsEtSource "{source}"',
            f":global ipsEtCount {count}",
            "",
        ]
    )
    return "\n".join(lines)


def build_metadata(
    *,
    stamp: str,
    source: str,
    count: int,
    rsc: str,
    feed_bytes: int,
    feed_sha256: str,
) -> dict:
    return {
        "generated": stamp,
        "source": source,
        "count": count,
        "feed_bytes": feed_bytes,
        "feed_sha256": feed_sha256,
        "rsc_sha256": hashlib.sha256(rsc.encode("utf-8")).hexdigest(),
        "tag": TAG,
    }


# --------------------------------------------------------------------------
# Descarga y CLI
# --------------------------------------------------------------------------


def fetch(url: str, timeout: float = 30.0) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain,*/*",
            "Accept-Encoding": "identity",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=f"Feed ET -> .rsc ({TAG})")
    parser.add_argument("--url", default=FEED_URL)
    parser.add_argument("--out", default="et-megatron.rsc")
    parser.add_argument("--json", default="et-megatron.json")
    parser.add_argument("--input", default=None, help="fichero local en vez de descargar")
    parser.add_argument("--min", type=int, default=MIN_ENTRIES, dest="min_entries")
    parser.add_argument("--max", type=int, default=MAX_ENTRIES, dest="max_entries")
    parser.add_argument("--stamp", default=None, help="fecha ISO (por defecto ahora)")
    args = parser.parse_args(argv)

    try:
        if args.input:
            data = Path(args.input).read_bytes()
        else:
            data = fetch(args.url)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"ERROR descargando {args.url}: {exc}", file=sys.stderr)
        return 2

    networks = parse_feed(data.decode("utf-8", errors="replace"))
    ordered = normalize(networks)
    count = len(ordered)
    if count < args.min_entries:
        print(
            f"ERROR: solo {count} redes validas (minimo {args.min_entries}); "
            "feed roto o vacio, no se publica nada",
            file=sys.stderr,
        )
        return 3
    if count > args.max_entries:
        print(
            f"ERROR: {count} redes supera el maximo {args.max_entries}; "
            "revisar el feed antes de publicar",
            file=sys.stderr,
        )
        return 4

    stamp = args.stamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rsc = build_rsc(ordered, stamp=stamp, source=args.url)

    out = Path(args.out)
    out.write_text(rsc, encoding="utf-8", newline="\n")
    if args.json:
        metadata = build_metadata(
            stamp=stamp,
            source=args.url,
            count=count,
            rsc=rsc,
            feed_bytes=len(data),
            feed_sha256=hashlib.sha256(data).hexdigest(),
        )
        Path(args.json).write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    print(f"{count} redes -> {out} ({len(rsc)} bytes) - {TAG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
