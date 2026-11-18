"""Tests del compilador del feed ET (`build_et_rsc.py`)."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import build_et_rsc as b  # noqa: E402

SAMPLE = """\
# comentario de cabecera
1.10.16.1
1.10.16.2

2.2.2.0/24  ; red comprometida
3.3.3.3 # inline
10.0.0.1
192.168.1.5
127.0.0.1
224.0.0.1
2001:db8::1
no-es-una-ip
5.5.5.5,
1.10.16.1
"""


def test_clean_line():
    assert b.clean_line("  1.2.3.4  ") == "1.2.3.4"
    assert b.clean_line("# solo comentario") == ""
    assert b.clean_line("") == ""
    assert b.clean_line("1.2.3.0/24 ; spam") == "1.2.3.0/24"


def test_parse_feed_keeps_only_public_ipv4():
    networks = b.parse_feed(SAMPLE)
    assert ipaddress.ip_network("1.10.16.1/32") in networks
    assert ipaddress.ip_network("2.2.2.0/24") in networks
    assert ipaddress.ip_network("3.3.3.3/32") in networks
    assert ipaddress.ip_network("5.5.5.5/32") in networks
    for forbidden in ("10.0.0.1/32", "192.168.1.5/32", "127.0.0.1/32", "224.0.0.1/32"):
        assert ipaddress.ip_network(forbidden) not in networks


def test_parse_feed_deduplicates():
    networks = b.parse_feed("1.10.16.1\n1.10.16.1\n")
    assert len(networks) == 1


def test_normalize_collapses_and_sorts():
    networks = {
        ipaddress.ip_network("9.9.9.0/24"),
        ipaddress.ip_network("1.0.0.0/8"),
        ipaddress.ip_network("1.2.0.0/16"),
    }
    ordered = b.normalize(networks)
    assert ordered == [ipaddress.ip_network("1.0.0.0/8"), ipaddress.ip_network("9.9.9.0/24")]


def test_build_rsc_marks_and_counts():
    networks = b.parse_feed(SAMPLE)
    rsc = b.build_rsc(networks, stamp="2026-11-16T00:00:00Z")
    adds = [line for line in rsc.splitlines() if line.startswith("/ip firewall address-list add")]
    assert len(adds) == len(b.normalize(networks))
    assert rsc.count("realizado por megatron") >= 2
    assert "# entradas: 5" in rsc
    assert ":global ipsEtCount 5" in rsc
    assert '"ips_megatron_et_a"' in rsc
    assert '"ips_megatron_et_b"' in rsc
    # la lista destino se limpia antes de rellenarla
    assert '/ip firewall address-list remove [find where list=$ipsEtTarget]' in rsc
    # los globales de control van al final
    assert rsc.rstrip().endswith(":global ipsEtCount 5")


def test_build_rsc_is_deterministic():
    one = b.parse_feed(SAMPLE)
    two = set(reversed(list(one)))
    assert b.build_rsc(one, stamp="X") == b.build_rsc(two, stamp="X")


def test_rsc_is_pure_ascii():
    rsc = b.build_rsc(b.parse_feed(SAMPLE), stamp="2026-11-16T00:00:00Z")
    rsc.encode("ascii")  # RouterOS importa sin sorpresas de codificacion


def test_main_publishes_files(tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text(SAMPLE.replace("no-es-una-ip", "6.6.6.6"), encoding="utf-8")
    out = tmp_path / "et-megatron.rsc"
    meta = tmp_path / "et-megatron.json"
    code = b.main(
        [
            "--input", str(feed),
            "--out", str(out),
            "--json", str(meta),
            "--min", "1",
        ]
    )
    assert code == 0
    assert out.exists() and meta.exists()
    payload = meta.read_text(encoding="utf-8")
    assert '"count": 6' in payload
    assert "realizado por megatron" in payload


def test_main_refuses_small_feed(tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text("1.10.16.1\n", encoding="utf-8")
    out = tmp_path / "et-megatron.rsc"
    code = b.main(["--input", str(feed), "--out", str(out), "--min", "100"])
    assert code == 3
    assert not out.exists()


def test_main_refuses_huge_feed(tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text("\n".join(f"8.{a}.{c}.1" for a in range(1, 6) for c in range(1, 6)), encoding="utf-8")
    out = tmp_path / "et-megatron.rsc"
    code = b.main(["--input", str(feed), "--out", str(out), "--max", "3", "--min", "1"])
    assert code == 4
    assert not out.exists()
