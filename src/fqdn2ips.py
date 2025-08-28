#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import sys
from typing import List
from dns.resolver import Resolver
from dns.exception import DNSException
import argparse
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


def resolve_fqdn_to_ip(fqdn: str) -> List[str]:
    resolver = Resolver()
    resolver.nameservers = ["1.1.1.1"]
    ips: List[str] = []
    try:
        for rtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(fqdn, rtype)
                for rr in answers:
                    ips.append(rr.to_text())
            except DNSException:
                pass
    except DNSException as e:
        log.warning(f"DNS解決エラー: {e}")
    return ips


def fqdn2ips(fqdn: str) -> List[str]:
    return resolve_fqdn_to_ip(fqdn)


def _print_result(fqdn: str, ips: List[str]) -> None:
    if ips:
        for ip in ips:
            print(f"{fqdn}\t{ip}")
    else:
        print(f"{fqdn}\t解決できませんでした")


def main() -> None:
    p = argparse.ArgumentParser(description="FQDN を IP に解決")
    p.add_argument("--fqdn", help="単一の FQDN を指定")
    args = p.parse_args()

    if args.fqdn:
        _print_result(args.fqdn.strip(), fqdn2ips(args.fqdn.strip()))
        return

    if not sys.stdin.isatty():
        for line in sys.stdin:
            fqdn = line.strip()
            if fqdn:
                _print_result(fqdn, fqdn2ips(fqdn))
        return

    #1件ごとに即解決
    while True:
        fqdn = input("FQDNを入力してください (終了は 'quit'): ").strip()
        if fqdn.lower() == "quit":
            break
        if fqdn:
            _print_result(fqdn, fqdn2ips(fqdn))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Resolve FQDN to IP addresses (A/AAAA)")
    parser.add_argument("--fqdn", help="Target FQDN (e.g. www.example.com)")
    args = parser.parse_args()

    if args.fqdn:
        ips = resolve_fqdn_to_ip(args.fqdn)
        if ips:
            print("\n".join(ips))
        else:
            print("IPアドレスが見つかりませんでした")
    else:
        # 対話式（従来どおり）
        try:
            while True:
                fqdn = input("FQDNを入力してください (終了は 'quit'): ").strip()
                if fqdn.lower() == "quit":
                    break
                if not fqdn:
                    continue
                ips = resolve_fqdn_to_ip(fqdn)
                if ips:
                    print("\n".join(ips))
                else:
                    print("IPアドレスが見つかりませんでした")
        except (KeyboardInterrupt, EOFError):
            pass
