#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import socket
import time
import logging
from typing import Set, List, Dict, Optional
from urllib.parse import quote
from pathlib import Path

import dns.resolver
import requests

# .env をリポジトリ直下から読込
try:
    from dotenv import load_dotenv
    ROOT = Path(__file__).resolve().parents[1]
    load_dotenv(ROOT / ".env")
except Exception:
    pass

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY") or None


class DomainEnumerator:
    """委任サブドメインとFQDNを再帰的に列挙する"""

    #よく使われる委任サブドメイン名
    DELEGATION_LABELS = [
        "dev", "test", "stage", "staging", "beta", "admin", "portal",
        "vpn", "intra", "internal", "cdn", "static", "img", "assets",
        "app", "api", "auth", "shop", "store", "blog",
    ]
    #各ゾーン直下でよく見られるホスト名
    HOST_LABELS = ["www", "mail", "mx", "smtp", "imap", "pop3", "ns1", "ns2"]

    def __init__(self, domain: str, shodan_api_key: Optional[str] = None) -> None:
        self.root = self._norm(domain)
        self.api_key = shodan_api_key
        self.subdomains: Set[str] = set()
        self.fqdns: Set[str] = set()
        self.visited: Set[str] = set()

    @staticmethod
    def _norm(name: str) -> str:
        return str(name).strip().rstrip(".").lower()

    # --- DNS解決 ---

    def _resolve(self, host: str, rtype: str) -> List[str]:
        """DNS解決。A/AAAAはsocket、その他はdnspythonを利用"""
        host = self._norm(host)
        if not host:
            return []
        if rtype in ("A", "AAAA"):
            try:
                fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
                res = socket.getaddrinfo(host, None, fam, socket.SOCK_STREAM)
                return sorted({x[4][0] for x in res})
            except Exception:
                pass
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 6
            ans = resolver.resolve(host, rtype, raise_on_no_answer=False)
            return [str(r).strip() for r in ans] if ans.rrset else []
        except Exception:
            return []

    def _exists(self, host: str) -> bool:
        return bool(self._resolve(host, "A") or self._resolve(host, "AAAA"))

    def _is_delegated(self, zone: str) -> bool:
        return bool(self._resolve(zone, "NS"))

    # --- 分類 ---

    def _add(self, host: str) -> None:
        h = self._norm(host)
        if not (h.endswith(f".{self.root}") or h == self.root):
            return

        # apexはFQDNとして扱う
        if h == self.root:
            self.fqdns.add(h)
            return

        if self._is_delegated(h):
            self.subdomains.add(h)
        else:
            self.fqdns.add(h)

    def _mx_hosts(self, mx_records: List[str]) -> Set[str]:
        out = set()
        for mx in mx_records:
            parts = mx.split()
            h = (parts[-1] if parts else mx).strip().rstrip(".").lower()
            if h and "." in h:
                out.add(h)
        return out
    
    # --- 列挙手法 ---


    def shodan_search(self, zone: str) -> None:
        """SHODAN APIを利用して候補を収集"""
        if not self.api_key:
            return
        d = self._norm(zone)
        cands: Set[str] = set()

        # /dns/domain
        try:
            url = f"https://api.shodan.io/dns/domain/{quote(d)}"
            r = requests.get(url, params={"key": self.api_key}, timeout=10)
            if r.status_code == 200:
                for sub in (r.json().get("subdomains") or []):
                    sub = str(sub).strip()
                    if sub:
                        cands.add(f"{sub}.{d}")
        except Exception as e:
            log.warning(f"SHODAN dns/domain: {e}")

        # /shodan/host/search
        try:
            for q in (f"domain:{d}", f'hostname:"*.{d}"'):
                r = requests.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": self.api_key, "query": q, "page": 1},
                    timeout=10,
                )
                if r.status_code == 200:
                    data = r.json()
                    for m in data.get("matches", []):
                        for hn in m.get("hostnames", []) or []:
                            cands.add(self._norm(hn))
                        cn = (
                            m.get("ssl", {})
                             .get("cert", {})
                             .get("subject", {})
                             .get("CN")
                        )
                        if cn:
                            cands.add(self._norm(str(cn)))
                time.sleep(1)
        except Exception as e:
            log.warning(f"SHODAN host/search: {e}")

        for h in sorted(cands):
            if (h.endswith(f".{self.root}") or h == self.root) and self._exists(h):
                self._add(h)

    def gather_dns(self, zone: str) -> None:
        """NS/MXレコードから派生ホストを収集"""
        z = self._norm(zone)
        for ns in self._resolve(z, "NS"):
            n = self._norm(ns)
            if n.endswith(f".{self.root}") or n == self.root:
                if self._exists(n):
                    self._add(n)
        for mxh in self._mx_hosts(self._resolve(z, "MX")):
            if mxh.endswith(f".{self.root}") or mxh == self.root:
                if self._exists(mxh):
                    self._add(mxh)

    def probe_delegations(self, zone: str) -> None:
        """典型的な委任サブドメインを確認"""
        z = self._norm(zone)
        for label in self.DELEGATION_LABELS:
            sub = f"{label}.{z}"
            if self._is_delegated(sub):
                self._add(sub)

    def bruteforce_hosts(self, zone: str) -> None:
        """典型的なホスト名を確認"""
        z = self._norm(zone)
        for label in self.HOST_LABELS:
            fqdn = f"{label}.{z}"
            if self._exists(fqdn):
                self._add(fqdn)

    # --- 再帰 ---

    def walk(self, zone: str, depth: int = 0) -> None:
        z = self._norm(zone)
        if z in self.visited:
            return
        self.visited.add(z)

        if depth == 0 and self.api_key:
            self.shodan_search(z)

        self.gather_dns(z)
        self.probe_delegations(z)
        self.bruteforce_hosts(z)

        if depth == 0 and self._exists(z):
            self._add(z)

        for sub in sorted(self.subdomains):
            if sub not in self.visited and sub.endswith(f".{self.root}"):
                self.walk(sub, depth + 1)

    # --- 公開API ---

    def run(self) -> Dict[str, List[str]]:
        self.subdomains.clear()
        self.fqdns.clear()
        self.visited.clear()
        self.walk(self.root, 0)
        return {
            "subdomains": sorted(self.subdomains),
            "fqdns": sorted(self.fqdns),
        }


def domain2fqdns(domain: str) -> List[str]:
    try:
        en = DomainEnumerator(domain, SHODAN_API_KEY)
        res = en.run()
        return res.get("fqdns", [])
    except Exception as e:
        log.error(f"error: {e}")
        return []


def main() -> None:
    import argparse

    p = argparse.ArgumentParser(description="FQDN列挙ツール")
    p.add_argument("--domain", help="対象ドメイン")
    p.add_argument("--demo", action="store_true", help="外部問い合わせを行わない簡易出力")
    args = p.parse_args()

    domain = (args.domain or input("対象ドメインを入力してください: ")).strip().lower().rstrip(".")

    if args.demo:
        for i, h in enumerate(sorted({domain, f"www.{domain}", f"mx.{domain}"}), 1):
            print(f"{i:2d}. {h}")
        return

    print(f"target: {domain}")
    print("-" * 40)
    out = domain2fqdns(domain)
    for i, fqdn in enumerate(sorted(out), 1):
        print(f"{i:2d}. {fqdn}")


if __name__ == "__main__":
    main()
