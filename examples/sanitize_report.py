#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
実レポート(raw_report.txt)を匿名化して anonymized_report.md を生成するツール
"""
import re
from pathlib import Path

SRC = Path("examples/raw_report.txt")
DST = Path("examples/anonymized_report.md")

def sanitize(text: str) -> str:
    # 会社名（株式会社◯◯）→ ACME株式会社
    text = re.sub(r"株式会社[一-龠ぁ-んァ-ンA-Za-z0-9]+", "ACME株式会社", text)

    # スキャン元IP（先に置換）: \g<1> でキャプチャ参照を明示
    text = re.sub(
        r"(スキャン元IPアドレス[\s:]*)(\b\d{1,3}(?:\.\d{1,3}){3}\b)",
        r"\g<1>198.51.100.5",
        text,
    )


    # ※ 少なくとも1文字は英字を含むことを要求して、IPのような数値だけの並びは除外
    def to_example_domain(m: re.Match) -> str:
        parts = m.group(0).split(".")
        return (parts[0] + ".example.com") if len(parts) >= 3 else "example.com"

    domain_pattern = r"(?=[A-Za-z0-9.-]*[A-Za-z][A-Za-z0-9.-]*)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
    text = re.sub(domain_pattern, to_example_domain, text)

    # それ以外のIP → 203.0.113.10
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "203.0.113.10", text)

    return text

def main() -> None:
    if not SRC.exists():
        raise SystemExit("examples/raw_report.txt がありません。")
    raw = SRC.read_text(encoding="utf-8")
    out = sanitize(raw).strip()

    md = f"# ORG2VULN REPORT (Anonymized Sample)\n\n```\n{out}\n```\n"
    DST.write_text(md, encoding="utf-8")
    print(f"Sanitized -> {DST}")

if __name__ == "__main__":
    main()
