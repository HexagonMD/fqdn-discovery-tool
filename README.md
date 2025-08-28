# Security Camp 2025（担当部分）

このリポジトリは、**セキュリティキャンプ全国大会 2025** のチーム開発から、  
私が担当した **ドメイン→FQDN探索 / FQDN→IP解決 / FQDN補完（VirusTotalスクレイピング）** を  
切り出し・再構成したものです。  

実在の企業名やドメイン等の機微情報は含まれておらず、  
公開しているサンプルレポートはすべて **匿名化済み** です。

---

## プロジェクトの背景
サイバー攻撃は本社を直接狙うとは限らず、**セキュリティの弱い関連会社や海外拠点**が起点になることがあります。  
本プロジェクトでは、そうした攻撃経路を把握し、防御にも活かせる基盤を構築しました。

- **RED チーム視点** : 関連企業を足がかりに攻撃経路を探索  
- **BLUE チーム視点** : 関連企業を含めた広域の脆弱性診断を支援  

---

## 担当範囲
- **domain2fqdns.py**  
  DNS / ブルートフォース / Shodan API を用いたサブドメイン・FQDN列挙  

- **fqdn2ips.py**  
  列挙したFQDNを名前解決し、IPアドレスとISPを収集  

- **html_fetcher.py**  
  **VirusTotalをPlaywrightでスクレイピング**し、  
  DNS探索で漏れるFQDNを補完（APIキー不要）  

---

## 工夫した点
- **API不要の補完手法**  
  → Playwright を利用し、CAPTCHAを避けつつスクレイピングを実装  
- **複数手法の組み合わせ**  
  → DNS・ブルートフォース・Shodan・VTを組み合わせ、FQDN漏れを最小化  
- **再現性と公開性**  
  → 実ドメイン情報を含まない匿名化済みレポートをサンプルとして公開  

---

## 匿名化済みレポートサンプル
👉 [examples/anonymized_report.md](examples/anonymized_report.md)  

このサンプルは [examples/sanitize_report.py](examples/sanitize_report.py) により  
実レポートから自動的に匿名化して生成されています。

---

## 収録ファイル
src/
├─ domain2fqdns.py # ドメイン→FQDN探索
├─ fqdn2ips.py # FQDN→IP/ISP解決
└─ html_fetcher.py # VirusTotalスクレイピング補完
examples/
├─ sanitize_report.py # 匿名化ツール
└─ anonymized_report.md # 匿名化済みサンプルレポート
README.md # 本ファイル
requirements.txt # 必要ライブラリ
.gitignore # 除外ファイル設定


---

## SHODAN API の利用（任意）
- `.env` に `SHODAN_API_KEY` を設定すると Shodan API を用いた探索が有効になります。
- 検索結果から以下を候補に追加します:
  - **hostnames** フィールドに記録されたホスト名  
  - **SSL証明書の CN** に含まれるホスト名  
- 収集した候補は DNS 解決で存在確認を行い、  
  **NSを持つものはサブドメインとして再帰探索、持たないものはFQDNとして登録** します。  
- APIキーが無い場合でも、DNS探索とブルートフォースのみで利用可能です。  

---

## 実行例
```bash
# バーチャル環境構築
py -3 -m venv .venv

# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# Linux / Mac
source .venv/bin/activate

# 必要ライブラリインストール
pip install -r requirements.txt

# Playwright のブラウザ（初回のみ）
python -m playwright install chromium

# FQDN探索
python src/domain2fqdns.py --demo --domain example.com

# VirusTotal補完（ブラウザ表示モード推奨）
python src/html_fetcher.py --domain example.com
# ※ CAPTCHA/ログイン表示時は headless を切って画面で操作:
# python src/html_fetcher.py --domain example.com --debug

# FQDNからIP解決
python src/fqdn2ips.py --fqdn example.com
