# ORG2VULN REPORT (Anonymized Sample)

作成日：2025-08-14

---

## ORG2VULN Scan Info
本レポートは、ORG2VULNスキャン結果をまとめたものです。  
ORG2VULNスキャンはキーワード「ACME株式会社」を元に、該当企業および関連企業のドメイン探索と脆弱性検出を行いました。  
以下に詳細なスキャン情報を記載します。

- スキャンに用いたキーワード: ACME株式会社
- 日時: 2025-08-14
- スキャン元IPアドレス: 198.51.100.5

スコープ:
- ドメイン数: 1
- FQDN数: 3
- 脆弱性発見数: 2

---

## ORG2VULN Results

### 組織名
ACME株式会社

### ドメイン
example.com

---

### FQDN: example.com
- IPアドレス: 203.0.113.10
- プロダクト: apache http_server
- CVE: N/A

---

### FQDN: example.com
- IPアドレス: 203.0.113.10
- プロダクト: apache httpd
- CVE: N/A

---

### FQDN: mx.example.com
- IPアドレス: 203.0.113.10
- プロダクト: postfix_admin_project / postfix_admin
- CVE: CVE-2014-2655, CVE-2012-0812

---

### FQDN: www.example.com
- IPアドレス: 203.0.113.10
- プロダクト: apache http_server / httpd
- CVE: N/A

---

## まとめ
対象ドメインから計 3 件のFQDNを探索し、2 件の既知の脆弱性（CVE）に該当する構成を確認しました。  
本レポートは **匿名化済みサンプル** であり、実在の企業・環境とは一切関係ありません。
