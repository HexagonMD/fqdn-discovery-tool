from sanitize_report import sanitize

def test_company_redact():
    text = "株式会社テスト"
    out = sanitize(text)
    assert "ACME株式会社" in out
    assert "株式会社テスト" not in out

def test_ip_redact():
    text = "サーバIP: 153.122.205.43"
    out = sanitize(text)
    assert "203.0.113.10" in out

def test_domain_redact():
    text = "www.foresight-net.co.jp"
    out = sanitize(text)
    assert "www.example.com" in out
