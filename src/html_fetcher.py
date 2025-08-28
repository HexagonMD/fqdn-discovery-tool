import random
import time
from typing import List, Dict
from playwright.sync_api import sync_playwright
import json
from pathlib import Path

class VirusTotalScraper:
    """VirusTotalからサブドメイン情報を取得するスクレイパー"""
    
    def __init__(self, headless: bool = False):
        """
        初期化
        Args:
            headless: ヘッドレスモードで実行するか
        """
        self.headless = headless
        self.subdomains = []
    
    def scrape_subdomains(self, domain: str) -> List[Dict[str, str]]:
        """
        指定ドメインのサブドメイン情報を取得
        
        Args:
            domain: 取得対象のドメイン名
            
        Returns:
            サブドメイン情報のリスト
        """
        url = f"https://www.virustotal.com/gui/domain/{domain}/relations"
        
        with sync_playwright() as p:
            # ブラウザ起動
            browser = p.chromium.launch(
                headless=self.headless,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-features=site-per-process',
                ]
            )
            
            # コンテキスト作成
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                locale='ja-JP',
            )
            
            # WebDriver検出を回避
            context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            """)
            
            page = context.new_page()
            
            try:
                # ページアクセス
                time.sleep(random.uniform(1, 3))
                page.goto(url, wait_until='networkidle')
                time.sleep(random.uniform(5, 7))
                
                # ページネーション処理
                pagination_count = 0
                previous_count = 0
                no_change_count = 0
                vt_button_selector = 'div > vt-ui-expandable.mb-3.subdomains > span > div > vt-ui-button'
                
                while True:
                    # 現在のサブドメイン数を確認
                    current_elements = page.query_selector_all('a[href*="/domain/"]')
                    current_count = len(current_elements)
                    
                    # 変化がない場合は終了
                    if current_count == previous_count:
                        no_change_count += 1
                        if no_change_count >= 2:
                            break
                    else:
                        no_change_count = 0
                        previous_count = current_count
                    
                    time.sleep(3)
                    
                    # ボタンクリック処理
                    button_clicked = page.evaluate(f"""
                        () => {{
                            const button = document.querySelector('{vt_button_selector}');
                            if (button && button.offsetParent !== null) {{
                                button.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                                setTimeout(() => {{ button.click(); }}, 500);
                                return true;
                            }}
                            return false;
                        }}
                    """)
                    
                    if button_clicked:
                        pagination_count += 1
                        time.sleep(5)
                    else:
                        # Playwrightで再試行
                        button = page.query_selector(vt_button_selector)
                        if button:
                            page.evaluate("""
                                (element) => {
                                    element.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                    setTimeout(() => { element.click(); }, 500);
                                }
                            """, button)
                            pagination_count += 1
                            time.sleep(5)
                        else:
                            no_change_count += 1
                            if no_change_count >= 2:
                                break
                
                # 最終スクロール
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(2)
                
                # サブドメイン収集
                all_found_domains = set()
                selectors = [
                    'a[href*="/domain/"]',
                    'table tbody tr td:first-child a',
                    '[class*="subdomain"] a',
                    'div[data-section="subdomains"] a'
                ]
                
                for selector in selectors:
                    elements = page.query_selector_all(selector)
                    for element in elements:
                        try:
                            # テキストから取得
                            text = element.inner_text().strip()
                            if (text and '.' in text and domain in text and 
                                not text.startswith('http')):
                                all_found_domains.add(text)
                            
                            # hrefから取得
                            href = element.get_attribute('href')
                            if href and '/domain/' in href:
                                domain_part = href.split('/domain/')[-1].split('/')[0]
                                if domain in domain_part and '.' in domain_part:
                                    all_found_domains.add(domain_part)
                        except:
                            pass
                
                # 結果を辞書形式に変換
                self.subdomains = [{'subdomain': subdomain} for subdomain in sorted(all_found_domains)]
                
            except Exception as e:
                print(f"エラーが発生しました: {e}")
                
            finally:
                time.sleep(random.uniform(1, 2))
                browser.close()
        
        return self.subdomains
    
    def get_subdomains_list(self) -> List[str]:
        """サブドメインのリストを取得"""
        return [item['subdomain'] for item in self.subdomains]
    
    def save_results(self, filename: str = "subdomains.json"):
        """結果をJSONファイルに保存"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.subdomains, f, ensure_ascii=False, indent=2)


def main():
    """メイン実行関数"""
    print("="*60)
    print("  VirusTotal Subdomain Scraper")
    print("="*60)
    
    # ドメイン入力
    domain = input("\n対象ドメインを入力してください (例: example.com): ").strip()
    if not domain:
        print("ドメインが入力されていません")
        return
    
    # ヘッドレスモード選択
    headless_input = input("ヘッドレスモードで実行しますか? (y/n): ").strip().lower()
    headless = headless_input == 'y'
    
    print(f"\nTarget Domain: {domain}")
    print(f"Mode: {'Headless' if headless else 'Browser Visible'}")
    print("="*60)
    
    print("\nスクレイピング実行中...")
    
    # スクレイパー実行
    scraper = VirusTotalScraper(headless=headless)
    subdomains = scraper.scrape_subdomains(domain)
    
    # 結果表示
    if subdomains:
        print(f"\n取得完了: {len(subdomains)} 個のサブドメインを発見\n")
        print("[サブドメイン一覧]")
        print("-"*60)
        
        subdomain_list = scraper.get_subdomains_list()
        for i, subdomain in enumerate(subdomain_list, 1):
            print(f"  {i:3d}. {subdomain}")
        
        # ファイル保存
        outdir = Path("artifacts")
        outdir.mkdir(exist_ok=True)
        filename = outdir / f"{domain.replace('.', '_')}_subdomains.json"
        scraper.save_results(str(filename))
        print(f"\n結果を {filename} に保存しました")
        
    else:
        print("\nサブドメインが取得できませんでした")


if __name__ == "__main__":
    main()