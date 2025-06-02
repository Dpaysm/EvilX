from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import tldextract
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.progress import Progress

console = Console()

class Scanner:
    def __init__(self, session, headers, rate_limiter=None):
        self.session = session
        self.headers = headers
        self.rate_limiter = rate_limiter

    def extract_domain(self, url):
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}"

    def is_redirect_param(self, param_name):
        redirect_keywords = ['url', 'next', 'redirect', 'target', 'dest', 'redir', 'return', 'goto']
        return any(key in param_name.lower() for key in redirect_keywords)

    def find_open_redirect_candidates(self, links, base_domain):
        candidates = []
        for link in links:
            parsed = urlparse(link)
            query = parse_qs(parsed.query)
            for param, values in query.items():
                if self.is_redirect_param(param):
                    for value in values:
                        dest_domain = self.extract_domain(value)
                        if dest_domain and dest_domain != base_domain:
                            candidates.append(link)
                            break
        return candidates

    def test_single_payload(self, url, payload):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        modified = False
        
        for param in query:
            if self.is_redirect_param(param):
                query[param] = [payload]
                modified = True
                
        if not modified:
            return None
            
        new_query = urlencode(query, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        try:
            response = self.session.get(new_url, headers=self.headers, allow_redirects=False, timeout=5)
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("Location", "")
                if payload in location:
                    return {
                        "url": new_url,
                        "payload": payload,
                        "code": response.status_code
                    }
        except:
            pass
        return None

    def run_tests(self, urls, payloads=None, threads=5):
        if not payloads:
            payloads = [
                "https://evil.com",
                "//evil.com",
                "https:evil.com",
                "javascript://alert(1)",
                "data:text/html,<script>alert(1)</script>"
            ]
        
        vulnerable = []
        
        with Progress() as progress:
            task = progress.add_task("Testing...", total=len(urls))

            def check(url):
                if self.rate_limiter:
                    self.rate_limiter.wait()
                for payload in payloads:
                    result = self.test_single_payload(url, payload)
                    if result:
                        console.print(f"[red][⚠️] VULNERABILITY FOUND:[/red] {result['url']}")
                        vulnerable.append(result)
                progress.update(task, advance=1)

            with ThreadPoolExecutor(max_workers=threads) as executor:
                executor.map(check, urls)

        return vulnerable
