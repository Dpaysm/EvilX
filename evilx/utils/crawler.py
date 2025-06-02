import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from rich.console import Console
from rich.progress import Progress

console = Console()

class Crawler:
    def __init__(self, session, headers, rate_limiter=None):
        self.session = session
        self.headers = headers
        self.rate_limiter = rate_limiter
        self.visited = set()
        self.collected_links = set()

    def is_same_domain(self, start_url, new_url):
        from urllib.parse import urlparse
        return urlparse(start_url).netloc == urlparse(new_url).netloc

    def crawl(self, url, depth=2, recursive=False, timeout=10, verbosity_level=1):
        queue = [(url, depth)]
        log_output = []
        self.visited.clear()
        self.collected_links.clear()

        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=None)

            while queue:
                current_url, current_depth = queue.pop(0)
                if current_depth == 0 or current_url in self.visited:
                    continue

                if verbosity_level:
                    console.print(f"[bold green][+] Scanning:[/bold green] {current_url}")
                self.visited.add(current_url)
                found = set()

                try:
                    if self.rate_limiter:
                        self.rate_limiter.wait()
                    
                    response = self.session.get(current_url, headers=self.headers, timeout=timeout)
                    soup = BeautifulSoup(response.text, "html.parser")
                    
                    for tag in soup.find_all(["a", "link", "script", "iframe", "form"]):
                        href = tag.get("href") or tag.get("src") or tag.get("action")
                        if href:
                            full_url = urljoin(current_url, href)
                            if full_url not in self.collected_links and self.is_same_domain(current_url, full_url):
                                self.collected_links.add(full_url)
                                found.add(full_url)
                                queue.append((full_url, current_depth - 1))

                    if verbosity_level:
                        console.print(f"[blue][🔗] Links found:[/blue] {len(found)}")
                    else:
                        progress.update(task, description=f"[cyan]Scanning: {current_url} ({len(found)} links)")

                    log_output.append(f"{current_url} scanned. Found: {len(found)} links\n")

                except Exception as e:
                    console.print(f"[red][-] Error scanning {current_url}: {str(e)}[/red]")
                    continue

        return log_output, self.collected_links
