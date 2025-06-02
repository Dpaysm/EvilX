import argparse
import json
import os
import signal
import sys
from datetime import datetime
import requests
from rich.console import Console
from utils.crawler import Crawler
from utils.scanner import Scanner
from utils.reporter import Reporter

# Initialize console
console = Console()

# Global variables
cancel_scan = False
verbosity_level = 1

class ScanStats:
    def __init__(self):
        self.start_time = datetime.now()
        self.urls_scanned = 0
        self.vulnerabilities_found = 0
        self.errors_encountered = 0
        self.redirects_found = 0

    def get_duration(self):
        return datetime.now() - self.start_time

class RateLimiter:
    def __init__(self, requests_per_second):
        self.delay = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self.last_request = 0

    def wait(self):
        if self.delay > 0:
            now = time.time()
            if self.last_request + self.delay > now:
                time.sleep(self.last_request + self.delay - now)
            self.last_request = time.time()

def show_banner():
    banner = """
    ╔═══════════════════════════════════════════╗
    ║             EVILX SCANNER                  ║
    ║     Open Redirect Vulnerability Scanner    ║
    ║              Version 2.0                   ║
    ╚═══════════════════════════════════════════╝
    """
    console.print(f"[cyan]{banner}[/cyan]")

def signal_handler(signum, frame):
    global cancel_scan
    if not cancel_scan:
        cancel_scan = True
        console.print("\n[yellow]⚠️ Interrupt received. Gracefully shutting down...[/yellow]")
        choice = console.input("\n[bold]Choose action ([c]ontinue/[s]kip/[e]xit): [/bold]").lower()
        if choice == 'c':
            cancel_scan = False
            return
        elif choice == 's':
            return
        else:
            console.print("[red]Exiting...[/red]")
            sys.exit(0)

def get_session(proxy=None):
    session = requests.Session()
    if proxy:
        session.proxies = {
            "http": proxy,
            "https": proxy
        }
    return session

def load_config():
    try:
        with open('config/config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        console.print("[red]Error: config/config.json not found[/red]")
        sys.exit(1)
    except json.JSONDecodeError:
        console.print("[red]Error: Invalid JSON in config/config.json[/red]")
        sys.exit(1)

def load_payloads(custom_payloads_file=None):
    if custom_payloads_file:
        try:
            with open(custom_payloads_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[yellow]Warning: Custom payloads file not found, using default payloads[/yellow]")

    try:
        with open('config/payloads.txt', 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print("[red]Error: config/payloads.txt not found[/red]")
        return [
            "https://evil.com",
            "//evil.com",
            "https:evil.com",
            "javascript://alert(1)",
            "data:text/html,<script>alert(1)</script>"
        ]

def process_url(url, args, session, config, stats):
    console.print(f"\n[bold cyan][+] Processing: {url}[/bold cyan]")
    
    # Initialize components
    rate_limiter = RateLimiter(args.rate_limit) if args.rate_limit > 0 else None
    crawler = Crawler(session, args.headers, rate_limiter)
    scanner = Scanner(session, args.headers, rate_limiter)
    reporter = Reporter(stats)

    try:
        # Crawl the URL
        log_output, collected_links = crawler.crawl(
            url, 
            depth=args.depth,
            recursive=bool(args.x),
            timeout=args.timeout,
            verbosity_level=args.v
        )

        stats.urls_scanned += len(collected_links)

        # Find redirect candidates
        base_domain = scanner.extract_domain(url)
        candidates = scanner.find_open_redirect_candidates(collected_links, base_domain)
        
        if candidates:
            console.print(f"[green][+] Found {len(candidates)} potential redirect endpoints[/green]")
            
            # Load payloads
            payloads = load_payloads(args.custom_payloads)
            
            # Test candidates
            vulnerable_urls = scanner.run_tests(candidates, payloads, args.threads)
            stats.vulnerabilities_found += len(vulnerable_urls)
            
            # Export results
            if vulnerable_urls:
                reporter.export_results(vulnerable_urls, args.format)
        
        return True

    except Exception as e:
        console.print(f"[red][-] Error processing {url}: {str(e)}[/red]")
        stats.errors_encountered += 1
        return False

def main():
    global verbosity_level, cancel_scan

    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Show banner
    show_banner()

    # Load configuration
    config = load_config()

    # Parse arguments
    parser = argparse.ArgumentParser(prog="evilx", description="[EVILX] Open Redirect Vulnerability Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target URL")
    group.add_argument("-l", "--list", help="File containing multiple URLs")
    parser.add_argument("-d", "--depth", type=int, default=config.get('default_depth', 2), help="Crawling depth")
    parser.add_argument("-t", "--threads", type=int, default=config.get('default_threads', 5), help="Number of threads")
    parser.add_argument("-x", type=int, choices=[0,1], default=0, help="Scan subpages (1/0)")
    parser.add_argument("-v", type=int, choices=[0,1], default=1, help="Verbosity level")
    parser.add_argument("--headers", help="Headers JSON string or file path")
    parser.add_argument("--timeout", type=int, default=config.get('default_timeout', 10), help="Request timeout in seconds")
    parser.add_argument("--rate-limit", type=float, default=config.get('rate_limit', 0), help="Requests per second (0 for no limit)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--format", choices=["txt", "json", "csv"], default="txt", help="Export format")
    parser.add_argument("--custom-payloads", help="File containing custom payloads")

    args = parser.parse_args()
    verbosity_level = args.v

    # Initialize statistics
    stats = ScanStats()

    try:
        # Process headers
        if args.headers:
            if os.path.isfile(args.headers):
                with open(args.headers) as f:
                    args.headers = json.load(f)
            else:
                args.headers = json.loads(args.headers)
        else:
            args.headers = {}

        # Create session
        session = get_session(args.proxy)

        # Create output directory if it doesn't exist
        os.makedirs('output', exist_ok=True)

        # Process URLs
        if args.url:
            process_url(args.url, args, session, config, stats)
        elif args.list:
            try:
                with open(args.list, "r") as file:
                    urls = [line.strip() for line in file if line.strip()]
                for url in urls:
                    if cancel_scan:
                        break
                    process_url(url, args, session, config, stats)
            except FileNotFoundError:
                console.print(f"[red][-] File not found:[/red] {args.list}")
                return

        # Generate final report
        reporter = Reporter(stats)
        reporter.generate_summary_report()

    except KeyboardInterrupt:
        console.print("\n[red]Scan terminated by user.[/red]")
    except Exception as e:
        console.print(f"[red][-] An error occurred: {str(e)}[/red]")
    finally:
        if cancel_scan:
            console.print("[yellow]Scan was interrupted. Partial results may have been saved.[/yellow]")

if __name__ == "__main__":
    main()