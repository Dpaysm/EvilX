import json
from rich.console import Console
from rich.table import Table
from datetime import datetime

console = Console()

class Reporter:
    def __init__(self, stats=None):
        self.stats = stats

    def generate_summary_report(self):
        table = Table(title="Scan Summary Report")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        if self.stats:
            table.add_row("Duration", str(self.stats.get_duration()))
            table.add_row("URLs Scanned", str(self.stats.urls_scanned))
            table.add_row("Vulnerabilities Found", str(self.stats.vulnerabilities_found))
            table.add_row("Redirects Found", str(self.stats.redirects_found))
            table.add_row("Errors Encountered", str(self.stats.errors_encountered))
        
        console.print(table)

    def export_results(self, vulnerable_urls, format="txt"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == "json":
            filename = f"output/vulnerable_{timestamp}.json"
            with open(filename, "w") as f:
                json.dump({"vulnerable_urls": vulnerable_urls}, f, indent=2)
        elif format == "csv":
            filename = f"output/vulnerable_{timestamp}.csv"
            with open(filename, "w") as f:
                f.write("URL,Payload,Response_Code\n")
                for vuln in vulnerable_urls:
                    f.write(f"{vuln['url']},{vuln['payload']},{vuln['code']}\n")
        else:
            filename = f"output/vulnerable_{timestamp}.txt"
            with open(filename, "w") as f:
                for vuln in vulnerable_urls:
                    f.write(f"{vuln['url']}\n")
        
        console.print(f"[green]Results exported to:[/green] {filename}")
