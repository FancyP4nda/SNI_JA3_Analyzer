import os
import sys
from typing import Optional
import typer
from rich.console import Console

from .parser import yield_tls_records
from .formatter import format_jsonl, format_table

app = typer.Typer(
    name="tls-analyzer",
    help="High-Performance TLS Forensic CLI Utility",
    add_completion=False,
)
err_console = Console(stderr=True)


def check_permissions(pcap_path: str):
    """Ensure the PCAP exists and is readable before booting Scapy."""
    if not os.path.exists(pcap_path):
        err_console.print(f"[red]Error:[/red] File '{pcap_path}' does not exist.")
        raise typer.Exit(code=1)
    if not os.access(pcap_path, os.R_OK):
        err_console.print(f"[red]Error:[/red] Permission denied to read '{pcap_path}'.")
        raise typer.Exit(code=1)


def build_bpf_filter(bpf: Optional[str], source: Optional[str], dest: Optional[str]) -> str:
    """Constructs a BPF filter string from CLI arguments."""
    filters = []
    if bpf:
        filters.append(f"({bpf})")
    
    if source:
        filters.append(f"(host {source})")
        
    if dest:
        filters.append(f"(dst host {dest})")

    # We only care about TCP packets since TLS runs over TCP
    filters.append("(tcp)")

    return " and ".join(filters)

@app.command()
def analyze(
    pcap: str = typer.Option(..., "--pcap", "-p", help="Path to PCAP/PCAPNG file"),
    bpf: Optional[str] = typer.Option(None, "--bpf", "-b", help="Raw BPF filter string (e.g., 'tcp port 443')"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Filter by source IP"),
    dest: Optional[str] = typer.Option(None, "--dest", "-d", help="Filter by destination IP"),
    limit: int = typer.Option(0, "--limit", "-l", help="Limit number of packets to process (0 = all)"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: 'table' or 'jsonl'"),
):
    """Parse TLS ClientHello packets and extract SNI and JA3 hashes."""
    
    check_permissions(pcap)
    
    if output not in ["table", "jsonl"]:
        err_console.print(f"[red]Error:[/red] Invalid output format '{output}'. Choose 'table' or 'jsonl'.")
        raise typer.Exit(code=1)

    bpf_compiled = build_bpf_filter(bpf, source, dest)
    
    try:
        records_generator = yield_tls_records(pcap_path=pcap, bpf_filter=bpf_compiled)
        
        if output == "jsonl":
             # For JSONL we stream until exhausted or hit limit internally
             import json
             count = 0
             for record in records_generator:
                 sys.stdout.write(json.dumps(record.__dict__) + "\n")
                 count += 1
                 if limit > 0 and count >= limit:
                     break
        else:
            format_table(records_generator, limit=limit)
            
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Analysis interrupted by user (Ctrl+C).[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:
        err_console.print(f"[red]Fatal Error Parsing PCAP:[/red] {e}")
        # Only print traceback if debug flag was passed conceptually (omitted for brevity here but handled generally in production CLI)
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
