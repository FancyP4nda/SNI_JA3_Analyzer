import json
from typing import Iterable, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import track

from .models import TLSRecord

console = Console()

def format_jsonl(records: Iterable[TLSRecord]):
    """Streams JSONL to stdout instantly."""
    for record in records:
        print(json.dumps(record.__dict__))

def format_table(records: Iterable[TLSRecord], limit: int = 0):
    """Accumulates and prints a Rich Table to stdout."""
    table = Table(title="TLS ClientHello Analysis", show_lines=True)

    table.add_column("Timestamp", style="cyan")
    table.add_column("Src IP", style="magenta")
    table.add_column("Dst IP", justify="right", style="green")
    table.add_column("Dst Port", style="green")
    table.add_column("Type", style="cyan")
    table.add_column("SNI", style="yellow")
    table.add_column("JA3/JA3S", style="blue")
    table.add_column("JA3/JA3S String")
    table.add_column("ESNI/ECH", style="red")

    count = 0
    # Collect records so we can render the table based on terminal size
    # If the user sets a huge limit, they should realistically use jsonl
    for record in track(records, description="Parsing PCAP...", console=console, transient=True):
        count += 1
        table.add_row(
            record.timestamp,
            record.src_ip,
            record.dst_ip,
            str(record.dst_port),
            record.message_type,
            record.sni,
            record.ja3,
            record.ja3_string,
            record.esni_ech,
        )
        if limit > 0 and count >= limit:
            break

    if count == 0:
        console.print("[yellow]No ClientHello records found.[/yellow]")
    else:
        # Pring the table specifically to standard out, separate from standard err if need be
        console.print(table)
