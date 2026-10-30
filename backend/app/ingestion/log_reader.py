"""Read a JSON Lines file and yield validated authentication events."""

from pathlib import Path
from typing import Iterator

from app.ingestion.log_parser import parse_log_line


def read_log_file(path: str | Path) -> Iterator[dict]:
    """Yield parsed events, reporting the line number for malformed entries."""
    log_path = Path(path)
    with log_path.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue
            try:
                yield parse_log_line(line)
            except ValueError as exc:
                raise ValueError(f"{log_path}:{line_number}: {exc}") from exc
