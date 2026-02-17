"""
LogLoader

Reads log files from disk, validates basic file/format integrity,
and yields raw records (dicts) for downstream normalization.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, Literal, Optional


Format = Literal["json", "jsonl", "csv"]
RawRecord = Dict[str, Any]


@dataclass
class LogValidationError(Exception):
    code: str
    message: str
    path: str
    line: Optional[int] = None
    col: Optional[int] = None

    def __str__(self) -> str:
        loc = ""
        if self.line is not None:
            loc += f" line={self.line}"
        if self.col is not None:
            loc += f" col={self.col}"
        return f"[{self.code}] {self.message} ({self.path}{loc})"


class LogLoader:
    def load(self, path: str, fmt: Optional[str] = None) -> Iterator[RawRecord]:
        p = self._validate_path(path)
        detected = self._detect_format(p, fmt)

        if detected == "json":
            yield from self._load_json(p)
        elif detected == "jsonl":
            yield from self._load_jsonl(p)
        elif detected == "csv":
            yield from self._load_csv(p)
        else:
            raise LogValidationError("UNSUPPORTED_FORMAT", f"Unsupported format: {detected}", str(p))

    # ------------- helpers -------------

    def _validate_path(self, path: str) -> Path:
        p = Path(path).expanduser()
        if not p.exists():
            raise LogValidationError("PATH_NOT_FOUND", "File does not exist", str(p))
        if not p.is_file():
            raise LogValidationError("NOT_A_FILE", "Path is not a file", str(p))
        try:
            with p.open("rb"):
                pass
        except OSError as e:
            raise LogValidationError("UNREADABLE", f"File not readable: {e}", str(p))
        return p

    def _detect_format(self, p: Path, fmt: Optional[str]) -> Format:
        if fmt:
            fmt_l = fmt.strip().lower()
            if fmt_l in ("json", "jsonl", "csv"):
                return fmt_l  # type: ignore[return-value]
            raise LogValidationError("BAD_FORMAT_ARG", f"Unknown format '{fmt}'", str(p))

        ext = p.suffix.lower()
        if ext == ".json":
            return "json"
        if ext in (".jsonl", ".ndjson"):
            return "jsonl"
        if ext == ".csv":
            return "csv"

        # fallback sniff (no extension)
        prefix = p.read_text(encoding="utf-8", errors="ignore")[:2048].lstrip()
        if not prefix:
            raise LogValidationError("EMPTY_FILE", "File is empty", str(p))

        if prefix.startswith("{") or prefix.startswith("["):
            return "json"

        first_nonempty = next((ln.strip() for ln in prefix.splitlines() if ln.strip()), "")
        if first_nonempty.startswith("{"):
            return "jsonl"

        return "csv"

    # ------------- JSON -------------

    def _load_json(self, p: Path) -> Iterator[RawRecord]:
        try:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise LogValidationError("JSON_PARSE_ERROR", e.msg, str(p), line=e.lineno, col=e.colno)

        # Accept either dict (single event) or list[dict] (events)
        if isinstance(data, dict):
            yield data
            return

        if isinstance(data, list):
            for i, item in enumerate(data):
                if not isinstance(item, dict):
                    raise LogValidationError(
                        "JSON_ARRAY_ELEMENT",
                        f"JSON array elements must be objects; found {type(item).__name__} at index {i}",
                        str(p),
                    )
                yield item
            return

        raise LogValidationError("JSON_TOPLEVEL", "JSON top-level must be an object or array", str(p))

    # ------------- JSONL -------------

    def _load_jsonl(self, p: Path) -> Iterator[RawRecord]:
        any_records = False
        with p.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                s = line.strip()
                if not s:
                    continue
                try:
                    obj = json.loads(s)
                except json.JSONDecodeError as e:
                    raise LogValidationError("JSONL_PARSE_ERROR", e.msg, str(p), line=lineno, col=e.colno)

                if not isinstance(obj, dict):
                    raise LogValidationError("JSONL_NOT_OBJECT", "JSONL lines must be JSON objects", str(p), line=lineno)

                any_records = True
                yield obj

        if not any_records:
            raise LogValidationError("JSONL_EMPTY", "JSONL has no JSON objects", str(p))

    # ------------- CSV -------------

    def _load_csv(self, p: Path) -> Iterator[RawRecord]:
        try:
            with p.open("r", encoding="utf-8-sig", newline="") as f:
                sample = f.read(4096)
                f.seek(0)

                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
                except csv.Error:
                    dialect = csv.excel

                reader = csv.DictReader(f, dialect=dialect)

                if not reader.fieldnames or all(not (h or "").strip() for h in reader.fieldnames):
                    raise LogValidationError("CSV_NO_HEADER", "CSV must include a header row", str(p))

                # Optional: reject duplicate headers (helps normalization)
                norm = [(h or "").strip() for h in reader.fieldnames]

                nonempty_cols = [h for h in norm if h]
                if len(nonempty_cols) < 2:
                    raise LogValidationError(
                        "CSV_TOO_FEW_COLUMNS",
                        "CSV must have at least 2 columns",
                        str(p),
                    )

                dupes = {h for h in norm if h and norm.count(h) > 1}
                if dupes:
                    raise LogValidationError("CSV_DUP_HEADERS", f"Duplicate CSV headers: {', '.join(sorted(dupes))}", str(p))

                # Stream rows
                row_count = 0
                for row in reader:
                    row_count += 1
                    yield dict(row)

                if row_count == 0:
                    raise LogValidationError("CSV_EMPTY", "CSV has headers but no data rows", str(p))

        except OSError as e:
            raise LogValidationError("CSV_READ_ERROR", f"CSV read failed: {e}", str(p))