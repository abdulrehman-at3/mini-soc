"""
Log collector: the "Windows/Linux Logs -> Log Collector -> Normalization"
stage of the pipeline.

Each configured source file is read starting from the line offset it left
off at last time (tracked in the `ingest_state` table), normalized, and
inserted into `events`. Lines that fail to parse are counted and skipped
rather than aborting the whole run — a single malformed line from a
noisy log source should never take down ingestion.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import config
from soc import database as db
from soc.normalizer import normalize_line


@dataclass
class IngestResult:
    new_events: List[dict] = field(default_factory=list)
    lines_read: int = 0
    lines_skipped: int = 0
    per_file: dict = field(default_factory=dict)


def collect_new_events(conn: sqlite3.Connection, sources: list | None = None) -> IngestResult:
    sources = sources if sources is not None else config.LOG_SOURCES
    result = IngestResult()

    for source in sources:
        path, fmt = source["path"], source["format"]
        file_result = {"read": 0, "skipped": 0, "inserted": 0}
        p = Path(path)
        if not p.exists():
            result.per_file[path] = file_result
            continue

        already_ingested = db.get_ingest_offset(conn, path)
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            all_lines = fh.readlines()

        new_lines = all_lines[already_ingested:]
        for line in new_lines:
            file_result["read"] += 1
            result.lines_read += 1
            event = normalize_line(fmt, line)
            if event is None:
                if line.strip():
                    file_result["skipped"] += 1
                    result.lines_skipped += 1
                continue
            event_id = db.insert_event(conn, event)
            file_result["inserted"] += 1
            row = db.get_event(conn, event_id)
            result.new_events.append(row)

        db.set_ingest_offset(conn, path, len(all_lines))
        result.per_file[path] = file_result

    conn.commit()
    return result
