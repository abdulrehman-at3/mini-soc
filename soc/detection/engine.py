"""Orchestrates every detection rule plus the anomaly detector against a
batch of newly-ingested events. This is the single function the CLI and
the dashboard both call — neither one duplicates detection logic."""
from __future__ import annotations

import sqlite3
from typing import List

import config as cfg
from soc.detection.anomaly import detect_volume_anomaly
from soc.detection.rules import RULES
from soc.models import Detection


def run_detection_pipeline(conn: sqlite3.Connection, new_events: List[dict]) -> List[Detection]:
    if not new_events:
        return []
    detections: List[Detection] = []
    for rule_fn in RULES:
        detections.extend(rule_fn(conn, new_events, cfg))
    detections.extend(detect_volume_anomaly(conn, new_events, cfg))
    return detections
