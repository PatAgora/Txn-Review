#!/usr/bin/env python3
"""
Seed the SQLite 'rules' table from an Excel file.

Usage:
  python3 seed_rules.py path/to/transaction_rules.xlsx
Optional:
  TX_DB=/absolute/path/to/tx.db python3 seed_rules.py data/transaction_rules.xlsx
  python3 seed_rules.py --wipe path/to/file.xlsx   # wipe existing rules then load

Expected Excel columns (case-insensitive; flexible names accepted):
  Category | Rule | Trigger Condition | Score Impact | Tag(s) | Escalation Outcome | Description
"""

import os
import sys
import sqlite3
from datetime import datetime

# Lazy import pandas only when script is run
try:
    import pandas as pd
except ImportError:
    print("This script requires pandas. Install with: pip install pandas openpyxl")
    sys.exit(1)

DB_PATH = os.getenv("TX_DB") or os.path.abspath(os.path.join(os.path.dirname(__file__), "tx.db"))

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT,
    rule TEXT,
    trigger_condition TEXT,
    score_impact TEXT,
    tags TEXT,
    outcome TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

UNIQUE_IDX = "CREATE UNIQUE INDEX IF NOT EXISTS ux_rules_category_rule ON rules(category, rule);"

UPSERT_SQL = """
INSERT INTO rules (category, rule, trigger_condition, score_impact, tags, outcome, description, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
ON CONFLICT(category, rule) DO UPDATE SET
  trigger_condition = excluded.trigger_condition,
  score_impact      = excluded.score_impact,
  tags              = excluded.tags,
  outcome           = excluded.outcome,
  description       = excluded.description,
  updated_at        = CURRENT_TIMESTAMP;
"""

def normalize_columns(columns):
    """Map flexible Excel headers to canonical names."""
    mapping = {}
    for c in columns:
        key = c.strip().lower()
        if key in ("category",): mapping[c] = "category"
        elif key in ("rule", "rule name", "name"): mapping[c] = "rule"
        elif key in ("trigger condition", "trigger", "condition"): mapping[c] = "trigger_condition"
        elif key in ("score impact", "impact", "score"): mapping[c] = "score_impact"
        elif key in ("tag(s)", "tags", "rule tags"): mapping[c] = "tags"
        elif key in ("escalation outcome", "outcome", "severity outcome"): mapping[c] = "outcome"
        elif key in ("description", "plain description", "explanation"): mapping[c] = "description"
        else:
            # keep original if we don't recognize it; may ignore later
            mapping[c] = c
    return mapping

def load_excel(path):
    df = pd.read_excel(path)
    # rename columns to canonical names
    colmap = normalize_columns(df.columns)
    df = df.rename(columns=colmap)

    required = {"category", "rule"}
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Excel missing required column(s): {', '.join(missing)}")

    # Ensure optional columns exist for robust iteration
    for opt in ["trigger_condition", "score_impact", "tags", "outcome", "description"]:
        if opt not in df.columns:
            df[opt] = ""

    # Fill NaNs with empty strings
    df = df.fillna("")

    records = []
    for _, r in df.iterrows():
        records.append((
            str(r.get("category") or "").strip(),
            str(r.get("rule") or "").strip(),
            str(r.get("trigger_condition") or "").strip(),
            str(r.get("score_impact") or "").strip(),
            str(r.get("tags") or "").strip(),
            str(r.get("outcome") or "").strip(),
            str(r.get("description") or "").strip()
        ))
    return records

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 seed_rules.py [/path/to/transaction_rules.xlsx] [--wipe]")
        sys.exit(1)

    wipe = False
    paths = []
    for arg in sys.argv[1:]:
        if arg == "--wipe":
            wipe = True
        else:
            paths.append(arg)

    if not paths:
        print("Please provide the Excel path. Example: python3 seed_rules.py data/transaction_rules.xlsx")
        sys.exit(1)

    xl_path = os.path.abspath(paths[0])
    if not os.path.exists(xl_path):
        print(f"Excel file not found: {xl_path}")
        sys.exit(1)

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    con = sqlite3.connect(DB_PATH)
    try:
        cur = con.cursor()
        cur.execute(CREATE_SQL)
        cur.execute(UNIQUE_IDX)

        if wipe:
            cur.execute("DELETE FROM rules;")
            print("Existing rules wiped.")

        recs = load_excel(xl_path)
        if not recs:
            print("No records found in Excel.")
            sys.exit(0)

        cur.executemany(UPSERT_SQL, recs)
        con.commit()
        print(f"Seeded/updated {len(recs)} rule(s) into {DB_PATH} at {datetime.now().isoformat(timespec='seconds')}")
    finally:
        con.close()

if __name__ == "__main__":
    main()