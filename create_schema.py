import sqlite3
import os
import csv

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "tx.db"))

SCHEMA_SQL = """
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS config_versions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ref_country_risk(
  iso2 TEXT PRIMARY KEY,
  risk_level TEXT CHECK(risk_level IN ('LOW','MEDIUM','HIGH','HIGH_3RD','PROHIBITED')),
  score INTEGER NOT NULL,
  prohibited INTEGER DEFAULT 0,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ref_sort_codes(
  sort_code TEXT PRIMARY KEY,
  bank_name TEXT,
  branch TEXT,
  schemes TEXT,
  valid_from DATE,
  valid_to DATE
);

CREATE TABLE IF NOT EXISTS kyc_profile(
  customer_id TEXT PRIMARY KEY,
  expected_monthly_in REAL,
  expected_monthly_out REAL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customer_cash_limits(
  customer_id TEXT PRIMARY KEY,
  daily_limit REAL,
  weekly_limit REAL,
  monthly_limit REAL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions(
  id TEXT PRIMARY KEY,
  txn_date DATE NOT NULL,
  customer_id TEXT NOT NULL,
  direction TEXT CHECK(direction IN ('in','out')) NOT NULL,
  amount REAL NOT NULL,
  currency TEXT DEFAULT 'GBP',
  base_amount REAL NOT NULL,
  country_iso2 TEXT,
  payer_sort_code TEXT,
  payee_sort_code TEXT,
  channel TEXT,
  narrative TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tx_customer_date ON transactions(customer_id, txn_date);
CREATE INDEX IF NOT EXISTS idx_tx_country ON transactions(country_iso2);
CREATE INDEX IF NOT EXISTS idx_tx_direction ON transactions(direction);

CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  txn_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  score INTEGER NOT NULL,
  severity TEXT CHECK(severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')) NOT NULL,
  reasons TEXT NOT NULL,
  rule_tags TEXT NOT NULL,
  config_version INTEGER REFERENCES config_versions(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_customer ON alerts(customer_id, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity, created_at);
"""

def seed_reference_data(conn):
    cur = conn.cursor()

    # seed config_versions
    cur.execute("INSERT INTO config_versions(name) VALUES (?)", ("init",))

    # country risk
    countries = [
        ("GB","LOW",0,0),
        ("IE","LOW",0,0),
        ("AE","HIGH_3RD",35,0),
        ("TR","HIGH",25,0),
        ("RU","PROHIBITED",100,1),
        ("IR","PROHIBITED",100,1),
    ]
    cur.executemany(
        "INSERT OR REPLACE INTO ref_country_risk(iso2,risk_level,score,prohibited) VALUES(?,?,?,?)",
        countries
    )

    # sort codes
    sort_codes = [
        ("12-34-56","Barclays","Liverpool","BACS,FPS,CHAPS",None,None),
        ("20-00-00","Barclays","London","BACS,FPS,CHAPS",None,None),
        ("04-00-04","Monzo","London","FPS",None,None),
        ("23-69-72","Starling Bank","London","FPS,CHAPS",None,None),
    ]
    cur.executemany(
        "INSERT OR REPLACE INTO ref_sort_codes(sort_code,bank_name,branch,schemes,valid_from,valid_to) VALUES(?,?,?,?,?,?)",
        sort_codes
    )

    # kyc profiles
    kycs = [
        ("CUST001",8000,5000),
        ("CUST002",12000,9000),
    ]
    cur.executemany(
        "INSERT OR REPLACE INTO kyc_profile(customer_id,expected_monthly_in,expected_monthly_out) VALUES(?,?,?)",
        kycs
    )

    # cash limits
    cash_limits = [
        ("CUST001",1000,3000,8000),
        ("CUST002",500,2000,5000),
    ]
    cur.executemany(
        "INSERT OR REPLACE INTO customer_cash_limits(customer_id,daily_limit,weekly_limit,monthly_limit) VALUES(?,?,?,?)",
        cash_limits
    )

    # sample transactions
    txns = [
        ("CUST001-20250801-10001","2025-08-01","CUST001","in",1200,"GBP",1200,"GB","12-34-56","20-00-00","bank","invoice 4821"),
        ("CUST001-20250803-10002","2025-08-03","CUST001","out",4800,"GBP",4800,"TR","20-00-00","12-34-56","bank","consultancy fee"),
        ("CUST001-20250805-10003","2025-08-05","CUST001","out",1500,"GBP",1500,"AE","04-00-04","23-69-72","bank","services"),
        ("CUST001-20250806-10004","2025-08-06","CUST001","in",900,"GBP",900,"GB","23-69-72","20-00-00","cash","cash deposit"),
        ("CUST002-20250802-10005","2025-08-02","CUST002","out",6500,"GBP",6500,"GB","20-00-00","12-34-56","bank","hardware purchase"),
        ("CUST002-20250804-10006","2025-08-04","CUST002","in",3000,"GBP",3000,"IE","12-34-56","04-00-04","bank","invoice"),
        ("CUST002-20250808-10007","2025-08-08","CUST002","out",2200,"GBP",2200,"AE","04-00-04","23-69-72","bank","USDT OTC"),
        ("CUST002-20250809-10008","2025-08-09","CUST002","in",400,"GBP",400,"RU","23-69-72","20-00-00","bank","gift"),
    ]
    cur.executemany(
        """INSERT OR REPLACE INTO transactions
        (id,txn_date,customer_id,direction,amount,currency,base_amount,country_iso2,payer_sort_code,payee_sort_code,channel,narrative)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        txns
    )

    conn.commit()

def create_schema():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)  # start fresh each time
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(SCHEMA_SQL)
    conn.commit()

    seed_reference_data(conn)
    conn.close()
    print(f"Schema + seed data created in {DB_PATH}")

if __name__ == "__main__":
    create_schema()