-- Init schema and seed data (PostgreSQL) generated from create_schema.py

-- Schema ---------------------------------------------------------------

-- config_versions
CREATE TABLE IF NOT EXISTS config_versions (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ref_country_risk
CREATE TABLE IF NOT EXISTS ref_country_risk (
  iso2 TEXT PRIMARY KEY,
  risk_level TEXT CHECK (risk_level IN ('LOW','MEDIUM','HIGH','HIGH_3RD','PROHIBITED')),
  score INTEGER NOT NULL,
  prohibited INTEGER DEFAULT 0,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ref_sort_codes
CREATE TABLE IF NOT EXISTS ref_sort_codes (
  sort_code TEXT PRIMARY KEY,
  bank_name TEXT,
  branch TEXT,
  schemes TEXT,
  valid_from DATE,
  valid_to DATE
);

-- kyc_profile
CREATE TABLE IF NOT EXISTS kyc_profile (
  customer_id TEXT PRIMARY KEY,
  expected_monthly_in DOUBLE PRECISION,
  expected_monthly_out DOUBLE PRECISION,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- customer_cash_limits
CREATE TABLE IF NOT EXISTS customer_cash_limits (
  customer_id TEXT PRIMARY KEY,
  daily_limit DOUBLE PRECISION,
  weekly_limit DOUBLE PRECISION,
  monthly_limit DOUBLE PRECISION,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- transactions
CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  txn_date DATE NOT NULL,
  customer_id TEXT NOT NULL,
  direction TEXT CHECK (direction IN ('in','out')) NOT NULL,
  amount DOUBLE PRECISION NOT NULL,
  currency TEXT DEFAULT 'GBP',
  base_amount DOUBLE PRECISION NOT NULL,
  country_iso2 TEXT,
  payer_sort_code TEXT,
  payee_sort_code TEXT,
  channel TEXT,
  narrative TEXT,
  transaction_type TEXT,
  instrument TEXT,
  originating_customer TEXT,
  originating_bank TEXT,
  beneficiary_customer TEXT,
  beneficiary_bank TEXT,
  posting_date DATE,
  counterparty_account_no TEXT,
  counterparty_bank_code TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tx_customer_date ON transactions (customer_id, txn_date);
CREATE INDEX IF NOT EXISTS idx_tx_country ON transactions (country_iso2);
CREATE INDEX IF NOT EXISTS idx_tx_direction ON transactions (direction);

-- alerts
CREATE TABLE IF NOT EXISTS alerts (
  id BIGSERIAL PRIMARY KEY,
  txn_id TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  score INTEGER NOT NULL,
  severity TEXT CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')) NOT NULL,
  reasons TEXT NOT NULL,
  rule_tags TEXT NOT NULL,
  config_version INTEGER REFERENCES config_versions(id),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_customer ON alerts (customer_id, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity, created_at);


-- rules (for Excel-driven or Admin-managed rules catalogue)
CREATE TABLE IF NOT EXISTS rules (
  id BIGSERIAL PRIMARY KEY,
  category TEXT,
  rule TEXT,
  trigger_condition TEXT,
  score_impact TEXT,
  tags TEXT,
  outcome TEXT,
  description TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_rules_category_rule ON rules(category, rule);

-- users
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT,
  password_hash TEXT NOT NULL,
  role TEXT CHECK (role IN ('admin','reviewer','bau_manager','remediation_manager')) NOT NULL DEFAULT 'reviewer',
  user_type TEXT CHECK (user_type IN ('BAU','Remediation')) NOT NULL DEFAULT 'BAU',
  must_change_password INTEGER DEFAULT 0,
  failed_login_attempts INTEGER DEFAULT 0,
  locked_until TIMESTAMP,
  last_login TIMESTAMP,
  last_password_change TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  -- 2FA fields
  totp_secret TEXT,
  totp_enabled INTEGER DEFAULT 0,
  backup_codes TEXT,
  totp_verified INTEGER DEFAULT 0
);

-- audit_log
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  event_type TEXT NOT NULL,
  user_id INTEGER,
  username TEXT,
  ip_address TEXT,
  user_agent TEXT,
  details TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_log_event ON audit_log(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id, created_at);

-- customers
CREATE TABLE IF NOT EXISTS customers (
  customer_id TEXT PRIMARY KEY,
  customer_name TEXT,
  business_type TEXT,
  onboarded_date DATE,
  status TEXT DEFAULT 'active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- statements
CREATE TABLE IF NOT EXISTS statements (
  id BIGSERIAL PRIMARY KEY,
  customer_id TEXT NOT NULL,
  account_name TEXT,
  filename TEXT,
  uploaded_by INTEGER,
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  record_count INTEGER,
  date_from DATE,
  date_to DATE
);

-- ref_bank_country (for CBS bank-name → country lookup)
CREATE TABLE IF NOT EXISTS ref_bank_country (
  bank_name_pattern TEXT PRIMARY KEY,
  country_iso2 TEXT NOT NULL,
  country_name TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- key-value config store used by the app
CREATE TABLE IF NOT EXISTS config_kv (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ai_rationales
CREATE TABLE IF NOT EXISTS ai_rationales (
  id BIGSERIAL PRIMARY KEY,
  customer_id TEXT NOT NULL,
  period_from TEXT,
  period_to TEXT,
  nature_of_business TEXT,
  est_income DOUBLE PRECISION,
  est_expenditure DOUBLE PRECISION,
  rationale_text TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(customer_id, period_from, period_to)
);

-- ai_cases
CREATE TABLE IF NOT EXISTS ai_cases (
  id BIGSERIAL PRIMARY KEY,
  customer_id TEXT NOT NULL,
  period_from TEXT,
  period_to TEXT,
  assessment_risk TEXT,
  assessment_score INTEGER,
  assessment_summary TEXT,
  rationale_text TEXT,
  rationale_generated_at TEXT,
  case_status TEXT DEFAULT 'open',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ai_answers
CREATE TABLE IF NOT EXISTS ai_answers (
  id BIGSERIAL PRIMARY KEY,
  case_id BIGINT NOT NULL,
  tag TEXT,
  question TEXT NOT NULL,
  answer TEXT,
  sources TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (case_id) REFERENCES ai_cases(id) ON DELETE CASCADE
);


-- Seed data ------------------------------------------------------------

-- ref_country_risk
INSERT INTO ref_country_risk (iso2, risk_level, score, prohibited)
VALUES
  ('GB','LOW',0,0),
  ('IE','LOW',0,0),
  ('AE','HIGH_3RD',35,0),
  ('TR','HIGH',25,0),
  ('RU','PROHIBITED',100,1),
  ('IR','PROHIBITED',100,1)
ON CONFLICT (iso2) DO UPDATE SET
  risk_level = EXCLUDED.risk_level,
  score = EXCLUDED.score,
  prohibited = EXCLUDED.prohibited,
  updated_at = CURRENT_TIMESTAMP;

-- ref_sort_codes
INSERT INTO ref_sort_codes (sort_code, bank_name, branch, schemes, valid_from, valid_to)
VALUES
  ('12-34-56','Barclays','Liverpool','BACS,FPS,CHAPS',NULL,NULL),
  ('20-00-00','Barclays','London','BACS,FPS,CHAPS',NULL,NULL),
  ('04-00-04','Monzo','London','FPS',NULL,NULL),
  ('23-69-72','Starling Bank','London','FPS,CHAPS',NULL,NULL)
ON CONFLICT (sort_code) DO UPDATE SET
  bank_name = EXCLUDED.bank_name,
  branch = EXCLUDED.branch,
  schemes = EXCLUDED.schemes,
  valid_from = EXCLUDED.valid_from,
  valid_to = EXCLUDED.valid_to;

-- kyc_profile
INSERT INTO kyc_profile (customer_id, expected_monthly_in, expected_monthly_out)
VALUES
  ('CUST001',8000,5000),
  ('CUST002',12000,9000)
ON CONFLICT (customer_id) DO UPDATE SET
  expected_monthly_in = EXCLUDED.expected_monthly_in,
  expected_monthly_out = EXCLUDED.expected_monthly_out,
  updated_at = CURRENT_TIMESTAMP;

-- customer_cash_limits
INSERT INTO customer_cash_limits (customer_id, daily_limit, weekly_limit, monthly_limit)
VALUES
  ('CUST001',1000,3000,8000),
  ('CUST002',500,2000,5000)
ON CONFLICT (customer_id) DO UPDATE SET
  daily_limit = EXCLUDED.daily_limit,
  weekly_limit = EXCLUDED.weekly_limit,
  monthly_limit = EXCLUDED.monthly_limit,
  updated_at = CURRENT_TIMESTAMP;

-- sample transactions
INSERT INTO transactions (
  id, txn_date, customer_id, direction, amount, currency, base_amount,
  country_iso2, payer_sort_code, payee_sort_code, channel, narrative
)
VALUES
  ('CUST001-20250801-10001','2025-08-01','CUST001','in',1200,'GBP',1200,'GB','12-34-56','20-00-00','bank','invoice 4821'),
  ('CUST001-20250803-10002','2025-08-03','CUST001','out',4800,'GBP',4800,'TR','20-00-00','12-34-56','bank','consultancy fee'),
  ('CUST001-20250805-10003','2025-08-05','CUST001','out',1500,'GBP',1500,'AE','04-00-04','23-69-72','bank','services'),
  ('CUST001-20250806-10004','2025-08-06','CUST001','in',900,'GBP',900,'GB','23-69-72','20-00-00','cash','cash deposit'),
  ('CUST002-20250802-10005','2025-08-02','CUST002','out',6500,'GBP',6500,'GB','20-00-00','12-34-56','bank','hardware purchase'),
  ('CUST002-20250804-10006','2025-08-04','CUST002','in',3000,'GBP',3000,'IE','12-34-56','04-00-04','bank','invoice'),
  ('CUST002-20250808-10007','2025-08-08','CUST002','out',2200,'GBP',2200,'AE','04-00-04','23-69-72','bank','USDT OTC'),
  ('CUST002-20250809-10008','2025-08-09','CUST002','in',400,'GBP',400,'RU','23-69-72','20-00-00','bank','gift')
ON CONFLICT (id) DO NOTHING;

-- rules (optional seed)
-- Use the Admin UI or the Excel importer to populate this table.
-- Example insert:
-- INSERT INTO rules (category, rule, trigger_condition, score_impact, tags, outcome, description)
-- VALUES ('Cash Activity','Daily cash limit breach','cash_in > daily_limit','+20','cash,limits','HIGH','Daily cash deposits exceed configured limit');
