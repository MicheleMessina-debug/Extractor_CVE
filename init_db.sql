CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  webhook_url TEXT,
  created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id SERIAL PRIMARY KEY,
  user_id INT REFERENCES users(id),
  type VARCHAR(20) NOT NULL, -- 'vendor','product','domain','keyword'
  value TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vulns (
  id SERIAL PRIMARY KEY,
  cve_id TEXT,
  source TEXT,
  published_at TIMESTAMP,
  last_modified TIMESTAMP,
  summary TEXT,
  cvss_score REAL,
  raw_json JSONB,
  created_at TIMESTAMP DEFAULT now(),
  UNIQUE (source, cve_id)
);

CREATE TABLE IF NOT EXISTS vuln_affected (
  id SERIAL PRIMARY KEY,
  vuln_id INT REFERENCES vulns(id) ON DELETE CASCADE,
  vendor TEXT,
  product TEXT,
  version_range TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
  id SERIAL PRIMARY KEY,
  user_id INT REFERENCES users(id),
  vuln_id INT REFERENCES vulns(id),
  subscription_id INT REFERENCES subscriptions(id),
  delivered BOOLEAN DEFAULT false,
  delivered_at TIMESTAMP,
  payload JSONB,
  created_at TIMESTAMP DEFAULT now()
);
