-- WARDEN-11 SQLite schema reference

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  severity TEXT NOT NULL,
  module TEXT NOT NULL,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  evidence TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS web_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL,
  status INTEGER NOT NULL,
  final_url TEXT NOT NULL,
  https INTEGER NOT NULL,
  header_summary TEXT NOT NULL,
  cookies TEXT NOT NULL,
  forms TEXT NOT NULL,
  notes TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secret_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_path TEXT NOT NULL,
  line INTEGER NOT NULL,
  kind TEXT NOT NULL,
  masked_value TEXT NOT NULL,
  context TEXT NOT NULL,
  created_at TEXT NOT NULL
);
