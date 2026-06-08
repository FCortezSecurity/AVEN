import sqlite3
import os
from datetime import datetime

def get_connection(db_path):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            cwe TEXT,
            published_date TEXT,
            modified_date TEXT,
            raw_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS kev_entries (
            cve_id TEXT PRIMARY KEY,
            vendor TEXT,
            product TEXT,
            vulnerability_name TEXT,
            date_added TEXT,
            required_action TEXT,
            due_date TEXT,
            ransomware_use TEXT,
            notes TEXT
        );

        CREATE TABLE IF NOT EXISTS poc_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            source TEXT,
            url TEXT,
            title TEXT,
            stars INTEGER DEFAULT 0,
            maturity TEXT,
            found_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS asset_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            asset_id TEXT,
            asset_hostname TEXT,
            match_reason TEXT,
            matched_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE,
            risk_score REAL,
            risk_tier TEXT,
            cvss_component REAL,
            epss_component REAL,
            maturity_component REAL,
            kev_component REAL,
            asset_component REAL,
            epss_score REAL,
            maturity_level TEXT,
            in_kev INTEGER DEFAULT 0,
            asset_match INTEGER DEFAULT 0,
            scored_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT,
            completed_at TEXT,
            cves_ingested INTEGER DEFAULT 0,
            cves_scored INTEGER DEFAULT 0,
            new_criticals INTEGER DEFAULT 0,
            errors TEXT
        );
    """)

    conn.commit()
    conn.close()
    return True