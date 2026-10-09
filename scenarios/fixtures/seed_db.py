import sqlite3
import json
from pathlib import Path
import random
import uuid
from datetime import datetime, timezone

def run_script(schema_path: Path, db_path: Path, s1_gt_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
        
    conn = sqlite3.connect(db_path)
    with open(schema_path, "r") as f:
        conn.executescript(f.read())
        
    conn.execute("INSERT INTO case_meta (key, value) VALUES (?, ?)", ("case_id", "s1_fake"))
    conn.execute("INSERT INTO case_meta (key, value) VALUES (?, ?)", ("created_at_utc", datetime.now(timezone.utc).isoformat()))
    
    conn.execute("""
        INSERT INTO evidence (filename, stored_path, sha256, size_bytes, line_count, collected_at_utc, collector, host, source_type, declared_tz)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, ("auth.log", "evidence/web01__auth.log", "f" * 64, 1024, 10, "2026-10-09T00:00:00Z", "bob", "web01", "auth_log", "UTC"))
    
    with open(s1_gt_path, "r") as f:
        gt = json.load(f)
        
    for i, step in enumerate(gt.get("steps", [])):
        ts = step["ts_utc"]
        host = step["host"]
        etype = step["event_type"]
        ip = step.get("match", {}).get("src_ip", "")
        username = step.get("match", {}).get("username", "")
        
        conn.execute("""
            INSERT INTO events (evidence_id, line_no, byte_offset, ts_original, ts_utc, ts_utc_corrected, skew_offset_s, host, source_type, event_type, severity, src_ip, username, message, raw_line)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (1, i+1, 0, ts, ts, ts, 0, host, "auth_log", etype, "high", ip, username, step["description"], f"raw: {step['description']}"))
    
    conn.execute("""
        INSERT INTO events_fts (rowid, message, raw_line, username, src_ip, detail)
        SELECT id, message, raw_line, username, src_ip, detail FROM events
    """)
    
    conn.commit()
    conn.close()
    
if __name__ == "__main__":
    schema_path = Path(__file__).resolve().parents[2] / "src" / "forensic" / "schema.sql"
    db_path = Path("cases/s1_fake/case.db")
    s1_gt_path = Path("scenarios/s1_ssh_bruteforce/ground_truth.json")
    run_script(schema_path, db_path, s1_gt_path)
    print("Seeded fake DB successfully.")
