#!/usr/bin/env python3
import os, sys, re, json, csv, hashlib, hmac
from pathlib import Path

ERRS = []

def err(msg):
    ERRS.append(msg)
    print(f"[ERROR] {msg}")

def info(msg):
    print(f"[INFO] {msg}")

REASON_RE = re.compile(r"^[a-z][a-z0-9_]*$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PR_RE   = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[0-9]+$")
TS_RE   = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

root = Path('.')

# 1) remediated.csv
rem = root / 'remediated.csv'
if rem.exists():
    with rem.open() as f:
        rdr = csv.DictReader(f)
        expected = {'repo','pr_url','timestamp','reasons'}
        if set(rdr.fieldnames or []) >= expected:
            rows = list(rdr)
            last_ts = None
            for i,row in enumerate(rows,1):
                repo = (row.get('repo') or '').strip()
                pr   = (row.get('pr_url') or '').strip()
                ts   = (row.get('timestamp') or '').strip()
                reasons = (row.get('reasons') or '').strip()
                if not REPO_RE.match(repo): err(f"remediated.csv row {i}: invalid repo '{repo}'")
                if not PR_RE.match(pr):     err(f"remediated.csv row {i}: invalid pr_url '{pr}'")
                if not TS_RE.match(ts):     err(f"remediated.csv row {i}: invalid timestamp '{ts}'")
                if last_ts and ts < last_ts:
                    err("remediated.csv not chronological by timestamp")
                last_ts = ts
                for r in [s.strip() for s in reasons.split(',') if s.strip()]:
                    if not REASON_RE.match(r): err(f"remediated.csv row {i}: invalid reason '{r}'")
        else:
            err("remediated.csv missing required columns {repo, pr_url, timestamp, reasons}")
else:
    info("remediated.csv not found (skipping)")

# 2) weekly_reason_rollup.csv
roll = root / 'weekly_reason_rollup.csv'
if roll.exists():
    with roll.open() as f:
        rdr = csv.DictReader(f)
        if set(rdr.fieldnames or []) >= {'reason','total_count'}:
            prev_reason = None
            for i,row in enumerate(rdr,1):
                r = (row.get('reason') or '').strip()
                c = (row.get('total_count') or '').strip()
                if not REASON_RE.match(r): err(f"weekly_reason_rollup.csv row {i}: invalid reason '{r}'")
                try:
                    cval = int(c)
                    if cval < 0: err(f"weekly_reason_rollup.csv row {i}: negative total_count")
                except:
                    err(f"weekly_reason_rollup.csv row {i}: total_count not integer '{c}'")
                if prev_reason and r < prev_reason:
                    err("weekly_reason_rollup.csv not alphabetical by reason")
                prev_reason = r
        else:
            err("weekly_reason_rollup.csv missing required columns {reason, total_count}")
else:
    info("weekly_reason_rollup.csv not found (skipping)")

# 3) slo_report.md (optional)
slo = root / 'slo_report.md'
if slo.exists():
    txt = slo.read_text(encoding='utf-8')
    if not txt.strip():
        err("slo_report.md is empty")
else:
    info("slo_report.md not found (skipping)")

# 4) sla_status.csv (optional)
sla = root / 'sla_status.csv'
if sla.exists():
    with sla.open() as f:
        rdr = csv.DictReader(f)
        need = {'reason','first_fail_date','days_open','sla_days','due_date','status'}
        if set(rdr.fieldnames or []) >= need:
            for i,row in enumerate(rdr,1):
                r = (row.get('reason') or '').strip()
                fd = (row.get('first_fail_date') or '').strip()
                do = (row.get('days_open') or '').strip()
                sd = (row.get('sla_days') or '').strip()
                dd = (row.get('due_date') or '').strip()
                st = (row.get('status') or '').strip()
                if not REASON_RE.match(r): err(f"sla_status.csv row {i}: invalid reason '{r}'")
                if not DATE_RE.match(fd):  err(f"sla_status.csv row {i}: invalid first_fail_date '{fd}'")
                if not DATE_RE.match(dd):  err(f"sla_status.csv row {i}: invalid due_date '{dd}'")
                try:
                    if int(do) < 0: err(f"sla_status.csv row {i}: days_open negative")
                    if int(sd) < 1: err(f"sla_status.csv row {i}: sla_days < 1")
                except:
                    err(f"sla_status.csv row {i}: numeric parse error for days_open/sla_days")
                if st not in {"on_track","at_risk","overdue"}: err(f"sla_status.csv row {i}: invalid status '{st}'")
        else:
            err("sla_status.csv missing required columns")
else:
    info("sla_status.csv not found (skipping)")

# 5) snapshot manifest + signature (optional)
manifest = Path('site/snapshot.manifest.json')
signature = Path('site/snapshot.signature')
if manifest.exists():
    try:
        man = json.loads(manifest.read_text(encoding='utf-8'))
        if 'generated_at_utc' not in man or 'files' not in man:
            err("snapshot.manifest.json missing keys {generated_at_utc, files}")
        else:
            if not TS_RE.match(man.get('generated_at_utc','')):
                err("snapshot.manifest.json: generated_at_utc not UTC ISO-8601")
            if not isinstance(man['files'], dict):
                err("snapshot.manifest.json: files must be object")
            for k,v in man['files'].items():
                if not re.match(r'^[a-f0-9]{64}$', v or ''):
                    err(f"snapshot.manifest.json: bad sha256 for file '{k}'")
    except Exception as e:
        err(f"snapshot.manifest.json not valid JSON: {e}")

    secret = os.getenv('SNAPSHOT_SIGNING_SECRET','')
    if signature.exists():
        sig = signature.read_text(encoding='utf-8').strip()
        if secret and sig:
            payload = json.dumps(man, separators=(',',':')).encode('utf-8')
            calc = hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
            if sig != calc:
                err("snapshot.signature HMAC mismatch")
        else:
            info("snapshot signature check skipped (no secret or empty signature)")
else:
    info("snapshot manifest not found (skipping)")

# Summary
if ERRS:
    print("
==== CONTRACT VIOLATIONS ====")
    for e in ERRS:
        print("- ", e)
    sys.exit(1)
else:
    print("All checks passed. rexce ABI contract respected.")
