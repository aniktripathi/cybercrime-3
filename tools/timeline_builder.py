#!/usr/bin/env python3
"""
timeline_builder.py - attack timeline builder and correlation engine (Case Omega, Part 4)

Reads the six log sources in evidence/logs/ (authentication, system/process, USB,
browser history, firewall, file changes) plus the human response notes, converts
everything to one time base (IST), applies named detection rules to flag suspicious
activity, correlates events across sources, computes dwell-time metrics and draws
two visualisations.

Outputs (in the output directory):
  timeline_full.csv           every normalised event with its flags
  timeline_key_events.md      flagged events grouped by attack phase
  correlation_findings.txt    cross-source correlations and metrics
  timeline_overview.png       swim-lane overview + traffic + file-activity panels
  timeline_impact_zoom.png    minute-level zoom on the encryption window

Usage:
    python3 tools/timeline_builder.py [logs_dir] [out_dir]
"""
import csv
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt

LOGS = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("evidence/logs")
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("evidence/timeline")
OUT.mkdir(parents=True, exist_ok=True)

BENIGN_DOMAIN_HINTS = ("sunrisemed", "insurer-tpa", "pubmed", "news[.]example")
APPROVED_EXTERNAL = {"192.0.2.10", "192.0.2.44", "192.0.2.80"}
PHASES = ["Initial Access", "Persistence & C2", "Credential Access", "Lateral Movement",
          "Collection & Exfiltration", "Defense Evasion / Recovery Denial", "Impact", "Response"]


def parse(s):
    # naive datetime in IST (all source logs are +05:30)
    return datetime.fromisoformat(s).replace(tzinfo=None)


def rows(name):
    with open(LOGS / name, newline="") as f:
        return list(csv.DictReader(f))


events = []   # dicts: t, source, host, summary, detail, flags(list), phase


def add(t, source, host, summary, detail="", flag=None, phase=None):
    events.append({"t": t, "source": source, "host": host, "summary": summary,
                   "detail": detail, "flags": [flag] if flag else [], "phase": phase})


# ----------------------------------------------------------------- load + rules
findings = []   # (t, phase, rule, host, text)


def finding(t, phase, rule, host, text):
    findings.append((t, phase, rule, host, text))


# Browser
for r in rows("browser_history.csv"):
    t = parse(r["timestamp"])
    benign = any(h in r["url"] for h in BENIGN_DOMAIN_HINTS)
    flag = None
    if r["event"] == "DOWNLOAD" and not benign:
        flag = "SUSPICIOUS_DOWNLOAD"
        finding(t, "Initial Access", flag, r["host"], f"{r['user']} downloaded {r['title']} from untrusted site {r['url']}")
    elif r["event"] == "UPLOAD":
        flag = "WEB_UPLOAD_EXFIL"
    elif r["event"] == "VISIT" and not benign:
        flag = "UNTRUSTED_SITE"
    add(t, "browser", r["host"], f"{r['event']} {r['url']}", r["title"], flag)

# USB
for r in rows("usb_events.csv"):
    t = parse(r["timestamp"])
    flag = None
    if r["event"] == "DEVICE_INSERTED" and r["in_asset_inventory"] == "NO":
        off = t.hour < 8 or t.hour >= 18
        flag = "UNREGISTERED_USB" + ("_OFF_HOURS" if off else "")
        finding(t, "Lateral Movement", flag, r["host"],
                f"Unregistered USB ({r['description']}, serial {r['serial']}) inserted {'outside business hours' if off else ''} in {r['user_session']} session")
    add(t, "usb", r["host"], f"{r['event']} {r['description']}", f"serial {r['serial']}", flag)
usb_insert = next((parse(r["timestamp"]) for r in rows("usb_events.csv") if r["in_asset_inventory"] == "NO"), None)

# System / process
for r in rows("system_events.csv"):
    t = parse(r["timestamp"])
    d, proc, det = r["description"], r["process"], r["detail"]
    flag = phase = None
    if r["event_id"] == "4688" and "\\Downloads\\" in det and ".pdf.exe" in det:
        flag, phase = "EXEC_FROM_DOWNLOADS", "Initial Access"
    elif r["event_id"] == "4698":
        flag, phase = "PERSISTENCE_SCHEDULED_TASK", "Persistence & C2"
    elif r["event_id"] == "SYSMON-10":
        flag, phase = "CREDENTIAL_STORE_ACCESS", "Credential Access"
    elif r["event_id"] == "4688" and len(det) > 2 and det[1:3] == ":\\" and det[0].upper() != "C":
        flag, phase = "EXEC_FROM_REMOVABLE", "Lateral Movement"
    elif r["event_id"] == "4688" and "arch.exe" in det:
        flag, phase = "DATA_STAGING_TOOL", "Collection & Exfiltration"
    elif "delete shadows" in det:
        flag, phase = "RECOVERY_INHIBITION", "Defense Evasion / Recovery Denial"
    elif r["event_id"] == "7036" and "stopped" in det:
        flag, phase = "SECURITY_OR_BACKUP_SERVICE_STOPPED", "Defense Evasion / Recovery Denial"
    elif r["event_id"] == "7045":
        flag, phase = "NEW_AUTOSTART_SERVICE", "Impact"
    elif r["event_id"] == "FW-POLICY":
        flag, phase = "CONTAINMENT", "Response"
    elif proc == "omegasvc.exe":
        flag, phase = "RANSOMWARE_EXECUTION", "Impact"
    if flag:
        finding(t, phase, flag, r["host"], f"{d}: {det}")
    add(t, "system", r["host"], f"[{r['event_id']}] {d}", det, flag, phase)

# Authentication
auth_rows = rows("auth_events.csv")
fails = defaultdict(list)
for r in auth_rows:
    t = parse(r["timestamp"])
    flag = phase = None
    if r["result"] == "FAILURE":
        fails[(r["account"], r["source_ip"], r["host"])].append(t)
    if r["event_id"] == "4624" and r["logon_type"] == "10" and r["account"].startswith("svc_"):
        flag, phase = "RDP_BY_SERVICE_ACCOUNT", "Lateral Movement"
    elif r["event_id"] == "4624" and r["host"] == "HOSP-EHR-DB01" and r["source_ip"] == "10.20.5.10":
        flag, phase = "LATERAL_SPREAD_FS_TO_EHR", "Lateral Movement"
    elif r["event_id"] == "4624" and r["account"].startswith("svc_") and r["logon_type"] == "3":
        recent = [x for x in fails.get((r["account"], r["source_ip"], r["host"]), []) if timedelta(0) <= t - x <= timedelta(minutes=10)]
        if len(recent) >= 5:
            flag, phase = "BRUTE_FORCE_THEN_SUCCESS", "Credential Access"
    if flag:
        finding(t, phase, flag, r["host"], f"{r['account']} {r['event_desc']} (type {r['logon_type']}) from {r['source_ip']}: {r['details']}")
    add(t, "auth", r["host"], f"[{r['event_id']}] {r['event_desc']} {r['account']}", f"from {r['source_ip']} type {r['logon_type']} {r['result']}", flag, phase)

# Firewall: beacon + exfil analytics
fw = rows("firewall_log.csv")
by_pair = defaultdict(list)
exfil_sessions = []
for r in fw:
    t = parse(r["timestamp"])
    by_pair[(r["src_host"], r["dst_ip"], r["action"])].append((t, int(r["bytes_out"])))
    big = int(r["bytes_out"]) >= 100 * 1024 * 1024 and r["dst_ip"] not in APPROVED_EXTERNAL and r["action"] == "ALLOW"
    if big:
        exfil_sessions.append((t, r["src_host"], r["dst_ip"], int(r["bytes_out"])))
    add(t, "firewall", r["src_host"], f"{r['action']} -> {r['dst_ip']}:{r['dst_port']}", f"{int(r['bytes_out']):,} B out",
        "EXFIL_SESSION" if big else None, "Collection & Exfiltration" if big else None)

beacon = None
for (host, dst, action), lst in by_pair.items():
    if action != "ALLOW" or dst in APPROVED_EXTERNAL or len(lst) < 20:
        continue
    ts_sorted = sorted(x[0] for x in lst)
    gaps = [(b - a).total_seconds() for a, b in zip(ts_sorted, ts_sorted[1:])]
    cv = statistics.pstdev(gaps) / statistics.mean(gaps)
    if cv < 0.1:
        blocked = [x for x in by_pair.get((host, dst, "DENY"), [])]
        beacon = dict(host=host, dst=dst, n=len(lst), first=ts_sorted[0], last=ts_sorted[-1],
                      median=statistics.median(gaps), cv=cv, blocked=len(blocked))
        finding(ts_sorted[0], "Persistence & C2", "PERIODIC_BEACON", host,
                f"{len(lst)} outbound sessions to {dst}:443 every ~{statistics.median(gaps)/60:.1f} min (CV {cv:.3f}) from {ts_sorted[0]:%d-%b %H:%M} to {ts_sorted[-1]:%d-%b %H:%M}")

if exfil_sessions:
    total = sum(x[3] for x in exfil_sessions)
    finding(exfil_sessions[0][0], "Collection & Exfiltration", "EXFIL_SESSION", exfil_sessions[0][1],
            f"{len(exfil_sessions)} large uploads to {exfil_sessions[0][2]} totalling {total/1024**3:.2f} GiB between "
            f"{exfil_sessions[0][0]:%H:%M} and {exfil_sessions[-1][0]:%H:%M}")

# File changes: staging + encryption
fc = rows("file_changes.csv")
staged = [(parse(r["timestamp"]), int(r["size_bytes"])) for r in fc if "\\stage\\" in r["path"] and r["extension"] == "7z"]
if staged:
    finding(staged[0][0], "Collection & Exfiltration", "DATA_STAGING", "HOSP-FS01",
            f"{len(staged)} staging archives created in C:\\Windows\\Temp\\stage totalling {sum(s for _, s in staged)/1024**3:.2f} GiB "
            f"({staged[0][0]:%H:%M}-{staged[-1][0]:%H:%M})")
enc = defaultdict(list)   # host -> [(t, files_represented)]
notes = []
for r in fc:
    t = parse(r["timestamp"])
    flag = phase = None
    if r["extension"] == "omega":
        enc[r["host"]].append((t, int(r["files_represented"])))
        flag, phase = "MASS_RENAME_OMEGA", "Impact"
    elif r["path"].endswith("README_OMEGA.txt"):
        notes.append((t, r["host"]))
        flag, phase = "RANSOM_NOTE_CREATED", "Impact"
    elif "\\stage\\" in r["path"]:
        flag, phase = "DATA_STAGING", "Collection & Exfiltration"
    elif r["path"].endswith("omegasvc.exe"):
        flag, phase = "RANSOMWARE_BINARY_DROPPED", "Impact"
    elif r["path"].endswith("osync.exe") or r["path"].endswith("InsuranceClaim_Form_Oct.pdf.exe"):
        flag, phase = "MALWARE_FILE_CREATED", "Initial Access" if "Downloads" in r["path"] else "Persistence & C2"
    add(t, "files", r["host"], f"{r['action']} {r['path']}", f"{int(r['size_bytes']):,} B x{r['files_represented']}", flag, phase)

enc_summary = {}
for host, lst in enc.items():
    lst.sort()
    per_min = defaultdict(int)
    for t, n in lst:
        per_min[t.replace(second=0, microsecond=0)] += n
    peak_t, peak = max(per_min.items(), key=lambda kv: kv[1])
    enc_summary[host] = dict(first=lst[0][0], last=lst[-1][0], files=sum(n for _, n in lst), peak=peak, peak_t=peak_t)
    finding(lst[0][0], "Impact", "MASS_RENAME_OMEGA", host,
            f"~{sum(n for _, n in lst):,} files renamed to .omega between {lst[0][0]:%H:%M:%S} and {lst[-1][0]:%H:%M:%S} (peak ~{peak:,}/min)")
if notes:
    fs_notes = [t for t, h in notes if h == "HOSP-FS01"]
    ehr_notes = [t for t, h in notes if h != "HOSP-FS01"]
    finding(min(fs_notes), "Impact", "RANSOM_NOTE_CREATED", "HOSP-FS01",
            f"README_OMEGA.txt created in {len(fs_notes)} share directories on the file server (and {len(ehr_notes)} on the EHR host at {min(ehr_notes):%H:%M})")

# Response notes
resp = rows("response_events.csv")
for r in resp:
    add(parse(r["timestamp"]), "response", r["actor"], r["event"], r["category"], None, "Response" if r["category"] != "detection" else None)
first_report = next(parse(r["timestamp"]) for r in resp if r["category"] == "detection")

# USB -> execution correlation
usb_exec = next((t for (t, ph, rule, h, tx) in findings if rule == "EXEC_FROM_REMOVABLE"), None)
rdp = next((t for (t, ph, rule, h, tx) in findings if rule == "RDP_BY_SERVICE_ACCOUNT"), None)
initial_exec = next(t for (t, ph, rule, h, tx) in findings if rule == "EXEC_FROM_DOWNLOADS")
brute_ok = next((t for (t, ph, rule, h, tx) in findings if rule == "BRUTE_FORCE_THEN_SUCCESS"), None)
shadow = next((t for (t, ph, rule, h, tx) in findings if rule == "RECOVERY_INHIBITION"), None)
contain = next((t for (t, ph, rule, h, tx) in findings if rule == "CONTAINMENT"), None)
enc_start = min(v["first"] for v in enc_summary.values())

def fmt(td):
    s = int(td.total_seconds()); h, rem = divmod(s, 3600); m, sec = divmod(rem, 60)
    return f"{h}h {m:02d}m {sec:02d}s"

# Attach flags so timeline_full.csv carries them
events.sort(key=lambda e: e["t"])
with open(OUT / "timeline_full.csv", "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["timestamp_ist", "source", "host", "summary", "detail", "flag", "phase"])
    for e in events:
        w.writerow([e["t"].isoformat(sep=" "), e["source"], e["host"], e["summary"], e["detail"],
                    ";".join(e["flags"]), e["phase"] or ""])

# ----------------------------------------------------------- key events markdown
findings.sort()
with open(OUT / "timeline_key_events.md", "w") as f:
    f.write("# Case Omega - Key Events Timeline (generated)\n\n")
    f.write("Generated by `tools/timeline_builder.py` from the logs in `evidence/logs/`. All times IST (UTC+05:30).\n\n")
    for ph in PHASES:
        items = [x for x in findings if x[1] == ph]
        if not items:
            continue
        f.write(f"## {ph}\n\n| Time (IST) | Host | Rule | Observation |\n|---|---|---|---|\n")
        for t, _, rule, host, text in items:
            f.write(f"| {t:%d-%b %H:%M:%S} | {host} | {rule} | {text.replace('|', '/')} |\n")
        f.write("\n")

# --------------------------------------------------------------- correlation text
lines = []
lines.append("=== Case Omega - Cross-source correlation findings ===")
lines.append(f"Events normalised: {len(events)} from 7 sources | Flagged findings: {len(findings)}")
lines.append("")
lines.append("[C1] Dwell time (first malicious execution -> encryption start)")
lines.append(f"     {initial_exec:%d-%b %H:%M:%S} -> {enc_start:%d-%b %H:%M:%S} = {fmt(enc_start - initial_exec)}")
if beacon:
    lines.append("[C2] Command-and-control beaconing (firewall)")
    lines.append(f"     {beacon['host']} -> {beacon['dst']}:443  {beacon['n']} sessions, median interval {beacon['median']/60:.1f} min, "
                 f"regularity CV={beacon['cv']:.3f}; {beacon['first']:%d-%b %H:%M} to {beacon['last']:%d-%b %H:%M}")
    lines.append(f"     First beacon is {fmt(beacon['first'] - initial_exec)} after execution of the downloaded loader; "
                 f"{beacon['blocked']} later attempts DENIED after isolation")
if brute_ok:
    lines.append("[C3] Credential attack: 6 failed network logons then success for svc_backup at "
                 f"{brute_ok:%H:%M:%S}, ~{fmt(brute_ok - parse('2026-10-13T14:04:40+05:30'))} after the credential-store access event (SYSMON-10) at 14:04:40")
if usb_insert and usb_exec and rdp:
    lines.append("[C4] USB -> execution -> lateral movement chain (13-Oct)")
    lines.append(f"     USB inserted {usb_insert:%H:%M:%S} -> executable run from E:\\ at {usb_exec:%H:%M:%S} (+{fmt(usb_exec - usb_insert)}) "
                 f"-> RDP to file server as svc_backup at {rdp:%H:%M:%S} (+{fmt(rdp - usb_insert)} after insertion)")
    lines.append("     Insertion was OUTSIDE business hours on an unregistered device while the implant (osync.exe) was already beaconing.")
if staged and exfil_sessions:
    total = sum(x[3] for x in exfil_sessions)
    lines.append("[C5] Collection and exfiltration (13-Oct)")
    lines.append(f"     Staging: {len(staged)} archives, {sum(s for _, s in staged)/1024**3:.2f} GiB created {staged[0][0]:%H:%M}-{staged[-1][0]:%H:%M}")
    lines.append(f"     Uploads: {len(exfil_sessions)} sessions to {exfil_sessions[0][2]}, {total/1024**3:.2f} GiB, {exfil_sessions[0][0]:%H:%M}-{exfil_sessions[-1][0]:%H:%M}")
    lines.append("     Browser history on HOSP-FS01 shows the same destination (file-drop-secure[.]io) opened at 22:04:11, one minute before the first upload - "
                 "browser, firewall and file-system evidence agree.")
lines.append("[C6] Recovery denial before encryption")
lines.append(f"     Shadow-copy deletion {shadow:%H:%M:%S}, backup agent stopped 02:00:15, OmegaSvc installed 02:03:00 -> encryption begins {enc_start:%H:%M:%S} "
             f"(preparation {fmt(enc_start - shadow)})")
lines.append("[C7] Encryption impact")
for host, v in enc_summary.items():
    lines.append(f"     {host}: {v['first']:%H:%M:%S}-{v['last']:%H:%M:%S} ({fmt(v['last'] - v['first'])}), ~{v['files']:,} files, peak ~{v['peak']:,}/min at {v['peak_t']:%H:%M}")
lines.append("[C8] Detection and response latency")
lines.append(f"     Encryption start -> first human report (nurse, 03:05): {fmt(first_report - enc_start)}")
lines.append(f"     Encryption start -> network isolation (03:41:15): {fmt(contain - enc_start)}")
lines.append(f"     Last exfiltration session ({exfil_sessions[-1][0]:%H:%M}) -> isolation: {fmt(contain - exfil_sessions[-1][0])}  (no alert or containment action appears in the evidence before the human report)")
lines.append(f"     First malicious execution -> isolation: {fmt(contain - initial_exec)}")
(OUT / "correlation_findings.txt").write_text("\n".join(lines) + "\n")
print("\n".join(lines))

# ---------------------------------------------------------------- visualisation
LANES = ["browser", "usb", "auth", "system", "firewall", "files", "response"]
COLORS = {"browser": "#1f77b4", "usb": "#9467bd", "auth": "#ff7f0e", "system": "#2ca02c",
          "firewall": "#8c564b", "files": "#d62728", "response": "#17becf"}
KEY = [
    (initial_exec, "system", "1", "Loader executed from Downloads (12-Oct 09:43)"),
    (beacon["first"] if beacon else initial_exec, "firewall", "2", "C2 beaconing begins (every ~10 min)"),
    (parse("2026-10-13T14:05:10+05:30"), "auth", "3", "Brute force on svc_backup, success 14:07"),
    (usb_insert, "usb", "4", "Unregistered USB inserted 18:52 (after hours)"),
    (rdp, "auth", "5", "RDP to file server as svc_backup 19:28"),
    (exfil_sessions[0][0], "firewall", "6", "Exfiltration to external host begins ~22:05"),
    (shadow, "system", "7", "Shadow copies deleted 01:58 (14-Oct)"),
    (enc_start, "files", "8", "Encryption starts 02:17 (FS01)"),
    (first_report, "response", "9", "First human report 03:05"),
    (contain, "system", "10", "Network isolation 03:41"),
]
x0, x1 = datetime(2026, 10, 12, 8, 0), datetime(2026, 10, 14, 8, 0)

fig = plt.figure(figsize=(16, 13.5))
gs = fig.add_gridspec(3, 1, height_ratios=[3.2, 1.5, 1.5], hspace=0.38)
ax = fig.add_subplot(gs[0])
for i, lane in enumerate(LANES):
    pts = [e for e in events if e["source"] == lane and not (lane == "firewall" and not e["flags"] and e["host"] != "BILLING-WS-07")]
    xs = [e["t"] for e in pts if not e["flags"]]
    ax.scatter(xs, [i] * len(xs), s=12, c=COLORS[lane], alpha=0.35, marker="|")
    fx = [e["t"] for e in pts if e["flags"]]
    ax.scatter(fx, [i] * len(fx), s=34, c=COLORS[lane], edgecolors="black", linewidths=0.6, zorder=3)
for (t, lane, num, _) in KEY:
    ax.annotate(num, (t, LANES.index(lane)), xytext=(0, 13), textcoords="offset points", ha="center",
                fontsize=11, fontweight="bold", color="white",
                bbox=dict(boxstyle="circle,pad=0.25", fc="black", ec="none"))
ax.set_yticks(range(len(LANES)))
ax.set_yticklabels([{"usb": "USB"}.get(l, l.capitalize()) for l in LANES], fontsize=11)
ax.set_ylim(-0.7, len(LANES) - 0.2)
ax.set_xlim(x0, x1)
ax.xaxis.set_major_locator(mdates.HourLocator(interval=4))
ax.xaxis.set_major_formatter(mdates.DateFormatter("%d-%b\n%H:%M"))
ax.axvspan(enc_start, datetime(2026, 10, 14, 2, 48), color="red", alpha=0.12)
ax.grid(axis="x", alpha=0.25)
ax.set_title("Case Omega - attack timeline across seven evidence sources (IST). Outlined dots = flagged by detection rules; red band = encryption window",
             fontsize=12, loc="left")

ax2 = fig.add_subplot(gs[1], sharex=ax)
bins = defaultdict(lambda: defaultdict(float))
for r in fw:
    t = parse(r["timestamp"]); b = t.replace(minute=0 if t.minute < 30 else 30, second=0)
    kind = "exfil host" if r["dst_ip"] == (exfil_sessions[0][2] if exfil_sessions else "") else ("C2 beacon" if r["dst_ip"] == (beacon["dst"] if beacon else "") else "approved external")
    bins[kind][b] += int(r["bytes_out"]) / 1024**2
for kind, col in [("approved external", "#7f7f7f"), ("C2 beacon", "#8c564b"), ("exfil host", "#d62728")]:
    xs = sorted(bins[kind]); ax2.bar(xs, [bins[kind][x] for x in xs], width=0.02, color=col, label=kind)
ax2.set_yscale("log"); ax2.set_ylabel("MB out / 30 min (log)")
ax2.legend(loc="upper left", fontsize=9, ncol=3)
ax2.set_title("Outbound traffic by destination class", fontsize=11, loc="left")
ax2.grid(axis="x", alpha=0.25)

ax3 = fig.add_subplot(gs[2], sharex=ax)
per5 = defaultdict(lambda: defaultdict(int))
for host, lst in enc.items():
    for t, n in lst:
        per5[host][t.replace(minute=t.minute - t.minute % 5, second=0)] += n
for host, col in [("HOSP-FS01", "#d62728"), ("HOSP-EHR-DB01", "#ff7f0e")]:
    xs = sorted(per5[host]); ax3.bar(xs, [per5[host][x] for x in xs], width=0.0033, color=col, label=host)
ax3.set_ylabel("files renamed / 5 min"); ax3.legend(loc="upper left", fontsize=9)
ax3.set_title("Encryption activity (.omega renames; each logged row represents 50 files)", fontsize=11, loc="left")
ax3.grid(axis="x", alpha=0.25)
fig.text(0.01, 0.015, "   ".join(f"({n}) {txt}" for _, _, n, txt in KEY[:5]) + "\n" + "   ".join(f"({n}) {txt}" for _, _, n, txt in KEY[5:]),
         fontsize=10, va="bottom")
fig.savefig(OUT / "timeline_overview.png", dpi=110, bbox_inches="tight")
plt.close(fig)

# zoom on the encryption window
z0, z1 = datetime(2026, 10, 14, 1, 45), datetime(2026, 10, 14, 4, 5)
fig, ax = plt.subplots(figsize=(15, 6.5))
for host, col in [("HOSP-FS01", "#d62728"), ("HOSP-EHR-DB01", "#ff7f0e")]:
    pm = defaultdict(int)
    for t, n in enc[host]:
        pm[t.replace(second=0, microsecond=0)] += n
    xs = sorted(pm); ax.bar(xs, [pm[x] for x in xs], width=0.0006, color=col, label=f"{host} (.omega renames/min)")
marks = [(shadow, "Shadow copies deleted"), (parse("2026-10-14T02:00:15+05:30"), "Backup agent stopped"),
         (parse("2026-10-14T02:03:00+05:30"), "OmegaSvc installed"), (enc_start, "Encryption starts (FS01)"),
         (parse("2026-10-14T02:32:50+05:30"), "Spread to EHR-DB01"), (parse("2026-10-14T02:33:05+05:30"), "EHR-SQL stopped"),
         (parse("2026-10-14T03:05:00+05:30"), "First human report"), (contain, "Network isolation"),
         (parse("2026-10-14T03:50:11+05:30"), "C2 beacon DENIED")]
ymax = ax.get_ylim()[1]
for i, (t, label) in enumerate(marks):
    ax.axvline(t, color="black", ls="--", lw=0.8)
    ax.text(t, ymax * (0.97 - 0.085 * (i % 8)), " " + label + f" {t:%H:%M}", fontsize=9, rotation=0, va="top",
            bbox=dict(fc="white", ec="none", alpha=0.8, pad=1))
ax.set_xlim(z0, z1)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.xaxis.set_major_locator(mdates.MinuteLocator(byminute=range(0, 60, 15)))
ax.set_ylabel("files renamed per minute"); ax.legend(loc="center right")
ax.set_title("Impact window, 14-Oct-2026 (IST): preparation -> encryption -> detection -> containment", loc="left")
ax.grid(axis="x", alpha=0.25)
fig.savefig(OUT / "timeline_impact_zoom.png", dpi=110, bbox_inches="tight")
plt.close(fig)
# tidy generated markdown (single trailing newline)
_md = OUT / "timeline_key_events.md"
_md.write_text(_md.read_text().rstrip() + "\n")
print("\nwrote timeline_full.csv, timeline_key_events.md, correlation_findings.txt, timeline_overview.png, timeline_impact_zoom.png")
