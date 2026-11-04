"""
Week 10 - Hunting APT-style techniques with insider data
Generates a small synthetic dataset (badge + sign-in + endpoint logs) and runs
five hunts that come from the APT29 / DPRK IT worker TTP mapping.

Badge ID -> Employee ID -> User account -> System activity  (correlation from Week 3)

Usage (from the repository root):
    python hunt_insider.py
Outputs:
    employees/badge/signin/endpoint.csvsynthetic logs (no real people or companies)
    findings.csv                 hunt results
    suspect_timeline.png         timeline of the top suspect
"""
from datetime import datetime, timedelta
from pathlib import Path
import random

import matplotlib.pyplot as plt
import pandas as pd

random.seed(10)
ROOT = Path(__file__).resolve().parent
LOGS = ROOT
DAY = datetime(2026, 10, 26)  # synthetic "Monday"

# ------------------------------------------------------------------ data
employees = pd.DataFrame([
    # emp_id, badge_id, account, role, remote, resignation_notice
    ("E01", "B101", "a.nurlanov", "Engineer", False, None),
    ("E02", "B102", "d.serikova", "Engineer", False, "2026-10-26"),   # leaving
    ("E03", "B103", "m.ivanov", "HR", False, None),
    ("E04", "B104", "s.kim", "SysAdmin", False, None),
    ("E05", None, "j.miller", "Remote Dev", True, None),               # fake hire?
    ("E06", None, "r.chen", "Remote Dev", True, None),                 # fake hire?
    ("E07", None, "t.lopez", "Remote Dev", True, None),
], columns=["emp_id", "badge_id", "account", "role", "remote", "resignation"])


def t(h, m=0, d=0):
    return DAY + timedelta(days=d, hours=h, minutes=m)


badge = pd.DataFrame([
    ("B101", "IN", t(8, 55)), ("B101", "OUT", t(18, 5)),
    ("B102", "IN", t(9, 10)), ("B102", "OUT", t(17, 40)),
    ("B102", "IN", t(21, 47)), ("B102", "OUT", t(23, 2)),            # after hours
    ("B103", "IN", t(9, 0)), ("B103", "OUT", t(18, 0)),
    # B104 (sysadmin) never badged in on Monday
], columns=["badge_id", "direction", "time"])

signin = pd.DataFrame([
    ("a.nurlanov", "WS-ENG-01", "office", "10.10.1.21", t(9, 2)),
    ("a.nurlanov", "VPN", "remote", "95.56.10.4", t(13, 15)),        # VPN while badge IN
    ("d.serikova", "WS-ENG-02", "office", "10.10.1.22", t(9, 14)),
    ("d.serikova", "WS-ENG-02", "office", "10.10.1.22", t(21, 52)),
    ("m.ivanov", "WS-HR-01", "office", "10.10.2.11", t(9, 5)),
    ("s.kim", "WS-ADM-01", "office", "10.10.3.5", t(10, 30)),        # on-site, no badge
    ("j.miller", "VPN", "remote", "73.12.44.201", t(9, 0)),
    ("r.chen", "VPN", "remote", "73.12.44.201", t(9, 3)),             # same home IP
    ("t.lopez", "VPN", "remote", "24.17.90.8", t(10, 0)),
], columns=["account", "host", "location", "src_ip", "time"])

endpoint = pd.DataFrame([
    ("d.serikova", "WS-ENG-02", "process", "7z.exe a -p project_x.7z \\\\fs01\\projects\\X", t(22, 1)),
    ("d.serikova", "WS-ENG-02", "usb_connect", "SanDisk Ultra 64GB (personal)", t(22, 6)),
    ("d.serikova", "WS-ENG-02", "usb_write", "project_x.7z 3.8 GB", t(22, 9)),
    ("d.serikova", "WS-ENG-02", "file_delete", "project_x.7z (local copy)", t(22, 31)),
    ("d.serikova", "IdP", "device_register", "Personal iPhone enrolled", t(17, 10)),
    ("d.serikova", "SharePoint", "bulk_download", "1,240 files from /sites/R&D", t(16, 30)),
    ("j.miller", "LT-REM-05", "usb_connect", "ATEN KVM-over-IP adapter", t(8, 50)),
    ("r.chen", "LT-REM-06", "process", "AnyDesk.exe started", t(9, 1)),
    ("t.lopez", "LT-REM-07", "process", "code.exe", t(10, 5)),
], columns=["account", "host", "event", "detail", "time"])

for name, frame in [("employees", employees), ("badge", badge),
                    ("signin", signin), ("endpoint", endpoint)]:
    frame.to_csv(LOGS / f"{name}.csv", index=False)

# ------------------------------------------------------------------ hunts
findings = []


def add(hunt, technique, account, evidence, severity):
    findings.append(dict(hunt=hunt, technique=technique, account=account,
                         evidence=evidence, severity=severity))


acct2badge = employees.set_index("account")["badge_id"].to_dict()

# H1 - remote VPN login while badge says the person is inside (credential sharing)
for r in signin[signin.location == "remote"].itertuples():
    b = acct2badge.get(r.account)
    if not b:
        continue
    ev = badge[(badge.badge_id == b) & (badge.time <= r.time)].sort_values("time")
    if len(ev) and ev.iloc[-1].direction == "IN":
        add("H1 Badge-IN + remote VPN", "T1078 Valid Accounts", r.account,
            f"VPN from {r.src_ip} at {r.time:%H:%M} while badge {b} is IN", "High")

# H2 - office workstation login without badge entry (tailgating / shared account)
for r in signin[signin.location == "office"].itertuples():
    b = acct2badge.get(r.account)
    ins = badge[(badge.badge_id == b) & (badge.direction == "IN") &
                (badge.time <= r.time) & (badge.time.dt.date == r.time.date())]
    if ins.empty:
        add("H2 Office login, no badge", "T1078 / physical tailgating", r.account,
            f"Login on {r.host} at {r.time:%H:%M}, no badge IN that day", "Medium")

# H3 - after-hours badge + archive + USB write (classic physical exfiltration)
after = badge[(badge.direction == "IN") & (badge.time.dt.hour >= 20)]
for b in after.badge_id.unique():
    acct = employees.loc[employees.badge_id == b, "account"].iloc[0]
    ev = endpoint[endpoint.account == acct]
    if {"usb_write"} <= set(ev.event) and ev.detail.str.contains("7z").any():
        add("H3 After-hours archive -> USB", "T1560.001 + T1052.001", acct,
            "Badge IN after 20:00, 7-Zip archive, 3.8 GB written to personal USB, "
            "local copy deleted (T1070.004)", "Critical")

# H4 - leaver: bulk SharePoint download + new device on resignation day
for e in employees.dropna(subset=["resignation"]).itertuples():
    ev = set(endpoint[endpoint.account == e.account].event)
    if {"bulk_download", "device_register"} <= ev:
        add("H4 Leaver data grab", "T1213.002 + T1098.005", e.account,
            "Resignation notice + 1,240 SharePoint files + personal device enrolled",
            "High")

# H5 - laptop farm: several remote hires share one home IP, KVM / remote tools
shared = signin[signin.location == "remote"].groupby("src_ip").account.nunique()
for ip in shared[shared > 1].index:
    accts = signin[signin.src_ip == ip].account.unique()
    tools = endpoint[endpoint.account.isin(accts) &
                     endpoint.detail.str.contains("KVM|AnyDesk")]
    add("H5 Laptop-farm pattern", "T1200 + T1219 + T1090.002", ", ".join(accts),
        f"{len(accts)} 'different' remote hires on one IP {ip}; "
        f"{len(tools)} KVM / remote-access events", "High")

out = pd.DataFrame(findings)
out.to_csv(ROOT / "findings.csv", index=False)
pd.set_option("display.width", 200, "display.max_colwidth", 70)
print(out[["hunt", "account", "severity"]].to_string(index=False))

# ------------------------------------------------------------------ timeline image
sus = "d.serikova"
tl = pd.concat([
    badge[badge.badge_id == "B102"].assign(src="Badge",
                                           label=lambda x: "Badge " + x.direction),
    signin[signin.account == sus].assign(src="Sign-in",
                                         label=lambda x: "Login " + x.host),
    endpoint[endpoint.account == sus].assign(src="Endpoint / cloud",
                                             label=lambda x: x.event),
])[["time", "src", "label"]].sort_values("time")

lanes = ["Badge", "Sign-in", "Endpoint / cloud"]
fig, ax = plt.subplots(figsize=(10, 3.2), dpi=150)
fig.patch.set_facecolor("#fcfcfb"); ax.set_facecolor("#fcfcfb")
for i, lane in enumerate(lanes):
    ax.axhline(i, color="#ecebe8", linewidth=1, zorder=0)
    pts = tl[tl.src == lane]
    hrs = pts.time.dt.hour + pts.time.dt.minute / 60
    after_hours = hrs >= 20
    ax.scatter(hrs[~after_hours], [i] * (~after_hours).sum(), s=60, color="#2a78d6",
               edgecolor="#fcfcfb", linewidth=2, zorder=3)
    ax.scatter(hrs[after_hours], [i] * after_hours.sum(), s=60, color="#e34948",
               edgecolor="#fcfcfb", linewidth=2, zorder=3)
    night = []
    for k, (h, lab) in enumerate(zip(hrs, pts.label)):
        if lane == "Endpoint / cloud" and h >= 20:   # dense cluster -> number it
            hh, mm = int(h), round((h - int(h)) * 60)
            night.append(f"{hh}:{mm:02d} {lab}")
            continue
        ax.annotate(lab, (h, i), xytext=(0, 9 if k % 2 == 0 else -13),
                    textcoords="offset points", fontsize=6.5, ha="center",
                    color="#52514e")
    if night:
        ax.text(20.15, i - 0.22, "\n".join(night),
                fontsize=6.5, color="#52514e", va="top")
ax.axvspan(20, 24, color="#e34948", alpha=0.06)
ax.text(22.6, 2.45, "after hours", fontsize=7, color="#52514e")
ax.set_yticks(range(3)); ax.set_yticklabels(lanes, fontsize=8)
ax.set_xticks(range(8, 25, 2)); ax.set_xticklabels([f"{h}:00" for h in range(8, 25, 2)], fontsize=8)
ax.set_xlim(7.5, 24); ax.set_ylim(-0.6, 2.7)
for s in ax.spines.values():
    s.set_visible(False)
ax.tick_params(length=0)
ax.set_title(f"Suspect timeline - {sus} (synthetic data, resignation day)",
             fontsize=10, loc="left", color="#0b0b0b")
fig.savefig(ROOT / "suspect_timeline.png", bbox_inches="tight",
            facecolor=fig.get_facecolor())
print("Saved findings.csv and suspect_timeline.png")
