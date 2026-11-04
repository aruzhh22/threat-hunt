"""
Week 10 - Learning APT Techniques
Builds two outputs from ttp_mapping.csv:
  1. apt29_vs_insider_layer.json        -> import into MITRE ATT&CK Navigator
  2. ttp_overlap_matrix.png            -> picture for the README

Usage (from the repository root):
    python build_layer.py
"""
import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parent
CSV = ROOT / "ttp_mapping.csv"
LAYER = ROOT / "apt29_vs_insider_layer.json"
PNG = ROOT / "ttp_overlap_matrix.png"

ACTORS = {
    "apt29": ("APT29", "#2a78d6"),
    "dprk_it_workers": ("DPRK IT workers", "#eb6834"),
    "physical_insider": ("Physical insider", "#1baf7a"),
}
TACTIC_ORDER = [
    "Initial Access", "Credential Access", "Persistence", "Defense Evasion",
    "Command and Control", "Collection", "Exfiltration", "Impact",
]

df = pd.read_csv(CSV)
df["tactic"] = pd.Categorical(df["tactic"], TACTIC_ORDER, ordered=True)
df = df.sort_values(["tactic", "technique_id"]).reset_index(drop=True)
df["score"] = df[list(ACTORS)].sum(axis=1)


# ---------- 1. ATT&CK Navigator layer ----------
def who(row):
    return ", ".join(name for key, (name, _) in ACTORS.items() if getattr(row, key))


layer = {
    "name": "Week 10 - APT29 vs Physical Insider",
    "versions": {"layer": "4.5", "navigator": "5.1.0"},
    "domain": "enterprise-attack",
    "description": "Score = how many of the 3 actors use the technique "
                   "(APT29, DPRK IT workers, physical insider).",
    "gradient": {"colors": ["#d6e6f8", "#6fa6e6", "#1d5aa6"],
                 "minValue": 1, "maxValue": 3},
    "legendItems": [
        {"label": "1 actor", "color": "#d6e6f8"},
        {"label": "2 actors", "color": "#6fa6e6"},
        {"label": "3 actors (overlap - hunt here first)", "color": "#1d5aa6"},
    ],
    "techniques": [
        {
            "techniqueID": r.technique_id,
            "score": int(r.score),
            "comment": f"Used by: {who(r)}. APT29: {r.apt29_example}. "
                       f"Insider: {r.insider_equivalent}. Logs: {r.our_log_source}",
            "enabled": True,
        }
        for r in df.itertuples()
    ],
    "hideDisabled": False,
}
LAYER.write_text(json.dumps(layer, indent=2), encoding="utf-8")


# ---------- 2. Overlap matrix image ----------
labels = [f"{r.technique_id}  {r.technique_name}" for r in df.itertuples()]
n = len(df)
fig, ax = plt.subplots(figsize=(8, 0.34 * n + 0.6), dpi=150)
fig.patch.set_facecolor("#fcfcfb")
ax.set_facecolor("#fcfcfb")

for col, (key, (_, color)) in enumerate(ACTORS.items()):
    for row, used in enumerate(df[key]):
        ax.add_patch(plt.Rectangle(
            (col + 0.08, row + 0.1), 0.84, 0.8,
            facecolor=color if used else "#ecebe8", edgecolor="#fcfcfb",
            linewidth=2, joinstyle="round"))

# tactic separators + labels
prev = None
for row, tac in enumerate(df["tactic"]):
    if tac != prev:
        if row:
            ax.axhline(row, color="#c3c2b7", linewidth=0.8, xmax=1.35, clip_on=False)
        ax.text(3.15, row + 0.55, tac, va="center", fontsize=8,
                color="#52514e", style="italic")
        prev = tac

ax.set_xlim(0, 3)
ax.set_ylim(n, 0)
ax.set_xticks([0.5, 1.5, 2.5])
ax.set_xticklabels([v[0] for v in ACTORS.values()], fontsize=9, color="#0b0b0b")
ax.xaxis.tick_top()
ax.set_yticks([i + 0.5 for i in range(n)])
ax.set_yticklabels(labels, fontsize=8, color="#0b0b0b")
ax.tick_params(length=0)
for s in ax.spines.values():
    s.set_visible(False)

shared = int((df["score"] == 3).sum())
ax.set_title(f"Who uses which ATT&CK technique  -  {shared} techniques shared by all three",
             fontsize=11, color="#0b0b0b", loc="left", pad=28)
ax.text(-2.6, n + 1.0, "Filled = documented use. Sources: MITRE ATT&CK G0016, Microsoft, "
         "Check Point, US DOJ / FBI PSAs.", fontsize=7, color="#52514e", clip_on=False)
fig.savefig(PNG, facecolor=fig.get_facecolor(), bbox_inches="tight")

print(f"Techniques: {n} | shared by all 3: {shared}")
print(df.groupby("tactic", observed=True)["score"].count().to_string())
print(f"Saved {LAYER.name} and {PNG.name}")
