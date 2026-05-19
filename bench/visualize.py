#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["matplotlib", "numpy", "pandas", "jinja2"]
# ///
"""Visualise Criterion benchmark results for the BTP cipher suite.

Produces publication-ready PDF + PNG plots for the research paper.
"""

import json
import re
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd

CRITERION_DIR = Path("target/criterion")
OUTPUT_DIR = Path("bench_results")
HOST_CPU_MHZ = 2400.0
RP2040_MHZ = 133.0

plt.rcParams.update(
    {
        "font.size": 11,
        "axes.labelsize": 12,
        "axes.titlesize": 13,
        "legend.fontsize": 9,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "lines.linewidth": 1.8,
        "lines.markersize": 6,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "grid.alpha": 0.25,
    }
)

COLORS = {
    "ascon-aead128": "#0077bb",
    "ascon-hash256": "#33bbee",
    "ascon-hash": "#009988",
    "speck-64-96-ecb": "#ee7733",
    "speck-64-96-cbc": "#cc5500",
    "speck-64-96-ctr": "#aa4400",
    "speck-64-128-ecb": "#ff9900",
    "speck-64-128-cbc": "#dd7700",
    "speck-64-128-ctr": "#bb5500",
    "present-80-ecb": "#cc3311",
    "present-80-cbc": "#aa2255",
    "present-80-ctr": "#dd1144",
    "present-128-ecb": "#aa66cc",
    "present-128-cbc": "#884499",
    "present-128-ctr": "#775588",
}

FAMILY_MARKERS = {"ascon": "D", "speck": "^", "present": "s"}
MODE_LINESTYLES = {"ecb": "-", "cbc": "--", "ctr": ":"}

# Human-readable labels for paper legends
LABELS = {
    "ascon-aead128": "ASCON-AEAD128",
    "ascon-hash256": "ASCON-Hash256",
    "ascon-hash": "ASCON-Hash",
    "speck-64-96-ecb": "SPECK-64/96 ECB",
    "speck-64-96-cbc": "SPECK-64/96 CBC",
    "speck-64-96-ctr": "SPECK-64/96 CTR",
    "speck-64-128-ecb": "SPECK-64/128 ECB",
    "speck-64-128-cbc": "SPECK-64/128 CBC",
    "speck-64-128-ctr": "SPECK-64/128 CTR",
    "present-80-ecb": "PRESENT-80 ECB",
    "present-80-cbc": "PRESENT-80 CBC",
    "present-80-ctr": "PRESENT-80 CTR",
    "present-128-ecb": "PRESENT-128 ECB",
    "present-128-cbc": "PRESENT-128 CBC",
    "present-128-ctr": "PRESENT-128 CTR",
}

FAST_GROUPS = [
    "ascon-aead128",
    "ascon-hash256",
    "speck-64-96-ecb",
    "speck-64-96-cbc",
    "speck-64-96-ctr",
    "speck-64-128-ecb",
    "speck-64-128-cbc",
    "speck-64-128-ctr",
]
SLOW_GROUPS = [
    "present-80-ecb",
    "present-80-cbc",
    "present-80-ctr",
    "present-128-ecb",
    "present-128-cbc",
    "present-128-ctr",
]
ALL_CIPHER_GROUPS = FAST_GROUPS + SLOW_GROUPS


def get_family(group: str) -> str:
    for fam in ("ascon", "speck", "present"):
        if fam in group:
            return fam
    return "unknown"


def get_mode(group: str) -> str:
    if "-cbc" in group:
        return "cbc"
    if "-ctr" in group:
        return "ctr"
    return "ecb"


def parse_json(p):
    with open(p) as f:
        d = json.load(f)
    return d["mean"]["point_estimate"], d["mean"]["confidence_interval"]


def parse_id(bench_id, group):
    if group == "ascon-aead128":
        m = re.match(r"ad(\d+)/(\d+)", bench_id)
        if m:
            return int(m.group(2)), int(m.group(1)), "aead"
        m = re.match(r"pt(\d+)_ad(\d+)", bench_id)
        if m:
            return int(m.group(1)), int(m.group(2)), "aead"
    elif group in LABELS:
        m = re.match(r"(?:len)?(\d+)", bench_id)
        if m:
            return int(m.group(1)), 0, "cipher"
    elif group == "ascon-phases":
        return 0, 0, "phase"
    return None


def collect():
    rows = []
    for p in CRITERION_DIR.rglob("*/new/estimates.json"):
        parts = p.parts
        try:
            i = parts.index("criterion")
        except ValueError:
            continue

        group = parts[i + 1]
        phase_names = ["init", "absorb_ad", "encrypt", "finalize"]
        if parts[i + 2] in phase_names:
            bench_id = parts[i + 2]
            phase = bench_id
        else:
            bench_id = "/".join(parts[i + 2 : -2])
            phase = None

        parsed = parse_id(bench_id, group)
        if not parsed:
            continue

        pt, ad, typ = parsed
        mean, ci = parse_json(p)
        rows.append(
            {
                "group": group,
                "bench_id": bench_id,
                "pt": pt,
                "ad": ad,
                "type": typ,
                "phase": phase,
                "mean": mean,
                "low": ci["lower_bound"],
                "high": ci["upper_bound"],
            }
        )
    return pd.DataFrame(rows)


def collect_aggregated():
    agg_csv = OUTPUT_DIR / "aggregated_results.csv"
    if not agg_csv.exists():
        print(f"Warning: {agg_csv} not found. Run bench/aggregate_runs.py first.")
        return None
    df = pd.read_csv(agg_csv)
    print(
        f"Loaded aggregated data: {len(df)} benchmarks from {df['num_runs'].iloc[0]} runs"
    )
    return df


def compute(df, metric):
    df = df.copy()
    pt = df["pt"].replace(0, 1)
    has_agg = "throughput_mean" in df.columns
    if metric == "throughput":
        if has_agg:
            df = df.assign(
                y=df["throughput_mean"],
                yl=df["throughput_mean"] - df["throughput_std"],
                yh=df["throughput_mean"] + df["throughput_std"],
            )
        else:
            df = df.assign(
                y=pt / df["mean"] * 1000,
                yl=pt / df["high"] * 1000,
                yh=pt / df["low"] * 1000,
            )
    elif metric == "cpb":
        if has_agg:
            df = df.assign(
                y=df["cpb_mean"],
                yl=df["cpb_mean"] - df["cpb_std"],
                yh=df["cpb_mean"] + df["cpb_std"],
            )
        else:
            df = df.assign(
                y=df["mean"] * HOST_CPU_MHZ / 1000 / pt,
                yl=df["low"] * HOST_CPU_MHZ / 1000 / pt,
                yh=df["high"] * HOST_CPU_MHZ / 1000 / pt,
            )
    return df


def _plot_lines(ax, df, groups, metric="throughput", fill_alpha=0.13):
    """Draw one line+CI-band per group onto *ax*."""
    for g in sorted(groups):
        sub = df[df["group"] == g].sort_values("pt")
        if sub.empty:
            continue
        sub = compute(sub, metric)
        color = COLORS.get(g)
        marker = FAMILY_MARKERS.get(get_family(g), "o")
        ls = MODE_LINESTYLES.get(get_mode(g), "-")
        label = LABELS.get(g, g)
        ax.plot(sub["pt"], sub["y"], marker=marker, ls=ls, label=label, color=color)
        ax.fill_between(sub["pt"], sub["yl"], sub["yh"], color=color, alpha=fill_alpha)


def _configure_log_axes(ax, ylabel, xbase=2, ybase=10):
    ax.set_xscale("log", base=xbase)
    ax.set_yscale("log", base=ybase)
    ax.set_xlabel("Message Length (bytes)")
    ax.set_ylabel(ylabel)
    ax.grid(True, which="both", ls="--", alpha=0.25)


def _add_present_note(ax):
    """Footnote explaining the PRESENT block-boundary oscillation."""
    ax.annotate(
        "Note: oscillation at small sizes reflects\n"
        "block-boundary padding (8-byte block).",
        xy=(0.03, 0.04),
        xycoords="axes fraction",
        fontsize=7.5,
        color="#666666",
        style="italic",
    )


def _save(fname):
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / f"{fname}.pdf", bbox_inches="tight")
    plt.savefig(OUTPUT_DIR / f"{fname}.png", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Saved: {fname}.png/pdf")


def plot_metric_split(df, metric, ylabel, fname, title):
    """Two-panel overview: fast ciphers left | PRESENT right."""
    dfp = df[df["type"] != "phase"]

    fig, (ax_f, ax_s) = plt.subplots(1, 2, figsize=(13, 4.5))

    _plot_lines(ax_f, dfp[dfp["group"].isin(FAST_GROUPS)], FAST_GROUPS, metric)
    _configure_log_axes(ax_f, ylabel)
    ax_f.set_title("ASCON & SPECK Family")
    ax_f.legend(frameon=False, fontsize=8, ncol=2)

    _plot_lines(ax_s, dfp[dfp["group"].isin(SLOW_GROUPS)], SLOW_GROUPS, metric)
    ax_s.set_xscale("log", base=2)
    ax_s.set_xlabel("Message Length (bytes)")
    ax_s.set_ylabel(ylabel)
    ax_s.set_title("PRESENT Family")
    ax_s.grid(True, which="both", ls="--", alpha=0.25)
    ax_s.legend(frameon=False, fontsize=8)
    _add_present_note(ax_s)

    fig.suptitle(title, fontsize=14, fontweight="bold")
    _save(fname)


def plot_fast_ciphers_comparison(df):
    reps = ["ascon-aead128", "ascon-hash256", "speck-64-96-ecb"]
    dfp = df[(df["type"] != "phase") & (df["group"].isin(reps))]

    fig, ax = plt.subplots(figsize=(6.5, 4))
    _plot_lines(ax, dfp, reps)
    _configure_log_axes(ax, "Throughput (MB/s)")
    ax.set_title("Fast Cipher Representatives: ASCON vs. SPECK-64/96 ECB")
    ax.legend(frameon=False, fontsize=9)
    _save("fast_ciphers_comparison")


def plot_present_modes(df):
    """All PRESENT variants: key size × mode."""
    groups = ["present-80-ecb", "present-80-cbc", "present-128-ecb", "present-128-cbc"]
    dfp = df[(df["type"] != "phase") & (df["group"].isin(groups))]

    fig, ax = plt.subplots(figsize=(6.5, 4))
    _plot_lines(ax, dfp, groups)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("Message Length (bytes)")
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_title("PRESENT: Key Size & Mode Comparison")
    ax.grid(True, which="both", ls="--", alpha=0.25)
    ax.legend(frameon=False, fontsize=9)
    _add_present_note(ax)
    _save("present_ciphers_comparison")


def plot_all_ciphers_loglog(df):
    """One ECB representative per family — clean overview."""
    reps = [
        "ascon-aead128",
        "ascon-hash256",
        "speck-64-96-ecb",
        "present-80-ecb",
        "present-128-ecb",
    ]
    dfp = df[(df["type"] != "phase") & (df["group"].isin(reps))]

    fig, ax = plt.subplots(figsize=(6.5, 4))
    _plot_lines(ax, dfp, reps)
    _configure_log_axes(ax, "Throughput (MB/s)")
    ax.set_title("Full Performance Spectrum (one representative per family)")
    ax.legend(frameon=False, fontsize=9)
    _save("all_ciphers_loglog")


def plot_phases(df):
    dfp = df[df["type"] == "phase"]
    if dfp.empty:
        print("No phase data found")
        return

    has_agg = "throughput_mean" in df.columns
    phase_order = ["init", "absorb_ad", "encrypt", "finalize"]
    phase_labels = {
        "init": "Init",
        "absorb_ad": "Absorb AD",
        "encrypt": "Encrypt",
        "finalize": "Finalize",
    }
    phase_colors = {
        "init": "#0077bb",
        "absorb_ad": "#33bbee",
        "encrypt": "#ee7733",
        "finalize": "#cc3311",
    }

    fig, ax = plt.subplots(figsize=(6.5, 4))
    bar_width = 0.55
    for i, phase in enumerate(phase_order):
        pdata = dfp[dfp["phase"] == phase]
        if pdata.empty:
            continue
        mean_val = pdata["mean"].iloc[0]
        if has_agg and "std" in pdata.columns:
            std_val = pdata["std"].iloc[0]
            yerr_low = yerr_high = std_val
        else:
            yerr_low = mean_val - pdata["low"].iloc[0]
            yerr_high = pdata["high"].iloc[0] - mean_val

        ax.bar(
            i,
            mean_val,
            width=bar_width,
            color=phase_colors.get(phase, "#aec7e8"),
            alpha=0.85,
            label=phase_labels.get(phase, phase),
            edgecolor="white",
            linewidth=1,
        )
        ax.errorbar(
            i,
            mean_val,
            yerr=[[yerr_low], [yerr_high]],
            fmt="none",
            color="black",
            capsize=4,
            capthick=1.5,
        )
        # Label offset: 4% above bar on linear scale
        ax.text(
            i,
            mean_val * 1.04,
            f"{mean_val:.0f} ns",
            ha="center",
            va="bottom",
            fontsize=9,
            color="#333333",
        )

    suffix = "Std Dev" if has_agg else "95% CI"
    ax.set_ylabel("Time (ns)")
    ax.set_title(f"ASCON-AEAD Phase Breakdown (with {suffix})")
    ax.set_xticks(range(len(phase_order)))
    ax.set_xticklabels([phase_labels[p] for p in phase_order], fontsize=10)
    ax.grid(True, ls="--", alpha=0.25, axis="y")
    ax.set_ylim(bottom=0)
    _save("ascon_phases")


def plot_mode_overhead(df):
    """3-panel: PRESENT (linear Y) | SPECK-64/96 (log Y) | SPECK-64/128 (log Y)."""
    panels = [
        (
            "PRESENT Mode Overhead",
            ["present-80-ecb", "present-80-cbc", "present-128-ecb", "present-128-cbc"],
            False,
        ),
        (
            "SPECK-64/96 Mode Overhead",
            ["speck-64-96-ecb", "speck-64-96-cbc", "speck-64-96-ctr"],
            True,
        ),
        (
            "SPECK-64/128 Mode Overhead",
            ["speck-64-128-ecb", "speck-64-128-cbc", "speck-64-128-ctr"],
            True,
        ),
    ]

    fig, axes = plt.subplots(1, 3, figsize=(13, 4.5))
    for ax, (title, groups, use_log) in zip(axes, panels):
        dfp = df[df["group"].isin(groups)]
        _plot_lines(ax, dfp, groups)
        ax.set_xscale("log", base=2)
        ax.set_xlabel("Message Length (bytes)")
        ax.set_ylabel("Throughput (MB/s)")
        ax.set_title(title)
        ax.grid(True, which="both", ls="--", alpha=0.25)
        ax.legend(frameon=False, fontsize=8)
        if use_log:
            ax.set_yscale("log", base=10)
        else:
            _add_present_note(ax)
    _save("mode_overhead")


def plot_present_keysize_impact(df):
    groups = ["present-80-ecb", "present-80-cbc", "present-128-ecb", "present-128-cbc"]
    dfp = df[(df["type"] != "phase") & (df["group"].isin(groups))]

    fig, ax = plt.subplots(figsize=(6.5, 4))
    _plot_lines(ax, dfp, groups)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("Message Length (bytes)")
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_title("PRESENT Key Size Impact: 80-bit vs. 128-bit")
    ax.grid(True, which="both", ls="--", alpha=0.25)
    ax.legend(frameon=False, fontsize=9)
    _add_present_note(ax)
    _save("present_keysize_impact")


def plot_combined_comparison(df):
    """Two-panel full survey: fast ciphers | PRESENT — with CI bands."""
    dfp = df[(df["type"] != "phase") & (df["group"].isin(ALL_CIPHER_GROUPS))]

    fig, (ax_f, ax_s) = plt.subplots(1, 2, figsize=(13, 5))

    _plot_lines(ax_f, dfp[dfp["group"].isin(FAST_GROUPS)], FAST_GROUPS)
    _configure_log_axes(ax_f, "Throughput (MB/s)")
    ax_f.set_title("ASCON & SPECK")
    ax_f.legend(frameon=False, fontsize=8, ncol=2)

    _plot_lines(ax_s, dfp[dfp["group"].isin(SLOW_GROUPS)], SLOW_GROUPS)
    ax_s.set_xscale("log", base=2)
    ax_s.set_xlabel("Message Length (bytes)")
    ax_s.set_ylabel("Throughput (MB/s)")
    ax_s.set_title("PRESENT")
    ax_s.grid(True, which="both", ls="--", alpha=0.25)
    ax_s.legend(frameon=False, fontsize=8)
    _add_present_note(ax_s)

    fig.suptitle("Combined Cipher & Mode Comparison", fontsize=14, fontweight="bold")
    _save("combined_comparison")


def plot_power_consumption(df):
    """Plot estimated energy per operation (nJ) vs message length - RP2040 model."""
    dfp = df[df["type"] != "phase"]

    v = RP2040_POWER["voltage_v"]
    i = RP2040_POWER["current_ma"]
    f = RP2040_POWER["frequency_hz"]
    scale = v * i / f * 1e9

    # Fast ciphers panel
    df_fast = dfp[dfp["group"].isin(FAST_GROUPS)]
    fig, (ax_f, ax_s) = plt.subplots(1, 2, figsize=(13, 4.5))

    for g in sorted(df_fast["group"].unique()):
        sub = df_fast[df_fast["group"] == g].sort_values("pt")
        if sub.empty:
            continue
        # Energy per operation = mean (ns) * MHz * scale
        # mean is in ns, so: (mean ns) * (RP2040_MHZ MHz) / 1000 * scale = nJ
        energy_per_op = sub["mean"] * RP2040_MHZ / 1000 * scale
        color = COLORS.get(g)
        marker = FAMILY_MARKERS.get(get_family(g), "o")
        ls = MODE_LINESTYLES.get(get_mode(g), "-")
        label = LABELS.get(g, g)
        ax_f.plot(
            sub["pt"], energy_per_op, marker=marker, ls=ls, label=label, color=color
        )

    ax_f.set_xscale("log", base=2)
    ax_f.set_yscale("log", base=10)
    ax_f.set_xlabel("Message Length (bytes)")
    ax_f.set_ylabel("Energy per Operation (nJ)")
    ax_f.set_title("ASCON & SPECK — Estimated Energy")
    ax_f.grid(True, which="both", ls="--", alpha=0.25)
    ax_f.legend(frameon=False, fontsize=8, ncol=2)

    # Present ciphers panel
    df_slow = dfp[dfp["group"].isin(SLOW_GROUPS)]
    for g in sorted(df_slow["group"].unique()):
        sub = df_slow[df_slow["group"] == g].sort_values("pt")
        if sub.empty:
            continue
        energy_per_op = sub["mean"] * RP2040_MHZ / 1000 * scale
        color = COLORS.get(g)
        marker = FAMILY_MARKERS.get(get_family(g), "o")
        ls = MODE_LINESTYLES.get(get_mode(g), "-")
        label = LABELS.get(g, g)
        ax_s.plot(
            sub["pt"], energy_per_op, marker=marker, ls=ls, label=label, color=color
        )

    ax_s.set_xscale("log", base=2)
    ax_s.set_yscale("log", base=10)
    ax_s.set_xlabel("Message Length (bytes)")
    ax_s.set_ylabel("Energy per Operation (nJ)")
    ax_s.set_title("PRESENT — Estimated Energy")
    ax_s.grid(True, which="both", ls="--", alpha=0.25)
    ax_s.legend(frameon=False, fontsize=8)
    ax_s.annotate(
        "Note: Estimated using RP2040\n(3.3V, 27mA @ 133MHz)",
        xy=(0.03, 0.04),
        xycoords="axes fraction",
        fontsize=7.5,
        color="#666666",
        style="italic",
    )

    fig.suptitle("Estimated Power Consumption (RP2040)", fontsize=14, fontweight="bold")
    _save("power_consumption")


MEMORY_FOOTPRINT_DATA = {
    "PRESENT-80": {
        "key_size": "80 bits (10 bytes)",
        "block_size": "64 bits (8 bytes)",
        "rounds": 32,
        "state_size": "8 bytes",
        "key_schedule": "80 bits → 32 round keys (64-bit each)",
        "rom_estimate": "~1.8 KB",
        "ram_estimate": "~24 bytes",
        "notes": "S-box (64B) + round keys (256B)",
    },
    "PRESENT-128": {
        "key_size": "128 bits (16 bytes)",
        "block_size": "64 bits (8 bytes)",
        "rounds": 32,
        "state_size": "8 bytes",
        "key_schedule": "128 bits → 32 round keys (64-bit each)",
        "rom_estimate": "~2.2 KB",
        "ram_estimate": "~24 bytes",
        "notes": "Doubled S-box for 128-bit key schedule",
    },
    "SPECK-64/96": {
        "key_size": "96 bits (12 bytes)",
        "block_size": "64 bits (8 bytes)",
        "rounds": 26,
        "state_size": "16 bytes (2×u32)",
        "key_schedule": "96-bit → 3×u32 expanded key",
        "rom_estimate": "~0.9 KB",
        "ram_estimate": "~28 bytes",
        "notes": "Pure ARX — extremely compact, no S-box",
    },
    "SPECK-64/128": {
        "key_size": "128 bits (16 bytes)",
        "block_size": "64 bits (8 bytes)",
        "rounds": 32,
        "state_size": "16 bytes (2×u32)",
        "key_schedule": "128-bit → 4×u32 expanded key",
        "rom_estimate": "~1.1 KB",
        "ram_estimate": "~32 bytes",
        "notes": "Pure ARX — highly compact on ARM Cortex-M0+",
    },
    "ASCON-AEAD128": {
        "key_size": "128 bits (16 bytes)",
        "block_size": "64 bits (8 bytes)",
        "rounds": "12 (AEAD) / 6 (hash)",
        "state_size": "40 bytes (5×u64)",
        "key_schedule": "Key + nonce initialisation",
        "rom_estimate": "~3.2 KB",
        "ram_estimate": "~48 bytes",
        "notes": "5-word permutation, complex initialisation",
    },
}

RP2040_POWER = {"voltage_v": 3.3, "current_ma": 27.0, "frequency_hz": 133_000_000}


def cycles_to_nanojoules(cycles: float) -> float:
    v = RP2040_POWER["voltage_v"]
    i = RP2040_POWER["current_ma"]
    f = RP2040_POWER["frequency_hz"]
    return cycles * v * i / f * 1e9


def generate_memory_table():
    rows = [
        {
            "Cipher": c,
            "Key Size": d["key_size"],
            "Block Size": d["block_size"],
            "State Size": d["state_size"],
            "Rounds": d["rounds"],
            "ROM (est.)": d["rom_estimate"],
            "RAM (est.)": d["ram_estimate"],
            "Notes": d.get("notes", ""),
        }
        for c, d in MEMORY_FOOTPRINT_DATA.items()
    ]
    table = pd.DataFrame(rows)
    table.to_csv(OUTPUT_DIR / "memory_footprint.csv", index=False)
    print("\nMemory Footprint Table:\n", table.to_string(index=False))
    return table


def generate_energy_table(df):
    rows, seen = [], set()
    for _, row in df[df["type"] != "phase"].iterrows():
        key = (row["group"], row["pt"])
        if key in seen:
            continue
        seen.add(key)
        cycles = row["mean"] * RP2040_MHZ / 1000
        energy_nj = cycles_to_nanojoules(cycles)
        rows.append(
            {
                "Cipher": LABELS.get(row["group"], row["group"]),
                "PT Length": row["pt"],
                "Cycles (est.)": round(cycles),
                "Energy (nJ)": round(energy_nj, 2),
                "Energy (µJ)": round(energy_nj / 1000, 3),
            }
        )
    table = (
        pd.DataFrame(rows).sort_values(["Cipher", "PT Length"]).reset_index(drop=True)
    )
    table.to_csv(OUTPUT_DIR / "energy_footprint.csv", index=False)
    print("\nEnergy Footprint Table:\n", table.to_string(index=False))
    return table


def speedup_table(df):
    base = "ascon-aead128"
    rows = []
    for pt in [64, 256, 1024]:
        base_sub = df[(df.group == base) & (df.pt == pt) & (df.ad == 0)]
        if base_sub.empty:
            continue
        base_val = base_sub.iloc[0]["mean"]
        for g in df["group"].unique():
            if g == base:
                continue
            sub = df[(df.group == g) & (df.pt == pt)]
            if sub.empty:
                continue
            rows.append((pt, LABELS.get(g, g), f"{base_val / sub.iloc[0]['mean']:.3f}"))
    table = pd.DataFrame(rows, columns=["PT", "Cipher", "Speedup vs ASCON-AEAD"])
    table.to_csv(OUTPUT_DIR / "speedup.csv", index=False)
    print("\nSpeedup table:\n", table.to_string(index=False))


def generate_latex_tables():
    mem_csv = OUTPUT_DIR / "memory_footprint.csv"
    energy_csv = OUTPUT_DIR / "energy_footprint.csv"
    speedup_csv = OUTPUT_DIR / "speedup.csv"

    if not mem_csv.exists() or not energy_csv.exists():
        print("Warning: CSV files not found, skipping LaTeX generation")
        return

    mem_df = pd.read_csv(mem_csv)
    cols = ["Cipher", "Key Size", "Block Size", "Rounds", "ROM (est.)", "RAM (est.)"]
    tex = mem_df[cols].to_latex(
        index=False,
        escape=True,
        column_format="@{}lccccr@{}",
        caption="Memory Footprint Comparison",
        label="tab:memory",
    )
    (OUTPUT_DIR / "memory_footprint.tex").write_text(tex)
    print("Saved: memory_footprint.tex")

    energy_df = pd.read_csv(energy_csv)
    tex = energy_df.to_latex(
        index=False,
        escape=True,
        column_format="@{}llccc@{}",
        caption="Energy Consumption Estimates (RP2040 @ 133 MHz)",
        label="tab:energy",
    )
    (OUTPUT_DIR / "energy_footprint.tex").write_text(tex)
    print("Saved: energy_footprint.tex")

    if speedup_csv.exists():
        tex = pd.read_csv(speedup_csv).to_latex(
            index=False,
            escape=True,
            column_format="@{}llc@{}",
            caption="Speedup Relative to ASCON-AEAD",
            label="tab:speedup",
        )
        (OUTPUT_DIR / "speedup.tex").write_text(tex)
        print("Saved: speedup.tex")


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    df = collect_aggregated()
    if df is None:
        print("No aggregated data found, collecting from single run...")
        df = collect()

    print("Loaded", len(df), "benchmarks")

    plot_metric_split(
        df,
        "throughput",
        "Throughput (MB/s)",
        "throughput_comparison",
        "Throughput Comparison",
    )
    plot_metric_split(
        df, "cpb", "Cycles per Byte", "cycles_per_byte", "Cycles per Byte Comparison"
    )

    plot_fast_ciphers_comparison(df)
    plot_present_modes(df)
    plot_all_ciphers_loglog(df)

    plot_phases(df)
    plot_mode_overhead(df)
    plot_present_keysize_impact(df)
    plot_combined_comparison(df)
    plot_power_consumption(df)

    generate_memory_table()
    generate_energy_table(df)
    speedup_table(df)
    generate_latex_tables()

    print("\nDone →", OUTPUT_DIR)


if __name__ == "__main__":
    main()
