#!/usr/bin/env python3
"""
Benchmark Runner - Runs Rust host benchmarks and generates SVG graphs for progress reports.
"""

import json
import subprocess
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

OUTPUT_DIR = Path("graphs")
RESULTS_FILE = Path("benchmark_results.json")

COLORS = {
    "present_80": "#E63946",
    "present_128": "#F4A261",
    "speck64_96": "#2A9D8F",
    "speck64_128": "#264653",
    "ascon_128": "#9B5DE5",
    "present_ecb": "#E63946",
    "present_cbc": "#F4A261",
    "speck_ecb": "#2A9D8F",
    "speck_cbc": "#264653",
    "speck_ctr": "#9B5DE5",
}


def run_benchmarks():
    """Run the Rust benchmarks and save JSON output."""
    print("Running Rust benchmarks...")

    result = subprocess.run(
        [
            "cargo",
            "test",
            "--no-default-features",
            "--features",
            "std",
            "benchmark_host",
            "--",
            "--nocapture",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent,
    )

    output = result.stdout + result.stderr

    start = output.find("{")
    end = output.rfind("}") + 1

    if start == -1 or end == 0:
        print("Error: Could not find JSON output")
        print("Output:", output[-1000:])
        return None

    json_str = output[start:end]
    data = json.loads(json_str)

    with open(RESULTS_FILE, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Benchmarks complete. Results saved to {RESULTS_FILE}")
    return data


def load_results():
    """Load existing benchmark results from file."""
    if RESULTS_FILE.exists():
        with open(RESULTS_FILE, "r") as f:
            return json.load(f)
    return None


def ensure_output_dir():
    """Create output directory for graphs."""
    OUTPUT_DIR.mkdir(exist_ok=True)


def plot_block_cipher_comparison(data):
    """Generate block cipher comparison bar chart."""
    fig, ax = plt.subplots(figsize=(12, 6))

    ciphers = data["block_ciphers"]
    names = ["PRESENT-80", "PRESENT-128", "SPECK64/96", "SPECK64/128", "ASCON-128"]
    keys = ["present_80", "present_128", "speck64_96", "speck64_128", "ascon_128"]

    x = range(len(names))
    width = 0.35

    mbps = [ciphers[k]["mbps"] for k in keys]
    colors = [COLORS[k] for k in keys]

    bars = ax.bar(x, mbps, width, color=colors, edgecolor="black", linewidth=1.2)

    ax.set_xlabel("Cipher", fontsize=12, fontweight="bold")
    ax.set_ylabel("Throughput (MB/s)", fontsize=12, fontweight="bold")
    ax.set_title(
        "Block Cipher Performance Comparison (Host)", fontsize=14, fontweight="bold"
    )
    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=11)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)

    for bar, val in zip(bars, mbps):
        ax.annotate(
            f"{val:.1f}",
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )

    plt.tight_layout()
    fig.savefig(
        OUTPUT_DIR / "block_cipher_comparison.svg", format="svg", bbox_inches="tight"
    )
    plt.close()
    print(f"Generated: {OUTPUT_DIR / 'block_cipher_comparison.svg'}")


def plot_mode_comparison(data):
    """Generate mode comparison grouped bar chart."""
    fig, ax = plt.subplots(figsize=(12, 6))

    modes = data["modes"]

    present_modes = ["present_ecb", "present_cbc"]
    present_names = ["PRESENT\nECB", "PRESENT\nCBC"]
    present_mbps = [modes[m]["mbps"] for m in present_modes]

    speck_modes = ["speck_ecb", "speck_cbc", "speck_ctr"]
    speck_names = ["SPECK\nECB", "SPECK\nCBC", "SPECK\nCTR"]
    speck_mbps = [modes[m]["mbps"] for m in speck_modes]

    x1 = range(len(present_names))
    x2 = [x + 0.4 for x in range(len(speck_names))]

    bars1 = ax.bar(
        x1,
        present_mbps,
        0.35,
        color=[COLORS[m] for m in present_modes],
        edgecolor="black",
        linewidth=1.2,
        label="PRESENT",
    )
    bars2 = ax.bar(
        x2,
        speck_mbps,
        0.35,
        color=[COLORS[m] for m in speck_modes],
        edgecolor="black",
        linewidth=1.2,
        label="SPECK",
    )

    ax.set_xlabel("Mode", fontsize=12, fontweight="bold")
    ax.set_ylabel("Throughput (MB/s)", fontsize=12, fontweight="bold")
    ax.set_title(
        "Block Cipher Mode Comparison (64-byte blocks)", fontsize=14, fontweight="bold"
    )
    ax.set_xticks([0, 0.4, 1, 1.4, 2])
    ax.set_xticklabels(["ECB", "", "CBC", "", "CTR"])
    ax.legend(loc="upper right", fontsize=10)
    ax.grid(axis="y", alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)

    for bars in [bars1, bars2]:
        for bar in bars:
            ax.annotate(
                f"{bar.get_height():.1f}",
                xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                ha="center",
                va="bottom",
                fontsize=9,
            )

    plt.tight_layout()
    fig.savefig(OUTPUT_DIR / "mode_comparison.svg", format="svg", bbox_inches="tight")
    plt.close()
    print(f"Generated: {OUTPUT_DIR / 'mode_comparison.svg'}")


def plot_ascon_breakdown(data):
    """Generate ASCON phase breakdown stacked bar chart."""
    fig, ax = plt.subplots(figsize=(10, 6))

    phases = data["ascon_phases"]
    phase_names = ["Init", "Absorb", "Encrypt", "Finalize"]
    phase_keys = ["init", "absorb", "encrypt", "finalize"]
    phase_values = [phases[k] for k in phase_keys]

    colors = ["#E63946", "#F4A261", "#2A9D8F", "#9B5DE5"]

    bars = ax.barh(
        phase_names,
        phase_values,
        color=colors,
        edgecolor="black",
        linewidth=1.2,
        height=0.6,
    )

    ax.set_xlabel("Time (ns)", fontsize=12, fontweight="bold")
    ax.set_title("ASCON-128 AEAD Phase Breakdown", fontsize=14, fontweight="bold")
    ax.grid(axis="x", alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)

    total = sum(phase_values)
    for bar, val in zip(bars, phase_values):
        percentage = (val / total) * 100
        ax.annotate(
            f"{val:.0f} ns ({percentage:.1f}%)",
            xy=(bar.get_width(), bar.get_y() + bar.get_height() / 2),
            ha="left",
            va="center",
            fontsize=10,
            fontweight="bold",
            xytext=(5, 0),
            textcoords="offset points",
        )

    ax.set_xlim(0, max(phase_values) * 1.4)
    plt.tight_layout()
    fig.savefig(OUTPUT_DIR / "ascon_breakdown.svg", format="svg", bbox_inches="tight")
    plt.close()
    print(f"Generated: {OUTPUT_DIR / 'ascon_breakdown.svg'}")


def plot_scaling_analysis(data):
    """Generate scaling analysis line chart."""
    fig, ax = plt.subplots(figsize=(12, 7))

    scaling = data["scaling"]

    datasets = [
        ("present_80", "PRESENT-80", "#E63946"),
        ("present_128", "PRESENT-128", "#F4A261"),
        ("speck64_128", "SPECK64/128", "#264653"),
        ("ascon_128", "ASCON-128", "#9B5DE5"),
    ]

    for key, label, color in datasets:
        points = scaling[key]
        x_vals = [int(p[0]) for p in points]
        y_vals = [p[1] for p in points]
        ax.plot(
            x_vals,
            y_vals,
            marker="o",
            markersize=8,
            linewidth=2.5,
            color=color,
            label=label,
        )

    ax.set_xlabel("Data Size (bytes)", fontsize=12, fontweight="bold")
    ax.set_ylabel("Time (ns)", fontsize=12, fontweight="bold")
    ax.set_title("Performance Scaling with Data Size", fontsize=14, fontweight="bold")
    ax.set_xscale("log", base=2)
    ax.set_xticks([8, 16, 32, 64, 128, 256])
    ax.set_xticklabels(["8", "16", "32", "64", "128", "256"])
    ax.legend(loc="upper left", fontsize=10)
    ax.grid(True, alpha=0.3, linestyle="--")
    ax.set_axisbelow(True)

    plt.tight_layout()
    fig.savefig(OUTPUT_DIR / "scaling_analysis.svg", format="svg", bbox_inches="tight")
    plt.close()
    print(f"Generated: {OUTPUT_DIR / 'scaling_analysis.svg'}")


def main():
    ensure_output_dir()

    data = load_results()
    if data is None:
        data = run_benchmarks()

    if data is None:
        print("Failed to get benchmark data")
        return 1

    print("\nGenerating graphs...")
    plot_block_cipher_comparison(data)
    plot_mode_comparison(data)
    plot_ascon_breakdown(data)
    plot_scaling_analysis(data)

    print(f"\nAll graphs saved to {OUTPUT_DIR}/")
    print("Generated files:")
    for f in OUTPUT_DIR.glob("*.svg"):
        print(f"  - {f}")

    return 0


if __name__ == "__main__":
    exit(main())
