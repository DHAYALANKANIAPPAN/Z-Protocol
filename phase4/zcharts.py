import json
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

os.makedirs("charts", exist_ok=True)

# ── Load netem results ──────────────────────────────────────
with open("netem_results.json") as f:
    netem = json.load(f)

losses   = [int(k) for k in netem.keys()]
tls_avgs = [netem[str(k)]["tls"]["avg"] for k in losses]
zp_avgs  = [netem[str(k)]["zp"]["avg"]  for k in losses]

# ── Chart 1: Latency vs packet loss ────────────────────────
fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(losses, tls_avgs, 'o-', color='#E24B4A', linewidth=2, label='TLS 1.3')
ax.plot(losses, zp_avgs,  's-', color='#1D9E75', linewidth=2, label='Z-Protocol')
ax.set_xlabel("Packet Loss (%)", fontsize=12)
ax.set_ylabel("Avg Handshake Latency (ms)", fontsize=12)
ax.set_title("Handshake Latency vs Network Packet Loss", fontsize=13)
ax.legend(fontsize=11)
ax.grid(True, alpha=0.3)
ax.set_xticks(losses)
plt.tight_layout()
plt.savefig("charts/latency_vs_loss.png", dpi=150)
print("[+] Saved charts/latency_vs_loss.png")
plt.close()

# ── Chart 2: Packet size comparison ────────────────────────
labels = ['TLS 1.3\nClientHello', 'TLS 1.3\nFull Handshake', 'Z-Protocol\nFirst Packet']
sizes  = [320, 1200, 3294]
colors = ['#E24B4A', '#F09595', '#1D9E75']

fig, ax = plt.subplots(figsize=(7, 5))
bars = ax.bar(labels, sizes, color=colors, width=0.5)
ax.set_ylabel("Bytes", fontsize=12)
ax.set_title("Packet Size Comparison", fontsize=13)
for bar, val in zip(bars, sizes):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 30,
            f'{val}B', ha='center', fontsize=11, fontweight='bold')
ax.set_ylim(0, max(sizes) * 1.15)
ax.grid(True, axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig("charts/packet_size_comparison.png", dpi=150)
print("[+] Saved charts/packet_size_comparison.png")
plt.close()

# ── Chart 3: KEM speed comparison ──────────────────────────
fig, ax = plt.subplots(figsize=(6, 5))
algos  = ['X25519\n(classical)', 'ML-KEM-1024\n(post-quantum)']
speeds = [0.1457, 0.0871]
colors = ['#E24B4A', '#1D9E75']
bars   = ax.bar(algos, speeds, color=colors, width=0.4)
ax.set_ylabel("Avg Time per Operation (ms)", fontsize=12)
ax.set_title("KEM Speed: Classical vs Post-Quantum", fontsize=13)
for bar, val in zip(bars, speeds):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.002,
            f'{val}ms', ha='center', fontsize=11, fontweight='bold')
ax.set_ylim(0, max(speeds) * 1.25)
ax.grid(True, axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig("charts/kem_speed_comparison.png", dpi=150)
print("[+] Saved charts/kem_speed_comparison.png")
plt.close()

# ── Chart 4: Error count under packet loss ──────────────────
tls_errors = [netem[str(k)]["tls"]["errors"] for k in losses]
zp_errors  = [netem[str(k)]["zp"]["errors"]  for k in losses]
x = range(len(losses))
w = 0.35

fig, ax = plt.subplots(figsize=(8, 5))
ax.bar([i - w/2 for i in x], tls_errors, width=w, color='#E24B4A', label='TLS 1.3')
ax.bar([i + w/2 for i in x], zp_errors,  width=w, color='#1D9E75', label='Z-Protocol')
ax.set_xlabel("Packet Loss (%)", fontsize=12)
ax.set_ylabel("Connection Errors", fontsize=12)
ax.set_title("Connection Errors under Packet Loss", fontsize=13)
ax.set_xticks(list(x))
ax.set_xticklabels([f"{l}%" for l in losses])
ax.legend(fontsize=11)
ax.grid(True, axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig("charts/errors_under_loss.png", dpi=150)
print("[+] Saved charts/errors_under_loss.png")
plt.close()

print("\n[+] All 4 charts saved to charts/ folder")
print("[+] Use these directly in your thesis document")
