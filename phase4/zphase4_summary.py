import os
import json

print("=" * 60)
print("  Z-PROTOCOL — PHASE 4 COMPLETION CHECK")
print("=" * 60)

checks = {
    "netem_results.json"              : "tc-netem benchmark results",
    "charts/latency_vs_loss.png"      : "Latency vs loss chart",
    "charts/packet_size_comparison.png": "Packet size chart",
    "charts/kem_speed_comparison.png" : "KEM speed chart",
    "charts/errors_under_loss.png"    : "Error count chart",
    "zspec.md"                        : "IETF-style protocol spec",
    "zlimitations.md"                 : "Limitations and future work",
}

all_ok = True
for path, label in checks.items():
    exists = os.path.exists(path)
    status = "OK" if exists else "MISSING"
    print(f"  [{status}] {label}")
    if not exists:
        all_ok = False

if os.path.exists("netem_results.json"):
    with open("netem_results.json") as f:
        data = json.load(f)
    print("\n  Benchmark results recorded:")
    for loss, r in data.items():
        print(f"    {loss}% loss → TLS={r['tls']['avg']}ms | Z-Proto={r['zp']['avg']}ms")

print("\n" + "=" * 60)
if all_ok:
    print("  ALL PHASE 4 DELIVERABLES COMPLETE")
    print("  Z-Protocol research prototype is thesis-ready")
else:
    print("  Some items missing — complete them before submission")
print("=" * 60)
