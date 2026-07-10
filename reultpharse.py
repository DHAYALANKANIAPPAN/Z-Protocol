
┌──(z㉿dhaya)-[~/secure_protocol_project/phase4]
└─$ sudo python3 znetem.py
============================================================
  Z-PROTOCOL vs TLS 1.3 — NETWORK STRESS TEST
============================================================

[*] Testing at 0% packet loss...
[*] Network loss cleared (0%)
    [-] Error at 0%: [Errno 2] No such file or directory

[*] Testing at 1% packet loss...
[*] Network loss set to 1%
    [-] Error at 1%: [Errno 2] No such file or directory

[*] Testing at 5% packet loss...
[*] Network loss set to 5%
    [-] Error at 5%: [Errno 2] No such file or directory

[*] Testing at 10% packet loss...
[*] Network loss set to 10%
    [-] Error at 10%: [Errno 2] No such file or directory
[*] tc-netem rules cleared

============================================================
  SUMMARY TABLE (save for thesis)
============================================================
Loss%    TLS avg ms      Z-Proto avg ms     Winner
------------------------------------------------------------

[+] Raw results saved to netem_results.json

┌──(z㉿dhaya)-[~/secure_protocol_project/phase4]
└─$ python3 zcharts.py                                                           
[+] Saved charts/latency_vs_loss.png
[+] Saved charts/packet_size_comparison.png
[+] Saved charts/kem_speed_comparison.png
[+] Saved charts/errors_under_loss.png

[+] All 4 charts saved to charts/ folder
[+] Use these directly in your thesis document

┌──(z㉿dhaya)-[~/secure_protocol_project/phase4]
└─$ python3 zphase4_summary.py                                                   
============================================================
  Z-PROTOCOL — PHASE 4 COMPLETION CHECK
============================================================
  [OK] tc-netem benchmark results
  [OK] Latency vs loss chart
  [OK] Packet size chart
  [OK] KEM speed chart
  [OK] Error count chart
  [OK] IETF-style protocol spec
  [OK] Limitations and future work

  Benchmark results recorded:

============================================================
  ALL PHASE 4 DELIVERABLES COMPLETE
  Z-Protocol research prototype is thesis-ready
============================================================

┌──(z㉿dhaya)-[~/secure_protocol_project/phase4]
└─$                                           
