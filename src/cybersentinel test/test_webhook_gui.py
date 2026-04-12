# test_webhook_routing.py
# Verifies that severity-based webhook routing works correctly after edits.
# Run from the CyberSentinel/ root:  python test_webhook_routing.py

import sys, os, sqlite3, json, datetime, time
sys.path.insert(0, os.path.dirname(__file__))

from modules import utils

# ── CONFIG — fill in your real URLs ──────────────────────────────────────────
WEBHOOKS = {
    "webhook_url":      "YOUR-WEBHOOK-API",
    "webhook_critical": "YOUR-WEBHOOK-API_",
    "webhook_high":     "YOUR-WEBHOOK-API",
    "webhook_chains":   "YOUR-WEBHOOK-API",
}
# ─────────────────────────────────────────────────────────────────────────────

utils.init_db()

def _now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _clear_events():
    with sqlite3.connect(utils.DB_FILE) as conn:
        conn.execute("DELETE FROM event_timeline")
        try:
            conn.execute("DELETE FROM chain_alerts")
        except Exception:
            pass

def _inject(event_type, detail, pid=1234):
    with sqlite3.connect(utils.DB_FILE) as conn:
        conn.execute(
            "INSERT INTO event_timeline (event_type,detail,pid,timestamp) VALUES (?,?,?,?)",
            (event_type, json.dumps(detail), pid, _now()),
        )
    print(f"    → Injected: {event_type}")
    time.sleep(0.05)

print("\n" + "="*65)
print("  CyberSentinel — Webhook Routing Test")
print("="*65)

# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 1: route_webhook_alert routing logic ─────────────────────────")

cases = [
    ("CRITICAL", False, "webhook_critical", "🔴 Should land in CRITICAL channel"),
    ("HIGH",     False, "webhook_high",     "🟠 Should land in HIGH channel"),
    ("MEDIUM",   False, "webhook_url",      "🟡 Should land in FALLBACK channel"),
    ("LOW",      False, "webhook_url",      "🟢 Should land in FALLBACK channel"),
    ("CRITICAL", True,  "webhook_chains",   "⛓️  Chain CRITICAL → should land in CHAINS channel"),
    ("HIGH",     True,  "webhook_chains",   "⛓️  Chain HIGH → should land in CHAINS channel"),
]

for severity, is_chain, expected_key, label in cases:
    # Replicate routing logic from route_webhook_alert
    if is_chain and WEBHOOKS.get("webhook_chains"):
        routed_to = "webhook_chains"
    elif severity == "CRITICAL" and WEBHOOKS.get("webhook_critical"):
        routed_to = "webhook_critical"
    elif severity == "HIGH" and WEBHOOKS.get("webhook_high"):
        routed_to = "webhook_high"
    else:
        routed_to = "webhook_url"

    ok = routed_to == expected_key
    print(f"  {'✅' if ok else '❌'}  {label}")
    print(f"       severity={severity}  is_chain={is_chain}  → routed to: {routed_to}")

# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 2: Live send — CRITICAL to critical channel ──────────────────")
ok = utils.route_webhook_alert(
    WEBHOOKS, "CRITICAL",
    "🔴 [TEST] CRITICAL Alert Routing",
    {"Source": "test_webhook_routing.py", "Severity": "CRITICAL",
     "Expected Channel": "#soc-critical", "Time": _now()},
)
print(f"  {'✅ Delivered' if ok else '❌ Failed (expected if URL is mock)'}")

# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 3: Live send — HIGH to high channel ──────────────────────────")
ok = utils.route_webhook_alert(
    WEBHOOKS, "HIGH",
    "🟠 [TEST] HIGH Alert Routing",
    {"Source": "test_webhook_routing.py", "Severity": "HIGH",
     "Expected Channel": "#soc-high", "Time": _now()},
)
print(f"  {'✅ Delivered' if ok else '❌ Failed (expected if URL is mock)'}")

# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 4: Live send — MEDIUM falls back to catch-all ────────────────")
ok = utils.route_webhook_alert(
    WEBHOOKS, "MEDIUM",
    "🟡 [TEST] MEDIUM Alert Routing",
    {"Source": "test_webhook_routing.py", "Severity": "MEDIUM",
     "Expected Channel": "#soc-medium-low (fallback)", "Time": _now()},
)
print(f"  {'✅ Delivered' if ok else '❌ Failed (expected if URL is mock)'}")

# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 5: Attack chain → chains channel (CRITICAL) ──────────────────")
from modules.chain_correlator import ChainCorrelator
_clear_events()
_inject("FILELESS_AMSI", {"script": "powershell -enc SQBFAFgA", "pid": 4488})
_inject("C2_CONNECTION", {"ip": "185.220.101.47", "process": "powershell.exe"})

correlator = ChainCorrelator(
    webhook_url=WEBHOOKS["webhook_url"],
    webhooks=WEBHOOKS,
)
results = correlator.run_correlation()
if results:
    for r in results:
        print(f"  ✅ Chain fired: [{r['severity']}] {r['chain_name']}")
        print(f"     → Should have posted to: #soc-chains")
else:
    print("  ⚠️  No chain triggered.")

# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 6: FeodoMonitor — CRITICAL routes to critical channel ─────────")
from modules.c2_fingerprint import FeodoMonitor
feodo = FeodoMonitor(webhook_url=WEBHOOKS["webhook_url"], webhooks=WEBHOOKS)
finding = {
    "type": "C2_IP_MATCH", "remote_ip": "185.220.101.47", "remote_port": 443,
    "process_name": "svchost.exe", "process_path": r"C:\Windows\svchost.exe", "pid": 7777,
}
feodo._persist(finding)
feodo._print_alert(finding)
ok = utils.route_webhook_alert(
    WEBHOOKS, "CRITICAL",
    "🌐 [TEST] C2 Connection — Feodo Tracker Match",
    {"Remote IP": f"{finding['remote_ip']}:{finding['remote_port']}",
     "Process": f"{finding['process_name']} (PID {finding['pid']})",
     "Expected Channel": "#soc-critical", "Time": _now()},
)
print(f"  {'✅ Delivered' if ok else '❌ Failed (expected if URL is mock)'}")

# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 7: DGA burst — HIGH routes to high channel ───────────────────")
from modules.c2_fingerprint import DgaMonitor
dga = DgaMonitor(webhook_url=WEBHOOKS["webhook_url"], webhooks=WEBHOOKS)
domains = [
    "xk3mq9p2.evilc2.net", "zv8nt1lp.evilc2.net", "qw2jx7rs.evilc2.net",
    "mn4kp6yz.evilc2.net", "bf9wq3lx.evilc2.net", "cr5th8mv.evilc2.net",
]
hit = False
for d in domains:
    result = dga.analyse(d)
    if result:
        print(f"  ✅ DGA burst: {d}  entropy={result['entropy']}")
        print(f"     → Should have posted to: #soc-high")
        hit = True
        break
if not hit:
    print("  ⚠️  DGA burst not triggered.")

# ─────────────────────────────────────────────────────────────────────────────
print("\n── TEST 8: Fallback — only webhook_url set, all routes fall back ──────")
fallback_only = {"webhook_url": WEBHOOKS["webhook_url"]}
for severity, is_chain in [("CRITICAL", False), ("HIGH", False), ("CRITICAL", True)]:
    ok = utils.route_webhook_alert(
        fallback_only, severity,
        f"[TEST] Fallback routing — {severity} is_chain={is_chain}",
        {"Severity": severity, "Expected": "all land in fallback", "Time": _now()},
        is_chain=is_chain,
    )
    print(f"  {'✅' if ok else '❌ (mock)'}  severity={severity} is_chain={is_chain} → fallback")

print("\n" + "="*65)
print("  Routing tests complete.")
print("  Expected channels per test:")
print("    Test 2 → #soc-critical")
print("    Test 3 → #soc-high")
print("    Test 4 → #soc-medium-low (fallback)")
print("    Test 5 → #soc-chains")
print("    Test 6 → #soc-critical")
print("    Test 7 → #soc-high")
print("    Test 8 → all fallback")
print("="*65 + "\n")