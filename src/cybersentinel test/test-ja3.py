import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from modules.c2_fingerprint import Ja3Monitor

m = Ja3Monitor()

tests = [
    ('1aa7bf8b97e540ca5edd75f7b8384bfa', 'TrickBot'),
    ('b386946a5a44d1ddcc843bc75336dfce', 'Dridex'),
    ('aabbccddeeff00112233445566778899', 'Benign'),
]

print("\n=== JA3 Blocklist Check ===\n")
for ja3, label in tests:
    hit = m.check_fingerprint(ja3)
    status = "BLOCKED" if hit else "clean"
    print(f"  {status:8}  {ja3}  ({label})")