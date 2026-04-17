#!/usr/bin/env python3
"""
offsetx/test_offsetx.py
────────────────────────
Tests for cyclic pattern generator and offset finder.
Run with: python3 test_offsetx.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from cyclic import cyclic_gen, cyclic_find, cyclic_contains

# ─── ANSI ────────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

passed = 0
failed = 0

def test(name, condition, extra=""):
    global passed, failed
    if condition:
        print(f"  {GREEN}✔{RESET}  {name}")
        passed += 1
    else:
        print(f"  {RED}✘{RESET}  {name}{f'  →  {extra}' if extra else ''}")
        failed += 1

def header(s):
    print(f"\n{CYAN}{BOLD}{'─'*12} {s} {'─'*12}{RESET}")


print(f"""
{BOLD}╔════════════════════════════════════╗
║   OffsetX — Test Suite             ║
╚════════════════════════════════════╝{RESET}
""")

# ─── Pattern Generation ───────────────────────────────────────────────────────
header("Pattern Generation")

p100 = cyclic_gen(100)
test("Length 100 is correct",   len(p100) == 100, f"got {len(p100)}")
test("Pattern is bytes",        isinstance(p100, bytes))
test("Pattern is printable",    all(chr(b).isprintable() for b in p100))

p2000 = cyclic_gen(2000)
test("Length 2000 is correct",  len(p2000) == 2000, f"got {len(p2000)}")

p0 = cyclic_gen(0)
test("Length 0 returns empty",  len(p0) == 0)

p1 = cyclic_gen(1)
test("Length 1 works",          len(p1) == 1)

# Check uniqueness of 4-byte chunks
header("Pattern Uniqueness (4-byte chunks)")
chunks = set()
pattern = cyclic_gen(4000)
for i in range(0, len(pattern) - 3, 4):
    chunk = pattern[i:i+4]
    chunks.add(chunk)
expected = len(pattern) // 4
test(f"4-byte chunks unique ({expected} total)", len(chunks) == expected,
     f"got {len(chunks)} unique out of {expected}")

# ─── Offset Finding ───────────────────────────────────────────────────────────
header("Offset Finding — 32-bit")

# Extract known offsets and verify roundtrip
for expected_offset in [0, 4, 8, 100, 200, 500, 1000, 1996]:
    pattern = cyclic_gen(2000)
    chunk = pattern[expected_offset:expected_offset+4]
    val = int.from_bytes(chunk, "little")
    found = cyclic_find(val, length=2000, bits=32)
    test(f"Offset {expected_offset} roundtrip", found == expected_offset,
         f"got {found}")

header("Offset Finding — Input Formats")
pattern = cyclic_gen(2000)
chunk   = pattern[128:132]
val_int = int.from_bytes(chunk, "little")
val_hex = hex(val_int)
val_str = val_hex[2:]  # no 0x prefix
val_bytes = chunk

test("Find by int",         cyclic_find(val_int,   2000) == 128)
test("Find by hex string",  cyclic_find(val_hex,   2000) == 128)
test("Find by hex no-0x",   cyclic_find(val_str,   2000) == 128)
test("Find by bytes",       cyclic_find(val_bytes, 2000) == 128)

header("Offset Finding — 64-bit")
pattern64 = cyclic_gen(5000)
for expected_offset in [0, 8, 64, 256, 1000]:
    chunk = pattern64[expected_offset:expected_offset+8]
    val = int.from_bytes(chunk, "little")
    found = cyclic_find(val, length=5000, bits=64)
    test(f"64-bit offset {expected_offset}", found == expected_offset,
         f"got {found}")

header("Edge Cases")
test("Value not in pattern returns -1",
     cyclic_find(0xDEADBEEF, length=2000) == -1)
test("cyclic_contains True for in-pattern value",
     cyclic_contains(val_int, 2000))
test("cyclic_contains False for not-in-pattern value",
     not cyclic_contains(0xDEADBEEF, 2000))

# ─── Determinism ─────────────────────────────────────────────────────────────
header("Determinism")
a = cyclic_gen(500)
b = cyclic_gen(500)
test("Same seed → same pattern", a == b)

c = cyclic_gen(600)
test("Shorter is prefix of longer", c[:500] == a)

# ─── Summary ─────────────────────────────────────────────────────────────────
total = passed + failed
print(f"""
{'─'*40}
  {BOLD}Results:{RESET}  {GREEN}{passed} passed{RESET}  /  {RED}{failed} failed{RESET}  /  {total} total
{'─'*40}
""")

if failed == 0:
    print(f"  {GREEN}{BOLD}🔥 All tests passed! OffsetX is ready to rock.{RESET}\n")
    sys.exit(0)
else:
    print(f"  {RED}{BOLD}⚠  {failed} test(s) failed — check above.{RESET}\n")
    sys.exit(1)
