# 🔥 OffsetX — Buffer Overflow Offset Finder

<img width="793" height="674" alt="image" src="https://github.com/user-attachments/assets/e3552fbd-3164-4309-94a6-1075ec552ced" />

OffsetX replaces the manual **crash → gdb → pattern → guess → retry** loop  
with a single, automated tool for both **local** and **remote** targets.

## Files

| File | Purpose |
|------|---------|
| `offsetx.py` | Main CLI tool |
| `cyclic.py`  | Importable cyclic library |
| `test_offsetx.py` | Test suite |

## Install

No pip dependencies needed for core features.

```bash
chmod +x offsetx.py
sudo mv offsetx.py /usr/local/bin/offsetx

```

## Usage

### Interactive Wizard (easiest)

```bash
offsetx wizard
```
Step-by-step: generate → send → enter EIP → get offset.

---

### Generate a cyclic pattern
```bash
 offsetx generate -l 2000
 offsetx generate -l 3000 -o pattern.bin
```

---

### Find offset from crash value
```bash
# 32-bit (EIP)
python3 offsetx.py find 0x41424344
python3 offsetx.py find 41424344

# 64-bit (RIP)
python3 offsetx.py find 0x4141416141414162 --bits 64 -l 5000
```

---

### Auto-crash with GDB (local binary)
```bash
python3 offsetx.py auto --binary ./vuln --length 2000
python3 offsetx.py auto --binary ./vuln --length 2000 --args "{pattern}"
```
Launches the binary under GDB, sends the pattern, captures EIP/RIP automatically.

---

### Remote target
```bash
# Basic
python3 offsetx.py remote --host 10.10.10.1 --port 4444 -l 2000

# With protocol prefix (e.g. FTP USER command)
python3 offsetx.py remote --host 10.10.10.1 --port 21 -l 3000 --prefix "USER "

# With suffix
python3 offsetx.py remote --host 192.168.1.5 --port 9999 -l 2000 --suffix "\r\n"
```
After crash, note the EIP/RIP in your debugger, then:
```bash
python3 offsetx.py find <EIP_VALUE> -l 2000
```

---

## Library usage in your exploit scripts

```python
from cyclic import cyclic_gen, cyclic_find

# Generate
pattern = cyclic_gen(2000)

# Craft payload
payload = pattern   # send this to crash the target

# After crash — find offset
offset = cyclic_find(0x41424344)   # int
offset = cyclic_find("0x41424344") # hex string
offset = cyclic_find("41424344")   # no 0x

print(f"[+] Offset: {offset}")

# Build exploit payload
payload = b"A" * offset + b"\xef\xbe\xad\xde" + b"\x90" * 100 + shellcode
```

---

## Verify your offset

Once you have the offset:
```bash
python3 -c "print('A'*<OFFSET> + 'B'*4 + 'C'*100)"
```
EIP should show `0x42424242` (BBBB) — perfect control.

---

## Workflow summary

```
1. Generate pattern      →  offsetx.py generate -l 2000
2. Send to target        →  offsetx.py remote  OR  offsetx.py auto
3. Read EIP/RIP crash    →  from debugger / GDB output
4. Find offset           →  offsetx.py find 0xDEADBEEF
5. Build exploit         →  "A" * offset + ret_addr + shellcode
```

## Run tests

```bash
python3 test_offsetx.py
```

> **For educational/CTF/authorized pentesting purposes only.**
