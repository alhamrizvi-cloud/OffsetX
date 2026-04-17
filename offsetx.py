#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██████╗ ███████╗███████╗███████╗███████╗████████╗██╗  ██╗ ║
║   ██╔═══██╗██╔════╝██╔════╝██╔════╝██╔════╝╚══██╔══╝╚██╗██╔╝ ║
║   ██║   ██║█████╗  █████╗  ███████╗█████╗     ██║    ╚███╔╝  ║
║   ██║   ██║██╔══╝  ██╔══╝  ╚════██║██╔══╝     ██║    ██╔██╗  ║
║   ╚██████╔╝██║     ██║     ███████║███████╗   ██║   ██╔╝ ██╗ ║
║    ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ║
║                                                               ║
║          Buffer Overflow Offset Finder  v1.0                  ║
║          by: OffsetX  |  "Find it. Own it."                   ║
╚═══════════════════════════════════════════════════════════════╝
"""

import argparse
import socket
import subprocess
import sys
import time
import struct
import os
import signal
import tempfile
from typing import Optional, Tuple

# ─── ANSI Colors ────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    ORANGE  = "\033[38;5;208m"
    FIRE    = "\033[38;5;196m"

def banner():
    print(f"""
{C.FIRE}{C.BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██████╗ ███████╗███████╗███████╗███████╗████████╗██╗  ██╗         ║
║  ██╔═══██╗██╔════╝██╔════╝██╔════╝██╔════╝╚══██╔══╝╚██╗██╔╝        ║
║  ██║   ██║█████╗  █████╗  ███████╗█████╗     ██║    ╚███╔╝         ║
║  ██║   ██║██╔══╝  ██╔══╝  ╚════██║██╔══╝     ██║    ██╔██╗         ║
║  ╚██████╔╝██║     ██║     ███████║███████╗   ██║   ██╔╝ ██╗        ║
║   ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝        ║
║                                                                      ║
║   {C.ORANGE}🔥 Buffer Overflow Offset Finder  v1.0{C.FIRE}                          ║
║   {C.YELLOW}   "Find the offset. Own the instruction pointer."{C.FIRE}               ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
{C.RESET}""")

def info(msg):    print(f"{C.CYAN}[*]{C.RESET} {msg}")
def ok(msg):      print(f"{C.GREEN}[+]{C.RESET} {C.BOLD}{msg}{C.RESET}")
def warn(msg):    print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):     print(f"{C.RED}[-]{C.RESET} {msg}")
def section(msg): print(f"\n{C.MAGENTA}{C.BOLD}{'─'*10} {msg} {'─'*10}{C.RESET}")


# ─── Cyclic Pattern Generator ────────────────────────────────────────────────

CHARSET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

def cyclic_gen(length: int) -> bytes:
    """Generate a De Bruijn-like cyclic pattern of given length."""
    pattern = bytearray()
    n = len(CHARSET)
    i = 0
    while len(pattern) < length:
        # 4-byte groups for easy EIP/RIP identification
        a = CHARSET[(i // (n * n)) % n]
        b = CHARSET[(i // n) % n]
        c = CHARSET[i % n]
        d = CHARSET[(i * 7 + 13) % n]
        pattern.extend([a, b, c, d])
        i += 1
    return bytes(pattern[:length])


def cyclic_find(value, length: int = 10000, bits: int = 32) -> int:
    """
    Find the offset of a value inside the cyclic pattern.
    value can be: int (EIP value), bytes (raw), or hex string like '0x41424344'
    """
    # Normalize value
    if isinstance(value, str):
        value = value.strip()
        if value.startswith("0x") or value.startswith("0X"):
            raw_int = int(value, 16)
        else:
            try:
                raw_int = int(value, 16)
            except ValueError:
                raw_int = int(value)
    elif isinstance(value, int):
        raw_int = value
    elif isinstance(value, bytes):
        raw_int = int.from_bytes(value, "little")
    else:
        raise ValueError(f"Unsupported type: {type(value)}")

    # Convert int → bytes (little-endian, 4 or 8 bytes)
    byte_width = 4 if bits == 32 else 8
    search_bytes = raw_int.to_bytes(byte_width, "little")

    pattern = cyclic_gen(length)
    idx = pattern.find(search_bytes)
    if idx == -1:
        # try big-endian
        search_bytes_be = raw_int.to_bytes(byte_width, "big")
        idx = pattern.find(search_bytes_be)
        if idx != -1:
            warn(f"Found in big-endian at offset {idx}")
            return idx
        return -1
    return idx


# ─── Local Crash Detection via GDB ──────────────────────────────────────────

GDB_SCRIPT_TEMPLATE = """\
set pagination off
set disassembly-flavor intel
run {args}
# after crash
python
import gdb
try:
    eip = gdb.parse_and_eval("$eip")
    print("OFFSETX_EIP=0x{:08x}".format(int(eip)))
except:
    try:
        rip = gdb.parse_and_eval("$rip")
        print("OFFSETX_RIP=0x{:016x}".format(int(rip)))
    except Exception as e:
        print("OFFSETX_ERR=" + str(e))
end
quit
"""

def run_with_gdb(binary: str, pattern: bytes, args_template: str = "{pattern}",
                 timeout: int = 10) -> Optional[str]:
    """
    Runs binary under GDB with the cyclic pattern.
    Returns the EIP/RIP value as hex string, or None on failure.
    """
    section("GDB Auto-Attach Mode")
    info(f"Target binary: {C.BOLD}{binary}{C.RESET}")

    # Write pattern to a temp file so we can pass it
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    tmp.write(pattern)
    tmp.close()
    pattern_arg = tmp.name

    # Build GDB commands
    run_args = args_template.replace("{pattern}", f"$(cat {pattern_arg})")
    gdb_cmds = f"""\
set pagination off
set disassembly-flavor intel
run {run_args}
python
import gdb
try:
    eip = int(gdb.parse_and_eval("$eip"))
    print("OFFSETX_EIP=0x{{:08x}}".format(eip))
except:
    try:
        rip = int(gdb.parse_and_eval("$rip"))
        print("OFFSETX_RIP=0x{{:016x}}".format(rip))
    except Exception as ex:
        print("OFFSETX_ERR=" + str(ex))
end
quit
"""
    gdb_script = tempfile.NamedTemporaryFile(delete=False, suffix=".gdb",
                                             mode="w")
    gdb_script.write(gdb_cmds)
    gdb_script.close()

    info("Launching GDB...")
    try:
        result = subprocess.run(
            ["gdb", "-batch", "-x", gdb_script.name, binary],
            capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout + result.stderr
        for line in output.splitlines():
            if "OFFSETX_EIP=" in line:
                val = line.split("=")[1].strip()
                ok(f"Captured EIP: {C.YELLOW}{val}{C.RESET}")
                return val
            elif "OFFSETX_RIP=" in line:
                val = line.split("=")[1].strip()
                ok(f"Captured RIP: {C.YELLOW}{val}{C.RESET}")
                return val
            elif "OFFSETX_ERR=" in line:
                err(f"GDB python error: {line.split('=',1)[1]}")
    except subprocess.TimeoutExpired:
        err("GDB timed out — process may not have crashed.")
    except FileNotFoundError:
        err("GDB not found. Install with: sudo apt install gdb")
    finally:
        os.unlink(tmp.name)
        os.unlink(gdb_script.name)
    return None


# ─── Remote Crash Detection ──────────────────────────────────────────────────

def send_remote(host: str, port: int, pattern: bytes,
                prefix: bytes = b"", suffix: bytes = b"",
                recv_first: bool = True, timeout: int = 5) -> bool:
    """
    Sends cyclic pattern to a remote service.
    Returns True if connection was refused/reset (crash indicator).
    """
    section("Remote Send Mode")
    info(f"Target: {C.BOLD}{host}:{port}{C.RESET}")
    info(f"Pattern length: {len(pattern)} bytes")
    if prefix: info(f"Prefix: {prefix!r}")
    if suffix: info(f"Suffix: {suffix!r}")

    payload = prefix + pattern + suffix
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        ok("Connected to target")

        if recv_first:
            try:
                banner_data = s.recv(1024)
                info(f"Server banner: {banner_data[:80]!r}")
            except socket.timeout:
                pass

        info(f"Sending {len(payload)} byte payload...")
        s.send(payload)
        time.sleep(0.5)

        try:
            response = s.recv(1024)
            if response:
                info(f"Got response ({len(response)} bytes) — service still alive")
            else:
                warn("Empty response — possible crash")
                return True
        except (socket.timeout, ConnectionResetError):
            warn("Connection reset/timeout — service likely crashed!")
            return True
        finally:
            s.close()

    except ConnectionRefusedError:
        warn("Connection refused — target may have crashed!")
        return True
    except Exception as e:
        err(f"Socket error: {e}")
    return False


# ─── Interactive Wizard ──────────────────────────────────────────────────────

def wizard():
    """Interactive step-by-step offset finder wizard."""
    banner()
    section("Interactive Offset Wizard")
    print(f"""
{C.CYAN}This wizard will guide you through finding a buffer overflow offset.
Steps:
  1. Generate cyclic pattern
  2. Send it to the target
  3. Enter the crash value (EIP/RIP)
  4. Get the exact offset{C.RESET}
""")

    # Step 1: Pattern length
    length = int(input(f"{C.BOLD}[?] Pattern length (default 2000): {C.RESET}").strip() or "2000")
    bits_str = input(f"{C.BOLD}[?] Architecture 32 or 64 bit? (default 32): {C.RESET}").strip() or "32"
    bits = int(bits_str)

    pattern = cyclic_gen(length)
    section("Generated Pattern")
    print(f"{C.YELLOW}{pattern.decode('latin-1')}{C.RESET}\n")
    ok(f"Pattern length: {length}")

    # Save to file?
    save = input(f"{C.BOLD}[?] Save pattern to file? (y/N): {C.RESET}").strip().lower()
    if save == "y":
        fname = input(f"{C.BOLD}[?] Filename (default: pattern.bin): {C.RESET}").strip() or "pattern.bin"
        with open(fname, "wb") as f:
            f.write(pattern)
        ok(f"Saved to {fname}")

    # Step 2: Crash value
    section("Enter Crash Value")
    print(f"{C.DIM}After the crash, find EIP/RIP in your debugger.{C.RESET}")
    print(f"{C.DIM}Examples: 0x41424344  |  41424344  |  1094795588{C.RESET}\n")
    crash_val = input(f"{C.BOLD}[?] EIP/RIP value: {C.RESET}").strip()

    # Step 3: Compute offset
    section("Computing Offset")
    offset = cyclic_find(crash_val, length=length, bits=bits)
    if offset == -1:
        err("Value not found in pattern!")
        err("Make sure:")
        err("  • The pattern was long enough")
        err("  • You copied the EXACT EIP/RIP value")
        err("  • The architecture (32/64) matches")
    else:
        print()
        print(f"  {'─'*50}")
        print(f"  {C.GREEN}{C.BOLD}  OFFSET FOUND: {C.YELLOW}{offset} bytes{C.RESET}")
        print(f"  {'─'*50}")
        print()
        ok(f"Overwrite EIP/RIP at byte {C.BOLD}{offset}{C.RESET} of your buffer")
        print()
        print(f"{C.DIM}Verify with:{C.RESET}")
        print(f"  {C.CYAN}python3 -c \"print('A'*{offset} + 'B'*4 + 'C'*100)\"{C.RESET}")
        print(f"  {C.DIM}→ EIP should be 0x42424242 (BBBB){C.RESET}")


# ─── CLI Entry Point ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OffsetX — Buffer Overflow Offset Finder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{C.CYAN}Examples:{C.RESET}
  # Interactive wizard
  python3 offsetx.py wizard

  # Generate pattern
  python3 offsetx.py generate -l 2000
  python3 offsetx.py generate -l 3000 -o pattern.bin

  # Find offset from crash value
  python3 offsetx.py find 0x41424344
  python3 offsetx.py find 0x41424344 -l 3000 --bits 64

  # Auto-crash with GDB (local)
  python3 offsetx.py auto --binary ./vuln --length 2000

  # Auto-crash remote
  python3 offsetx.py remote --host 10.10.10.1 --port 4444 --length 2000 --prefix "USER "
"""
    )

    sub = parser.add_subparsers(dest="cmd")

    # wizard
    sub.add_parser("wizard", help="Interactive step-by-step wizard")

    # generate
    gen_p = sub.add_parser("generate", help="Generate cyclic pattern")
    gen_p.add_argument("-l", "--length", type=int, default=2000, help="Pattern length")
    gen_p.add_argument("-o", "--output", type=str, help="Output file (binary)")

    # find
    find_p = sub.add_parser("find", help="Find offset from EIP/RIP value")
    find_p.add_argument("value", type=str, help="EIP/RIP crash value (hex or int)")
    find_p.add_argument("-l", "--length", type=int, default=10000, help="Search length")
    find_p.add_argument("--bits", type=int, default=32, choices=[32, 64])

    # auto (GDB)
    auto_p = sub.add_parser("auto", help="Auto-crash binary with GDB")
    auto_p.add_argument("--binary", required=True, help="Path to vulnerable binary")
    auto_p.add_argument("-l", "--length", type=int, default=2000)
    auto_p.add_argument("--args", default="{pattern}", help="Arg template, use {pattern}")
    auto_p.add_argument("--bits", type=int, default=32, choices=[32, 64])
    auto_p.add_argument("--timeout", type=int, default=15)

    # remote
    rem_p = sub.add_parser("remote", help="Send pattern to remote target")
    rem_p.add_argument("--host", required=True)
    rem_p.add_argument("--port", type=int, required=True)
    rem_p.add_argument("-l", "--length", type=int, default=2000)
    rem_p.add_argument("--prefix", default="", help="Data to send before pattern")
    rem_p.add_argument("--suffix", default="", help="Data to send after pattern")
    rem_p.add_argument("--no-recv-first", action="store_true")
    rem_p.add_argument("--timeout", type=int, default=5)

    args = parser.parse_args()

    if not args.cmd or args.cmd == "wizard":
        wizard()
        return

    banner()

    if args.cmd == "generate":
        section("Pattern Generator")
        pattern = cyclic_gen(args.length)
        info(f"Length: {args.length}")
        if args.output:
            with open(args.output, "wb") as f:
                f.write(pattern)
            ok(f"Pattern saved to {args.output}")
        else:
            print(f"\n{C.YELLOW}{pattern.decode('latin-1')}{C.RESET}\n")
            ok("Copy the above pattern and send it to your target")

    elif args.cmd == "find":
        section("Offset Finder")
        info(f"Searching for: {C.BOLD}{args.value}{C.RESET}")
        info(f"Architecture: {args.bits}-bit")
        offset = cyclic_find(args.value, length=args.length, bits=args.bits)
        if offset == -1:
            err("Value NOT found in pattern")
            err("Try increasing --length or check the value")
            sys.exit(1)
        else:
            print(f"\n  {'═'*48}")
            print(f"  {C.GREEN}{C.BOLD}  ✔  EXACT OFFSET: {C.YELLOW}{offset} bytes{C.RESET}")
            print(f"  {'═'*48}\n")
            ok(f"Pad with {offset} bytes then your control value")

    elif args.cmd == "auto":
        section("GDB Auto Mode")
        pattern = cyclic_gen(args.length)
        info(f"Pattern length: {args.length}")
        crash_val = run_with_gdb(args.binary, pattern, args.args, args.timeout)
        if not crash_val:
            err("Could not capture crash value via GDB")
            sys.exit(1)
        offset = cyclic_find(crash_val, length=args.length, bits=args.bits)
        if offset == -1:
            err("Crash value not found in pattern — try a longer pattern")
            sys.exit(1)
        print(f"\n  {'═'*48}")
        print(f"  {C.GREEN}{C.BOLD}  ✔  EXACT OFFSET: {C.YELLOW}{offset} bytes{C.RESET}")
        print(f"  {'═'*48}\n")

    elif args.cmd == "remote":
        pattern = cyclic_gen(args.length)
        prefix = args.prefix.encode().decode("unicode_escape").encode("latin-1")
        suffix = args.suffix.encode().decode("unicode_escape").encode("latin-1")
        crashed = send_remote(
            args.host, args.port, pattern, prefix, suffix,
            recv_first=not args.no_recv_first, timeout=args.timeout
        )
        if crashed:
            ok("Service appears to have crashed!")
            print()
            warn("Now attach a debugger and note the EIP/RIP value.")
            print(f"  Then run: {C.CYAN}python3 offsetx.py find <EIP_VALUE> -l {args.length}{C.RESET}")
        else:
            warn("Service did not crash — try a longer pattern or check the target")


if __name__ == "__main__":
    main()
