"""
offsetx/cyclic.py
─────────────────
Standalone cyclic pattern library for OffsetX.
Can be imported independently into exploit scripts.

Usage:
    from cyclic import cyclic_gen, cyclic_find
    pattern = cyclic_gen(2000)
    offset  = cyclic_find(0x41424344)
"""

# De Bruijn sequence charset
CHARSET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def cyclic_gen(length: int, charset: bytes = CHARSET) -> bytes:
    """
    Generate a cyclic pattern of `length` bytes.
    Each 4-byte chunk is unique for easy EIP matching.

    Args:
        length:  Total number of bytes to generate.
        charset: Bytes to cycle through (default: alphanum).

    Returns:
        bytes of the requested length.

    Example:
        >>> cyclic_gen(16)
        b'AAAaAAABAAAcAAAC'
    """
    n = len(charset)
    pattern = bytearray()
    i = 0
    while len(pattern) < length:
        a = charset[(i // (n * n)) % n]
        b = charset[(i // n) % n]
        c = charset[i % n]
        d = charset[(i * 7 + 13) % n]
        pattern.extend([a, b, c, d])
        i += 1
    return bytes(pattern[:length])


def cyclic_find(value, length: int = 10000, bits: int = 32,
                charset: bytes = CHARSET) -> int:
    """
    Find the byte offset of `value` inside a cyclic pattern.

    Args:
        value:  EIP/RIP value — int, hex string ("0x41424344"),
                or raw bytes (little-endian).
        length: How long a pattern to search in (default 10000).
        bits:   32 or 64 (determines byte width of search value).
        charset: Must match what was used in cyclic_gen.

    Returns:
        int offset, or -1 if not found.

    Example:
        >>> cyclic_find(0x61414101)
        8
        >>> cyclic_find("0x41424344")
        ...
    """
    # ── Normalize input ──────────────────────────────────────────
    if isinstance(value, str):
        value = value.strip()
        raw_int = int(value, 16) if value.startswith(("0x", "0X")) \
                  else int(value, 16) if all(c in "0123456789abcdefABCDEF" for c in value) \
                  else int(value)
    elif isinstance(value, int):
        raw_int = value
    elif isinstance(value, bytes):
        raw_int = int.from_bytes(value, "little")
    else:
        raise TypeError(f"Unsupported value type: {type(value)}")

    byte_width = 4 if bits == 32 else 8
    pattern = cyclic_gen(length, charset)

    # Try little-endian first (x86 default)
    search_le = raw_int.to_bytes(byte_width, "little")
    idx = pattern.find(search_le)
    if idx != -1:
        return idx

    # Try big-endian (MIPS, SPARC, etc.)
    search_be = raw_int.to_bytes(byte_width, "big")
    idx = pattern.find(search_be)
    return idx


def cyclic_contains(value, length: int = 10000, bits: int = 32) -> bool:
    """Check if a value appears in a cyclic pattern."""
    return cyclic_find(value, length, bits) != -1


def pattern_str(length: int) -> str:
    """Return cyclic pattern as ASCII string."""
    return cyclic_gen(length).decode("latin-1")


# ── CLI for quick use ────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 cyclic.py gen  <length>")
        print("  python3 cyclic.py find <eip_value> [length] [32|64]")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "gen":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
        print(cyclic_gen(n).decode("latin-1"))
    elif cmd == "find":
        val = sys.argv[2]
        l   = int(sys.argv[3]) if len(sys.argv) > 3 else 10000
        b   = int(sys.argv[4]) if len(sys.argv) > 4 else 32
        offset = cyclic_find(val, l, b)
        if offset == -1:
            print(f"[-] Not found in pattern of length {l}")
        else:
            print(f"[+] Offset: {offset}")
