"""AES (FIPS-197) in pure Python: the block cipher behind most RAT configs and loader payloads.
Decryption is what the tool needs; encryption exists so the tests can build realistic samples."""

from __future__ import annotations


def _xt(a: int) -> int:
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a, b = _xt(a), b >> 1
    return r


def _sbox() -> tuple[list[int], list[int]]:
    s, inv = [0] * 256, [0] * 256
    for x in range(256):
        y = 1
        for _ in range(254):                      # multiplicative inverse in GF(2^8): x^254
            y = _mul(y, x)
        y = y if x else 0
        r = y
        for k in range(1, 5):                     # the affine transform
            r ^= ((y << k) | (y >> (8 - k))) & 0xFF
        s[x] = r ^ 0x63
        inv[s[x]] = x
    return s, inv


SBOX, INV_SBOX = _sbox()
_M = {k: [_mul(i, k) for i in range(256)] for k in (2, 3, 9, 11, 13, 14)}


def _expand(key: bytes) -> list[list[int]]:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nk = len(key) // 4
    rounds = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xt(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(rounds + 1)]


class AES:
    def __init__(self, key: bytes):
        self.rk = _expand(bytes(key))
        self.rounds = len(self.rk) - 1

    def encrypt_block(self, block: bytes) -> bytes:
        s = [b ^ k for b, k in zip(block, self.rk[0])]
        m2, m3 = _M[2], _M[3]
        for r in range(1, self.rounds + 1):
            s = [SBOX[b] for b in s]
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]           # shift rows (column-major state)
            if r != self.rounds:
                t = []
                for c in range(4):
                    a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                    t += [m2[a0] ^ m3[a1] ^ a2 ^ a3, a0 ^ m2[a1] ^ m3[a2] ^ a3,
                          a0 ^ a1 ^ m2[a2] ^ m3[a3], m3[a0] ^ a1 ^ a2 ^ m2[a3]]
                s = t
            s = [b ^ k for b, k in zip(s, self.rk[r])]
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        s = [b ^ k for b, k in zip(block, self.rk[self.rounds])]
        m9, m11, m13, m14 = _M[9], _M[11], _M[13], _M[14]
        for r in range(self.rounds - 1, -1, -1):
            s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]           # inverse shift rows
            s = [INV_SBOX[b] for b in s]
            s = [b ^ k for b, k in zip(s, self.rk[r])]
            if r:
                t = []
                for c in range(4):
                    a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                    t += [m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3], m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3],
                          m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3], m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]]
                s = t
        return bytes(s)


def unpad(data: bytes) -> bytes | None:
    """PKCS#7; None when the padding is not valid (the usual sign of a wrong key)."""
    if not data or len(data) % 16:
        return None
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        return None
    return data[:-n]


def pad(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def decrypt_ecb(key: bytes, data: bytes, strip: bool = True) -> bytes | None:
    if not data or len(data) % 16:
        return None
    c = AES(key)
    out = b"".join(c.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))
    return unpad(out) if strip else out


def decrypt_cbc(key: bytes, iv: bytes, data: bytes, strip: bool = True) -> bytes | None:
    if not data or len(data) % 16 or len(iv) != 16:
        return None
    c = AES(key)
    out, prev = bytearray(), iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(c.decrypt_block(block), prev))
        prev = block
    return unpad(bytes(out)) if strip else bytes(out)


def encrypt_ecb(key: bytes, data: bytes) -> bytes:
    c = AES(key)
    data = pad(data)
    return b"".join(c.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))


def encrypt_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = AES(key)
    data, out, prev = pad(data), bytearray(), iv
    for i in range(0, len(data), 16):
        prev = c.encrypt_block(bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out += prev
    return bytes(out)
