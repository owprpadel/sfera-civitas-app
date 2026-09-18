"""
crypto_core.py — Primitivas criptográficas de Sfera Civitas (versión DESARROLLO)

Implementa, en Python puro (sin dependencias externas), las piezas que el roadmap
técnico exige para desacoplar identidad ↔ voto y hacer el voto verificable:

  1) FIRMA CIEGA RSA (Chaum / RFC 9474 FDH) — el módulo de Identidad firma una
     credencial de voto SIN ver su contenido: así el módulo de Voto puede validar
     "esta persona tiene derecho a un voto" sin saber QUIÉN es. (Desacople.)

  2) ELGAMAL HOMOMÓRFICO (grupo MODP 2048-bit de RFC 3526) — el voto se cifra en
     el cliente; los cifrados se pueden multiplicar para obtener el recuento
     cifrado (homomorfismo aditivo), y solo el/los custodios (trustees) descifran
     el TOTAL, nunca un voto individual.

  3) Utilidades de tablón (hash-chain) y recibo verificable.

⚠️ AVISO (honestidad, alineado con el doc de infraestructura): esto es una versión
   de DESARROLLO/didáctica para probar el flujo integrado end-to-end. Para producción
   real se usaría un motor auditado (p. ej. Belenios) con custodios distribuidos,
   pruebas ZK de descifrado, resistencia a coacción, etc. Aquí el trustee es único.
"""
from __future__ import annotations
import hashlib
import secrets
from dataclasses import dataclass


# ─────────────────────────────────────────────────────────────────────────────
# Utilidades numéricas
# ─────────────────────────────────────────────────────────────────────────────
def _is_probable_prime(n: int, k: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def H_int(*parts: bytes) -> int:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return int.from_bytes(h.digest(), "big")


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# 1) FIRMA CIEGA RSA (Full-Domain-Hash)  — módulo de Identidad
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class BlindPubKey:
    n: int
    e: int


class BlindSigner:
    """Emisor de credenciales anónimas (vive en el módulo de Identidad).

    Firma a ciegas un token que genera el ciudadano ya verificado. El módulo de
    Voto valida la firma con la clave pública, pero no puede ligar el token a la
    identidad: unlinkabilidad matemática.
    """

    def __init__(self, bits: int = 2048):
        # p, q primos; n = p*q; e=65537; d = e^-1 mod phi
        while True:
            p = _gen_prime(bits // 2)
            q = _gen_prime(bits // 2)
            if p == q:
                continue
            n = p * q
            phi = (p - 1) * (q - 1)
            e = 65537
            if phi % e == 0:
                continue
            d = pow(e, -1, phi)
            self.n, self.e, self.d = n, e, d
            return

    def pub(self) -> BlindPubKey:
        return BlindPubKey(self.n, self.e)

    def _fdh(self, msg: bytes) -> int:
        """Full-Domain-Hash: expande SHA-256 hasta ~len(n) con contador (MGF-like)."""
        out = b""
        counter = 0
        target = (self.n.bit_length() + 7) // 8
        while len(out) < target:
            out += hashlib.sha256(counter.to_bytes(4, "big") + msg).digest()
            counter += 1
        return int.from_bytes(out, "big") % self.n

    # --- lado ciudadano (cliente) ---
    @staticmethod
    def blind(pub: BlindPubKey, msg: bytes) -> tuple[int, int]:
        """Devuelve (blinded, r) — el ciudadano ciega su token con factor r."""
        target = (pub.n.bit_length() + 7) // 8
        out = b""
        counter = 0
        while len(out) < target:
            out += hashlib.sha256(counter.to_bytes(4, "big") + msg).digest()
            counter += 1
        m = int.from_bytes(out, "big") % pub.n
        while True:
            r = secrets.randbelow(pub.n - 2) + 2
            try:
                pow(r, -1, pub.n)  # r debe ser invertible
                break
            except ValueError:
                continue
        blinded = (m * pow(r, pub.e, pub.n)) % pub.n
        return blinded, r

    # --- lado emisor (identidad) ---
    def sign_blinded(self, blinded: int) -> int:
        return pow(blinded, self.d, self.n)

    # --- lado ciudadano: quita el cegado ---
    @staticmethod
    def unblind(pub: BlindPubKey, blind_sig: int, r: int) -> int:
        r_inv = pow(r, -1, pub.n)
        return (blind_sig * r_inv) % pub.n

    # --- lado voto: verifica la credencial anónima ---
    @staticmethod
    def verify(pub: BlindPubKey, msg: bytes, sig: int) -> bool:
        target = (pub.n.bit_length() + 7) // 8
        out = b""
        counter = 0
        while len(out) < target:
            out += hashlib.sha256(counter.to_bytes(4, "big") + msg).digest()
            counter += 1
        m = int.from_bytes(out, "big") % pub.n
        return pow(sig, pub.e, pub.n) == m


# ─────────────────────────────────────────────────────────────────────────────
# 2) ELGAMAL HOMOMÓRFICO  — módulo de Voto
# ─────────────────────────────────────────────────────────────────────────────
# Grupo MODP de 2048 bits (RFC 3526, id 14). p seguro, g=2.
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(_P_HEX, 16)
G = 2
Q = (P - 1) // 2  # orden del subgrupo de residuos cuadráticos


@dataclass
class ElgamalPub:
    p: int
    g: int
    h: int  # g^x


class Trustee:
    """Custodio de la clave (en producción serían varios con umbral)."""

    def __init__(self):
        self.x = secrets.randbelow(Q - 2) + 2
        self.h = pow(G, self.x, P)

    def pub(self) -> ElgamalPub:
        return ElgamalPub(P, G, self.h)


def elgamal_encrypt(pub: ElgamalPub, vote: int) -> tuple[int, int]:
    """Cifra un voto (0/1 por opción) como M = g^vote. Homomórfico aditivo."""
    m = pow(pub.g, vote, pub.p)
    y = secrets.randbelow(Q - 2) + 2
    c1 = pow(pub.g, y, pub.p)
    c2 = (m * pow(pub.h, y, pub.p)) % pub.p
    return c1, c2


def elgamal_combine(cts: list[tuple[int, int]], p: int = P) -> tuple[int, int]:
    """Multiplica cifrados → cifrado de la SUMA de los votos (recuento cifrado)."""
    a, b = 1, 1
    for c1, c2 in cts:
        a = (a * c1) % p
        b = (b * c2) % p
    return a, b


def trustee_decrypt_tally(trustee: Trustee, combined: tuple[int, int], max_votes: int) -> int:
    """Descifra SOLO el total y resuelve el log discreto (baby-step) hasta max_votes."""
    c1, c2 = combined
    s = pow(c1, trustee.x, P)
    gm = (c2 * pow(s, -1, P)) % P
    # dlog: encontrar t tal que g^t = gm, 0<=t<=max_votes
    acc = 1
    for t in range(max_votes + 1):
        if acc == gm:
            return t
        acc = (acc * G) % P
    raise ValueError("dlog no encontrado (¿max_votes insuficiente?)")


# ─────────────────────────────────────────────────────────────────────────────
# 3) Tablón append-only (hash-chain) + recibo
# ─────────────────────────────────────────────────────────────────────────────
def chain_hash(prev_hash: str, payload: str) -> str:
    return sha256_hex(prev_hash + "|" + payload)
