"""
crypto_zk.py — Pruebas de conocimiento cero (ZK) y custodios distribuidos.

Cierra dos huecos del prototipo hacia "serio":

 A) PAPELETA BIEN FORMADA (sin confiar en el cliente):
    - prueba disyuntiva Chaum-Pedersen de que cada opción cifra 0 o 1;
    - prueba de que la suma de opciones cifra exactamente 1 (one-hot).
    Todo NO interactivo (Fiat-Shamir). El servidor VERIFICA; no puede falsear.

 B) CUSTODIOS DISTRIBUIDOS (que nadie descifre solo):
    - n custodios, cada uno con su x_i; clave pública combinada H = Π g^{x_i};
    - descifrado del TOTAL por partes, cada custodio con prueba Chaum-Pedersen
      de que su parte es correcta (log_g h_i = log_{c1} s_i); se combinan.

Grupo: el mismo de crypto_core (MODP-2048, RFC 3526). Exponentes mod Q.
"""
from __future__ import annotations
import hashlib
import secrets
from dataclasses import dataclass

from crypto_core import P, G, Q


def _H(*ints: int) -> int:
    h = hashlib.sha256()
    for x in ints:
        h.update(str(x).encode())
    return int.from_bytes(h.digest(), "big") % Q


def _rand() -> int:
    return secrets.randbelow(Q - 2) + 2


# ─────────────────────────────────────────────────────────────────────────────
# A1) Prueba disyuntiva de bit: (c1,c2) cifra 0 O 1 bajo pubkey h
#     Relación clausula i: c1 = g^y  y  c2·g^{-i} = h^y   (igualdad de dlog y)
# ─────────────────────────────────────────────────────────────────────────────
def prove_bit(h: int, c1: int, c2: int, y: int, b: int) -> dict:
    # clausula real = b ; se simula la falsa
    # variables por clausula: (a1_i=g^w, a2_i=h^w) commit; challenge c_i; resp r_i
    ch = [0, 0]
    r = [0, 0]
    a1 = [0, 0]
    a2 = [0, 0]
    fake = 1 - b
    # clausula falsa: elige c_fake, r_fake al azar y despeja los commits
    ch[fake] = _rand()
    r[fake] = _rand()
    # target de la clausula fake: c2 * g^{-fake}
    t2 = (c2 * pow(pow(G, fake, P), -1, P)) % P
    a1[fake] = (pow(G, r[fake], P) * pow(c1, -ch[fake] % Q, P)) % P
    a2[fake] = (pow(h, r[fake], P) * pow(t2, -ch[fake] % Q, P)) % P
    # clausula real: commit honesto
    w = _rand()
    a1[b] = pow(G, w, P)
    a2[b] = pow(h, w, P)
    # challenge global (Fiat-Shamir) y reparto
    c = _H(h, c1, c2, a1[0], a2[0], a1[1], a2[1])
    ch[b] = (c - ch[fake]) % Q
    r[b] = (w + ch[b] * y) % Q
    return {"a1": a1, "a2": a2, "c": [ch[0], ch[1]], "r": [r[0], r[1]]}


def verify_bit(h: int, c1: int, c2: int, pr: dict) -> bool:
    a1, a2, ch, r = pr["a1"], pr["a2"], pr["c"], pr["r"]
    if (ch[0] + ch[1]) % Q != _H(h, c1, c2, a1[0], a2[0], a1[1], a2[1]):
        return False
    for i in (0, 1):
        if pow(G, r[i], P) != (a1[i] * pow(c1, ch[i], P)) % P:
            return False
        t2 = (c2 * pow(pow(G, i, P), -1, P)) % P
        if pow(h, r[i], P) != (a2[i] * pow(t2, ch[i], P)) % P:
            return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# A2) Prueba de que el producto de la papeleta cifra 1 (one-hot exacto)
#     C1=Π c1_i = g^R ; C2=Π c2_i = g^1 · h^R.  Probar dlog R en (C1, C2/g).
# ─────────────────────────────────────────────────────────────────────────────
def prove_sum_one(h: int, C1: int, C2: int, R: int) -> dict:
    T2 = (C2 * pow(G, -1, P)) % P  # debe ser h^R  (y C1 = g^R)
    w = _rand()
    a1 = pow(G, w, P)
    a2 = pow(h, w, P)
    c = _H(h, C1, C2, a1, a2)
    r = (w + c * R) % Q
    return {"a1": a1, "a2": a2, "r": r}


def verify_sum_one(h: int, C1: int, C2: int, pr: dict) -> bool:
    T2 = (C2 * pow(G, -1, P)) % P
    c = _H(h, C1, C2, pr["a1"], pr["a2"])
    return (pow(G, pr["r"], P) == (pr["a1"] * pow(C1, c, P)) % P and
            pow(h, pr["r"], P) == (pr["a2"] * pow(T2, c, P)) % P)


def combine_ballot(ballot: list[tuple[int, int]]) -> tuple[int, int]:
    C1, C2 = 1, 1
    for c1, c2 in ballot:
        C1 = (C1 * c1) % P
        C2 = (C2 * c2) % P
    return C1, C2


def verify_ballot(h: int, ballot: list[tuple[int, int]], bit_proofs: list[dict], sum_proof: dict) -> bool:
    """VERIFICA (servidor): cada opción es 0/1 y el conjunto suma 1. Sin confiar en el cliente."""
    if len(ballot) != len(bit_proofs):
        return False
    for (c1, c2), pr in zip(ballot, bit_proofs):
        if not verify_bit(h, c1, c2, pr):
            return False
    C1, C2 = combine_ballot(ballot)
    return verify_sum_one(h, C1, C2, sum_proof)


# ─────────────────────────────────────────────────────────────────────────────
# B) Custodios distribuidos
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class TrusteeShare:
    x: int          # secreto del custodio i
    h: int          # g^{x_i} (público)


def gen_trustees(n: int = 3) -> tuple[list[TrusteeShare], int]:
    """Genera n custodios independientes y la clave pública combinada H=Πg^{x_i}."""
    shares = [TrusteeShare(x=(secrets.randbelow(Q - 2) + 2), h=0) for _ in range(n)]
    H = 1
    for s in shares:
        s.h = pow(G, s.x, P)
        H = (H * s.h) % P
    return shares, H


def partial_decrypt(share: TrusteeShare, A: int) -> dict:
    """Custodio i aporta s_i = A^{x_i} + prueba CP de que log_g h_i = log_A s_i."""
    s = pow(A, share.x, P)
    w = _rand()
    a_g = pow(G, w, P)
    a_A = pow(A, w, P)
    c = _H(share.h, s, a_g, a_A, A)
    r = (w + c * share.x) % Q
    return {"s": s, "a_g": a_g, "a_A": a_A, "r": r, "h": share.h}


def verify_partial(A: int, pd: dict) -> bool:
    c = _H(pd["h"], pd["s"], pd["a_g"], pd["a_A"], A)
    return (pow(G, pd["r"], P) == (pd["a_g"] * pow(pd["h"], c, P)) % P and
            pow(A, pd["r"], P) == (pd["a_A"] * pow(pd["s"], c, P)) % P)


def combine_decrypt(A: int, B: int, partials: list[dict], max_votes: int) -> int:
    """Combina las partes (cada una verificada) y resuelve el total (dlog pequeño)."""
    S = 1
    for pd in partials:
        if not verify_partial(A, pd):
            raise ValueError("prueba de descifrado de un custodio inválida")
        S = (S * pd["s"]) % P
    gm = (B * pow(S, -1, P)) % P
    acc = 1
    for t in range(max_votes + 1):
        if acc == gm:
            return t
        acc = (acc * G) % P
    raise ValueError("dlog no encontrado")
