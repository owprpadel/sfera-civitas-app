"""Prueba end-to-end SIN dependencias (stdlib). Cubre la DOBLE VÍA (registro tipo X
y registro con certificado digital), pruebas ZK de papeleta y custodios distribuidos.
Ejecuta: python test_service.py"""
import os, secrets
os.environ["SFERA_DB"] = "/tmp/sfera_test.db"
os.environ.setdefault("SFERA_ADMIN_EMAILS", "admin@sfera.org")  # admin para abrir/cerrar votación
if os.path.exists("/tmp/sfera_test.db"):
    os.remove("/tmp/sfera_test.db")
import db; db.init_db()
import service as s, crypto_core as cc, crypto_zk as zk
from crypto_core import P, G, Q


def reg_open(email):
    """Registro tipo X: email + 2FA -> LoA 'open'."""
    r = s.register(email, "clave-test-123"); s.verify(email, r.get("codigo_piloto") or r.get("twofa_code_DEV"))
    return s.get_user(s.login(email, "clave-test-123")["user_id"])


def reg_verified(email):
    """Registro con certificado digital -> LoA 'verified'."""
    u = reg_open(email)
    s.verify_certificate(email, "CERT:" + email)  # DEV: certificado simulado
    return s.get_user(u["id"])


def _enc(H, v):
    y = secrets.randbelow(Q - 2) + 2
    return (pow(G, y, P), (pow(G, v, P) * pow(H, y, P)) % P), y


def make_ballot(H, n_opts, chosen):
    """LADO CLIENTE: cifra one-hot y genera pruebas ZK (cada opción 0/1, suma 1)."""
    ballot, ys, bit_proofs = [], [], []
    for i in range(n_opts):
        b = 1 if i == chosen else 0
        (c1, c2), y = _enc(H, b)
        ballot.append({"c1": str(c1), "c2": str(c2)}); ys.append(y)
        bit_proofs.append(zk.prove_bit(H, c1, c2, y, b))
    C1, C2 = zk.combine_ballot([(int(b["c1"]), int(b["c2"])) for b in ballot])
    sum_proof = zk.prove_sum_one(H, C1, C2, sum(ys) % Q)
    return ballot, bit_proofs, sum_proof


# Fases 1-3
autor = reg_open("autor@sfera.org")
admin = reg_open("admin@sfera.org")
did = s.create_debate("Presupuesto de mi ciudad 2027", "", "Hacienda local", "Ayuntamiento", autor)["debate_id"]
# Fases en orden (solo la fase actual admite acciones): el admin avanza manualmente.
s.set_phase(did, "deliberar", admin)
s.add_argument(did, autor["id"], "favor", "Más a transporte público.")
s.set_phase(did, "proponer", admin)
s.add_proposal(did, autor["id"], "Destinar 20% a movilidad sostenible.")   # propuesta CIUDADANA (insumo)
# Solo se votan propuestas EXPERTAS: el admin del asunto (o un experto) publica una.
s.add_expert_proposal(did, admin, "Destinar el 20% a movilidad sostenible",
                      "Reservar el 20% del presupuesto de inversiones a transporte público y carril bici.",
                      "Recoge la propuesta ciudadana más apoyada y los argumentos sobre transporte público.")

# Fase 4: votación (custodios distribuidos + dos vías). Papeleta = propuesta experta + «Ninguna».
s.set_phase(did, "votar", admin)
eid = s.get_debate(did)["election"]["id"]
pub = s.election_public(eid)
assert pub["options"] == ["Destinar el 20% a movilidad sostenible", s.NONE_OPTION], pub["options"]
H = int(pub["elgamal_pub"]["h"])


def votar(user, chosen, via):
    bpub = cc.BlindPubKey(int(pub["blind_pub"][via]["n"]), int(pub["blind_pub"][via]["e"]))
    token = secrets.token_bytes(32)
    blinded, r = cc.BlindSigner.blind(bpub, token)
    sig = cc.BlindSigner.unblind(bpub, int(s.issue_credential(eid, user, str(blinded), via)["blind_sig"]), r)
    ballot, bp, sp = make_ballot(H, len(pub["options"]), chosen)
    return s.cast_vote(eid, token.hex(), str(sig), ballot, bp, sp, via)


# Vía ABIERTA (tipo X): 6 a favor, 4 en contra
rec = [votar(reg_open(f"si{i}@sfera.org"), 0, "open") for i in range(6)] + \
      [votar(reg_open(f"no{i}@sfera.org"), 1, "open") for i in range(4)]
# Vía VERIFICADA (certificado): 3 a favor, 1 en contra
recv = [votar(reg_verified(f"vsi{i}@sfera.org"), 0, "verified") for i in range(3)] + \
       [votar(reg_verified(f"vno{i}@sfera.org"), 1, "verified") for i in range(1)]
print("Recibo abierto:", rec[0]["receipt"], "· recibo verificado:", recv[0]["receipt"])

# Un usuario 'open' NO puede pedir credencial en la vía verificada (403)
try:
    votar(reg_open("colado@sfera.org"), 0, "verified")
    print("FALLO: usuario open votó en vía verificada")
except s.SferaError as e:
    print("Vía verificada protegida:", e.status, "-", e.msg[:45])

# Papeleta TRAMPOSA en vía abierta: intenta votar '2' -> la prueba ZK la rechaza (400)
u = reg_open("tramposo@sfera.org")
bpub = cc.BlindPubKey(int(pub["blind_pub"]["open"]["n"]), int(pub["blind_pub"]["open"]["e"]))
tk = secrets.token_bytes(32); bl, r = cc.BlindSigner.blind(bpub, tk)
sig = cc.BlindSigner.unblind(bpub, int(s.issue_credential(eid, u, str(bl), "open")["blind_sig"]), r)
(c1, c2), y = _enc(H, 2)  # voto ilegal = 2
badbit = zk.prove_bit(H, c1, c2, y, 1)
(c1b, c2b), yb = _enc(H, 0)
ballot_bad = [{"c1": str(c1), "c2": str(c2)}, {"c1": str(c1b), "c2": str(c2b)}]
C1, C2 = zk.combine_ballot([(c1, c2), (c1b, c2b)])
sp_bad = zk.prove_sum_one(H, C1, C2, (y + yb) % Q)
try:
    s.cast_vote(eid, tk.hex(), str(sig), ballot_bad, [badbit, zk.prove_bit(H, c1b, c2b, yb, 0)], sp_bad, "open")
    print("FALLO: aceptó papeleta ilegal")
except s.SferaError as e:
    print("Papeleta ilegal rechazada por ZK:", e.status, "-", e.msg[:40])

# Fase 5: publicar (descifrado distribuido, recuentos SEPARADOS por vía)
result = s.close_election(eid, admin)
print("ABIERTA :", result["open"]["opciones"], "=", result["open"]["recuento"], "(umbral", result["open"]["umbral_convocatoria"], ")")
print("VERIFIC.:", result["verified"]["opciones"], "=", result["verified"]["recuento"], "(umbral", result["verified"]["umbral_convocatoria"], ")")
assert result["open"]["recuento"] == [6, 4], result["open"]["recuento"]
assert result["verified"]["recuento"] == [3, 1], result["verified"]["recuento"]
aud = s.audit(eid)
print("AUDITORÍA:", aud)
assert aud["cadena_integra"] and aud["papeletas_zk_validas"] and aud["recuento_reproducible"]
print("\nOK: doble vía (tipo X + certificado) · identidad desacoplada · papeleta con prueba ZK ·")
print("    custodios distribuidos · recuentos separados por garantía · verificable/auditable.")
