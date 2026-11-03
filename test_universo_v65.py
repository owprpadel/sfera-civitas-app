"""v65 · UN SOLO UNIVERSO con certificado digital.
- Apoyos ponderados: email = 1 punto, certificado = 2; avanza al llegar a CONV_QUORUM puntos.
- Voto: una persona, un voto. Se publica TODOS y, aparte, «de ellos, con certificado» (si >= 5
  y el resto 0 o >= 5, para que el reparto no delate a nadie).
- Un certificado, un voto: borrar la cuenta y verificar otra con el mismo certificado NO permite votar dos veces.
Ejecuta: python3 test_universo_v65.py"""
import os, secrets
os.environ.setdefault("SFERA_CERT_SIM_ALLOWED", "1")
os.environ["SFERA_PILOT_CODES"] = "1"
os.environ["SFERA_CONV_QUORUM"] = "10"          # umbral pequeño para la prueba (10 puntos)
DBP = "/tmp/sfera_test_universo_v65.db"
os.environ["SFERA_DB"] = DBP
os.environ.setdefault("SFERA_ADMIN_EMAILS", "uadmin@sfera.org")
if os.path.exists(DBP):
    os.remove(DBP)
import db; db.init_db()
import service as s, cert_service as cs, crypto_core as cc, crypto_zk as zk
from crypto_core import P, G, Q

OK = FAIL = 0
def check(c, m):
    global OK, FAIL
    if c: OK += 1; print("  ok  ·", m)
    else: FAIL += 1; print("  FALLO ·", m)
def err(fn, status, m, frag=""):
    try: fn()
    except s.SferaError as e:
        check(e.status == status and frag in e.msg, f"{m} ({e.status}: {e.msg[:70]})"); return
    check(False, m + " (no lanzó error)")
def reg(email):
    r = s.register(email, "clave-test-123"); s.verify(email, r.get("codigo_piloto"))
    return s.get_user(s.login(email, "clave-test-123")["user_id"])
def cert(user, ref):
    """Firma con el certificado (simulado) JUSTO ANTES de un voto o apoyo: vale para una acción."""
    cs._mark_verified_sim(user["email"], ref); return s.get_user(user["id"])
REFS = {}

admin = reg("uadmin@sfera.org")

print("1 · Apoyos ponderados (email 1 · certificado 2 · umbral 10 puntos)")
check(s.CONV_QUORUM == 10 and s.CONV_PESO_CERT == 2 and s.CONV_QUORUM_VERIF == 5, "umbral 10 puntos; solo con certificado bastan 5")
did = s.create_debate("Asunto de un solo universo", "", "Movilidad", "Ayuntamiento", admin)["debate_id"]
for i in range(4):
    s.support_debate(did, reg(f"e{i}@sfera.org"))                 # 4 puntos
for i in range(2):
    s.support_debate(did, cert(reg(f"c{i}@sfera.org"), f"REF-C{i}"))   # +4 → 8 puntos
d = s.get_debate(did)
check(d["apoyos_puntos"] == 9 and d["phase"] == "convocar", f"creador 1 + 4 email + 2×2 certificado = 9 puntos: aún en Convocar ({d['apoyos_puntos']})")
s.support_debate(did, cert(reg("c2@sfera.org"), "REF-C2"))            # +2 → 11
d = s.get_debate(did)
check(d["apoyos_puntos"] == 11 and d["phase"] == "deliberar" and d["qualified_track"] == "mixto",
      "con 11 puntos (mezcla) pasa a Deliberar")
print("1b · El certificado se pide en CADA acción")
did3 = s.create_debate("Asunto sin firma reciente", "", "Movilidad", "Ayuntamiento", admin)["debate_id"]
c0 = s.get_user(s.login("c0@sfera.org", "clave-test-123")["user_id"])    # verificada, pero su firma ya se usó
r = s.support_debate(did3, c0)
check(r["via"] == "abierto" and s.get_debate(did3)["apoyos_puntos"] == 2, "cuenta verificada SIN firmar ahora: su apoyo cuenta como email (1 punto)")
did2 = s.create_debate("Asunto solo con certificado", "", "Movilidad", "Ayuntamiento", admin)["debate_id"]
for i in range(5):
    u_ = s.get_user(s.login(f"c{i}@sfera.org", "clave-test-123")["user_id"]) if i < 3 else reg(f"c{i}@sfera.org")
    s.support_debate(did2, cert(u_, f"REF-C{i}"))
d2 = s.get_debate(did2)
check(d2["phase"] == "deliberar" and d2["apoyos_puntos"] == 11, "creador + 5 apoyos con certificado (la mitad de personas) bastan")

print("2 · Resultado: TODOS + desglose con certificado (mínimo 5)")
def eleccion(titulo):
    x = s.create_debate(titulo, "", "Movilidad", "Ayuntamiento", admin)["debate_id"]
    s.set_phase(x, "deliberar", admin); s.set_phase(x, "proponer", admin)
    s.add_expert_proposal(x, admin, "Opción A", "Texto A.", "")
    s.set_phase(x, "votar", admin)
    return s.get_debate(x)["election"]["id"]
def votar(eid, user, chosen, firma=None):
    pub = s.election_public(eid, user)
    if firma:
        user = cert(user, firma)
    via = "verified" if firma else "open"
    H = int(pub["elgamal_pub"]["h"])
    bpub = cc.BlindPubKey(int(pub["blind_pub"][via]["n"]), int(pub["blind_pub"][via]["e"]))
    tok = secrets.token_bytes(32); bl, rr = cc.BlindSigner.blind(bpub, tok)
    sig = cc.BlindSigner.unblind(bpub, int(s.issue_credential(eid, user, str(bl), via)["blind_sig"]), rr)
    ballot, ys, bps = [], [], []
    for i in range(len(pub["options"])):
        b = 1 if i == chosen else 0; y = secrets.randbelow(Q - 2) + 2
        c1, c2 = pow(G, y, P), (pow(G, b, P) * pow(H, y, P)) % P
        ballot.append({"c1": str(c1), "c2": str(c2)}); ys.append(y); bps.append(zk.prove_bit(H, c1, c2, y, b))
    C1, C2 = zk.combine_ballot([(int(x["c1"]), int(x["c2"])) for x in ballot])
    return s.cast_vote(eid, tok.hex(), str(sig), ballot, bps, zk.prove_sum_one(H, C1, C2, sum(ys) % Q), via)

cert_users = [s.get_user(s.login(f"c{i}@sfera.org", "clave-test-123")["user_id"]) for i in range(5)]
email_users = [s.get_user(s.login(f"e{i}@sfera.org", "clave-test-123")["user_id"]) for i in range(4)]
eid = eleccion("Votación con 6 email y 5 certificado")
more = [reg(f"m{i}@sfera.org") for i in range(2)]
for u in email_users + more:
    votar(eid, u, 1)                                   # 6 email → «Ninguna»
for i, u in enumerate(cert_users):
    votar(eid, u, 0 if i < 4 else 1, firma=f"REF-C{i}")   # 5 con certificado (firman en ESTA votación): 4 A, 1 Ninguna
r = s.close_election(eid, admin)
check(r["todos"]["total_votos"] == 11 and r["todos"]["recuento"] == [4, 7], f"TODOS: 11 votos [4, 7] (cada persona un voto) {r['todos']['recuento']}")
check(r["con_certificado"]["total_votos"] == 5 and r["con_certificado"]["recuento"] == [4, 1],
      "de ellos, con certificado: 5 votos [4, 1] (publicable)")
check("open" not in r and "verified" not in r, "no se publica un resultado «solo email» aparte")
a = s.audit(eid)
check(a["recuento_reproducible"] is True, "la comprobación pública repite ambos recuentos y coinciden")

eid2 = eleccion("Votación con 3 email y 5 certificado")
for u in more + email_users[:1]:
    votar(eid2, u, 1)
for i, u in enumerate(cert_users):
    votar(eid2, u, 0, firma=f"REF-C{i}")
r2 = s.close_election(eid2, admin)
check(r2["con_certificado"]["recuento"] is None and not r2["con_certificado"]["desglose_publicado"],
      "resto de 3 votos (<5): NO se publica el reparto con certificado (restando se verían esos 3 votos)")
check(r2["todos"]["recuento"] == [5, 3], "el resultado de todos sí se publica [5, 3]")

print("3 · Un certificado, un voto (aunque se borre la cuenta)")
eid3 = eleccion("Votación anti doble voto")
votante = reg("doble@sfera.org")
votar(eid3, votante, 0, firma="REF-DOBLE")
s.delete_account(votante["id"], "clave-test-123")
nuevo = reg("doble2@sfera.org")       # mismo certificado, cuenta nueva
err(lambda: votar(eid3, nuevo, 1, firma="REF-DOBLE"), 409, "tras borrar la cuenta y firmar con el mismo certificado en otra: NO vuelve a votar", "ya ha votado")
otro = reg("sinfirma@sfera.org"); cert(otro, "REF-SINFIRMA")
with db.session() as conn:
    conn.execute("UPDATE users SET cert_fresh_until=? WHERE id=?", (db.now() - 1, otro["id"])); conn.commit()
pub3 = s.election_public(eid3, otro)
bpub = cc.BlindPubKey(int(pub3["blind_pub"]["verified"]["n"]), int(pub3["blind_pub"]["verified"]["e"]))
bl, _ = cc.BlindSigner.blind(bpub, secrets.token_bytes(32))
err(lambda: s.issue_credential(eid3, s.get_user(otro["id"]), str(bl), "verified"), 403,
    "cuenta verificada pero SIN firmar en esta votación: no vota con certificado", "firma con tu certificado")
check(s.issue_credential(eid3, s.get_user(otro["id"]), str(bl), "open")["via"] == "open", "…y puede votar solo con email")
with db.session() as conn:
    n = conn.execute("SELECT COUNT(*) AS n FROM cert_votes WHERE election_id=?", (eid3,)).fetchone()["n"]
    cols = [c[1] for c in conn.execute("PRAGMA table_info(cert_votes)").fetchall()]
check(n == 1 and "user_id" not in cols and "email" not in cols, "el registro guarda solo la huella del certificado (sin cuenta ni email)")
s.close_election(eid3, admin)
with db.session() as conn:
    conn.execute("UPDATE elections SET closed_at=? WHERE id=?", (db.now() - 91 * 86400, eid3)); conn.commit()
s.purge_expired()
with db.session() as conn:
    n2 = conn.execute("SELECT COUNT(*) AS n FROM cert_votes WHERE election_id=?", (eid3,)).fetchone()["n"]
check(n2 == 0, "se borra a los 90 días del cierre (retención)")

print(f"\nRESULTADO universo v65: {OK} OK · {FAIL} fallos")
raise SystemExit(1 if FAIL else 0)
