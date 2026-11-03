"""v64 · RGPD/LOPDGDD (21-oct-2026): consentimiento en el registro, códigos con huella,
borrado con anonimización, exportación de datos, retención, certificado sin nombre,
tablón sin horas, IA nunca en privados y API sin ids para quien no tiene sesión.
Ejecuta: python3 test_rgpd_v64.py"""
import ast
import json
import os
import re
import secrets
os.environ.setdefault("SFERA_CERT_SIM_ALLOWED", "1")
os.environ["SFERA_PILOT_CODES"] = "1"
DBP = "/tmp/sfera_test_rgpd_v64.db"
os.environ["SFERA_DB"] = DBP
os.environ.setdefault("SFERA_ADMIN_EMAILS", "radmin@sfera.org")
for k in ("SFERA_RESEND_KEY", "SFERA_BREVO_KEY", "SFERA_ZEPTO_KEY", "SFERA_SMTP_HOST"):
    os.environ.pop(k, None)
if os.path.exists(DBP):
    os.remove(DBP)
import db; db.init_db()
import service as s, cert_service as cs, crypto_core as cc, crypto_zk as zk, moderation as mod
import citizen_docs as cd
from crypto_core import P, G, Q

OK = FAIL = 0


def check(cond, msg):
    global OK, FAIL
    if cond:
        OK += 1; print("  ok  ·", msg)
    else:
        FAIL += 1; print("  FALLO ·", msg)


def err(fn, status, msg, frag=""):
    try:
        fn()
    except s.SferaError as e:
        check(e.status == status and frag in e.msg, f"{msg} ({e.status}: {e.msg[:70]})")
        return
    check(False, msg + " (no lanzó error)")


def one(sql, p=()):
    with db.session() as conn:
        r = conn.execute(sql, p).fetchone()
        return dict(r) if r else None


def run(sql, p=()):
    with db.session() as conn:
        conn.execute(sql, p); conn.commit()


def reg(email):
    r = s.register(email, "clave-test-123"); s.verify(email, r["codigo_piloto"])
    return s.get_user(s.login(email, "clave-test-123")["user_id"])


print("1 · Consentimiento en el registro")
err(lambda: s.register("c1@sfera.org", "clave-test-123", False, True, True), 400, "sin aceptar Condiciones → 400", "Condiciones")
err(lambda: s.register("c1@sfera.org", "clave-test-123", True, False, True), 400, "sin consentimiento de privacidad → 400", "opiniones políticas")
err(lambda: s.register("c1@sfera.org", "clave-test-123", True, True, False), 400, "sin declarar 14 años → 400", "14 años")
err(lambda: s.register("c1@sfera.org", "clave-test-123", True, True, None), 400, "None no vale como consentimiento", "14 años")
check(one("SELECT 1 AS x FROM users WHERE email='c1@sfera.org'") is None, "sin consentimiento no se crea la cuenta")
r = s.register("c1@sfera.org", "clave-test-123", True, True, True)
u = one("SELECT * FROM users WHERE id=?", (r["user_id"],))
check(u["terms_version"] == s.LEGAL_VERSION == "2026-10-21", "guarda la versión aceptada (LEGAL_VERSION)")
check(u["privacy_accepted_at"] and int(u["age_confirmed"]) == 1, "guarda el momento del consentimiento y la edad")
check(s.legal_info() == {"version": "2026-10-21", "privacy_url": "https://sferacivitas.org/privacidad.html",
                          "terms_url": "https://app.sferacivitas.org/terminos.html"}, "legal_info (GET /api/legal)")

print("6 · Códigos de verificación con huella y modo piloto explícito")
code = r["codigo_piloto"]
check(u["twofa_code"] and u["twofa_code"] != code and u["twofa_code"].startswith("h$"), "el código NO se guarda en claro (HMAC)")
err(lambda: s.verify("c1@sfera.org", "000000" if code != "000000" else "111111"), 400, "código incorrecto → 400", "incorrecto")
check(s.verify("c1@sfera.org", code)["verified"], "el código correcto (comparado por huella) verifica")
os.environ["SFERA_PILOT_CODES"] = "0"
r2 = s.register("c2@sfera.org", "clave-test-123")
check("codigo_piloto" not in r2, "sin SFERA_PILOT_CODES=1 el registro NO devuelve el código")
check("codigo_piloto" not in s.resend_code("c2@sfera.org"), "ni el reenvío")
check("codigo_piloto" not in s.forgot_password("c1@sfera.org"), "ni el código de contraseña")
os.environ["SFERA_PILOT_CODES"] = "1"
rc = s.resend_code("c2@sfera.org")
run("UPDATE users SET twofa_created=? WHERE email='c2@sfera.org'", (db.now() - 25 * 3600,))
err(lambda: s.verify("c2@sfera.org", rc["codigo_piloto"]), 400, "un código de más de 24 h caduca", "caducado")
# compatibilidad: un código en claro anterior al despliegue sigue valiendo
run("UPDATE users SET twofa_code='123456', twofa_created=NULL, twofa_attempts=0 WHERE email='c2@sfera.org'")
check(s.verify("c2@sfera.org", "123456")["verified"], "código en claro previo al despliegue: sigue valiendo una vez")

print("5 · Certificado: sin nombre, mismo secreto")
check(cs.SECRET == s._SECRET, "cert_service usa el MISMO secreto que service")
uc = reg("cert@sfera.org")
s.verify_certificate("cert@sfera.org", "CN=GARCIA LOPEZ ANA - 12345678Z")
row = one("SELECT cert_subject, cert_pid, loa FROM users WHERE id=?", (uc["id"],))
check(row["cert_subject"] == db.CERT_NEUTRAL_LABEL and "GARCIA" not in json.dumps(row), "no guarda el nombre (etiqueta neutra)")
check(row["cert_pid"] and len(row["cert_pid"]) == 64 and row["loa"] == "verified", "guarda solo la huella HMAC")
uc2 = reg("cert2@sfera.org")
err(lambda: s.verify_certificate("cert2@sfera.org", "CN=GARCIA LOPEZ ANA - 12345678Z"), 409, "mismo certificado en otra cuenta → 409")
cs._mark_verified_sim("cert2@sfera.org", "OTRA-REF Pepe Pérez")
check(one("SELECT cert_subject FROM users WHERE id=?", (uc2["id"],))["cert_subject"] == db.CERT_NEUTRAL_LABEL, "cert_service tampoco guarda la referencia")
run("UPDATE users SET cert_subject='Nombre Antiguo' WHERE id=?", (uc2["id"],))
db.init_db()
check(one("SELECT cert_subject FROM users WHERE id=?", (uc2["id"],))["cert_subject"] == db.CERT_NEUTRAL_LABEL, "migración al arrancar: nombres antiguos → etiqueta neutra")

print("4 · Voto: tablón sin horas, recuento SOLO del agregado")
admin = reg("radmin@sfera.org")
autor = reg("autor@sfera.org")
did = s.create_debate("Asunto RGPD de prueba de voto", "", "Hacienda local", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did, "deliberar", admin)
a1 = s.add_argument(did, autor["id"], "favor", "Argumento del autor que borrará su cuenta.")
s.set_phase(did, "proponer", admin)
p1 = s.add_proposal(did, autor["id"], "Propuesta del autor que borrará su cuenta.")
s.add_expert_proposal(did, admin, "Opción A", "Texto de la opción A.", "")
s.set_phase(did, "votar", admin)
eid = s.get_debate(did)["election"]["id"]
pub = s.election_public(eid)
H = int(pub["elgamal_pub"]["h"])


def make_ballot(n, chosen):
    ballot, ys, bps = [], [], []
    for i in range(n):
        b = 1 if i == chosen else 0
        y = secrets.randbelow(Q - 2) + 2
        c1, c2 = pow(G, y, P), (pow(G, b, P) * pow(H, y, P)) % P
        ballot.append({"c1": str(c1), "c2": str(c2)}); ys.append(y); bps.append(zk.prove_bit(H, c1, c2, y, b))
    C1, C2 = zk.combine_ballot([(int(x["c1"]), int(x["c2"])) for x in ballot])
    return ballot, bps, zk.prove_sum_one(H, C1, C2, sum(ys) % Q)


def votar(user, chosen):
    bpub = cc.BlindPubKey(int(pub["blind_pub"]["open"]["n"]), int(pub["blind_pub"]["open"]["e"]))
    tok = secrets.token_bytes(32)
    bl, rr = cc.BlindSigner.blind(bpub, tok)
    sig = cc.BlindSigner.unblind(bpub, int(s.issue_credential(eid, user, str(bl), "open")["blind_sig"]), rr)
    b, bp, sp = make_ballot(len(pub["options"]), chosen)
    return s.cast_vote(eid, tok.hex(), str(sig), b, bp, sp, "open")


votar(autor, 0)
votar(reg("v1@sfera.org"), 0)
votar(reg("v2@sfera.org"), 1)
# El recuento NO descifra papeletas una a una: se intercepta el descifrado parcial.
calls = []
_orig = s.zk.partial_decrypt
s.zk.partial_decrypt = lambda sh, A: (calls.append(A) or _orig(sh, A))
res = s.close_election(eid, admin)
s.zk.partial_decrypt = _orig
check(res["todos"]["recuento"] == [2, 1], "recuento correcto [2, 1]")
check(len(calls) == len(pub["options"]) * 3, "v65: descifra SOLO el agregado de TODOS por opción (sin certificado: no se descifra ningún desglose)")
with db.session() as conn:
    ballots = [dict(r) for r in conn.execute("SELECT payload_json FROM bulletin_board WHERE election_id=? AND kind='ballot'", (eid,)).fetchall()]
agg_c1 = 1
for b in ballots:
    agg_c1 = (agg_c1 * int(json.loads(b["payload_json"])["ballot"][0]["c1"])) % P
check(agg_c1 in calls and not any(int(json.loads(b["payload_json"])["ballot"][0]["c1"]) in calls for b in ballots),
      "lo que se descifra es el PRODUCTO de las papeletas, nunca una papeleta")
check(one("SELECT COUNT(*) AS n FROM bulletin_board WHERE election_id=? AND created IS NOT NULL", (eid,))["n"] == 0,
      "ninguna entrada del tablón (génesis, papeletas, resultado) guarda hora")
check(one("SELECT closed_at FROM elections WHERE id=?", (eid,))["closed_at"], "la votación guarda su momento de cierre (retención)")
check("user" not in json.dumps(s.get_board(eid)) and "issued" not in json.dumps(s.get_board(eid)), "el tablón no tiene identidad")

print("3 · Exportar mis datos")
uid_a = autor["id"]
run("INSERT INTO notifications(user_id,kind,debate_id,text,read,created) VALUES(?,?,?,?,0,?)", (uid_a, "x", did, "aviso", db.now()))
exp = s.export_account(autor)
blob = json.dumps(exp, ensure_ascii=False)
check(exp["perfil"]["email"] == "autor@sfera.org" and exp["consentimientos"]["version_aceptada"] == s.LEGAL_VERSION, "perfil + consentimientos")
check(len(exp["argumentos"]) == 1 and len(exp["propuestas"]) == 1 and len(exp["notificaciones"]) >= 1, "aportaciones y avisos")
check(len(exp["asuntos_convocados"]) == 1, "asuntos que convocó")
check(len(exp["votaciones_con_papeleta_emitida"]) == 1 and exp["votaciones_con_papeleta_emitida"][0]["election_id"] == eid,
      "lista de votaciones con papeleta emitida")
check("pass_hash" not in blob and "scrypt$" not in blob and "twofa" not in blob and "reset_code" not in blob, "sin contraseñas ni huellas")
check("ballot" not in blob and "c1" not in blob and "recuento" not in blob, "NUNCA el contenido de un voto")

print("2 · Eliminar la cuenta: identidad suprimida y todo anonimizado")
otro = reg("otro@sfera.org")
did2 = s.create_debate("Asunto en convocatoria para apoyos", "", "Movilidad", "Ayuntamiento", otro)["debate_id"]
s.support_debate(did2, autor)
did3 = s.create_debate("Asunto deliberar útiles", "", "Movilidad", "Ayuntamiento", otro)["debate_id"]
s.set_phase(did3, "deliberar", admin)
a_otro = s.add_argument(did3, otro["id"], "favor", "Argumento de otra persona.")
aid_otro = a_otro.get("id") or a_otro.get("argument_id")
s.toggle_util("argument", aid_otro, autor, True)
cdoc = cd.add_doc(did3, autor, "dato", "Un dato del autor", "Texto del dato", "")
mod.report_content(autor, "argument", aid_otro, "spam", "")             # denuncia pendiente
mod.block_user(autor, otro["id"])
org = s.create_org(autor, "Colectivo del autor")
oid = org["org_id"]
s.invite_member(autor, oid, "invitado@sfera.org")
run("INSERT INTO org_invites(org_id,email,token,used,created) VALUES(?,?,?,0,?)", (oid, "autor@sfera.org", "tok-autor", db.now()))
run("INSERT INTO payments(org_id,provider,external_id,status,amount_cents,currency,units,email,raw,created) VALUES(?,?,?,?,?,?,?,?,?,?)",
    (oid, "lemonsqueezy", "ext-1", "paid", 200, "EUR", 1, "autor@sfera.org", '{"email":"autor@sfera.org"}', db.now()))
run("INSERT INTO support_tickets(msg_uid,from_email,subject,body,status,created,updated) VALUES(?,?,?,?,?,?,?)",
    ("uid-1", "Autor <autor@sfera.org>", "Ayuda", "cuerpo", "nuevo", db.now(), db.now()))
run("INSERT INTO expert_profiles(user_id,display_name,specialty,created) VALUES(?,?,?,?)", (uid_a, "Autor Experto", "Hacienda", db.now()))
ballots_before = one("SELECT COUNT(*) AS n FROM bulletin_board WHERE election_id=? AND kind='ballot'", (eid,))["n"]
err(lambda: s.delete_account(uid_a, "mala-clave"), 403, "contraseña incorrecta → 403")
check(s.delete_account(uid_a, "clave-test-123")["deleted"], "borra la cuenta")
anon = one("SELECT id FROM users WHERE email=?", (s.ANON_EMAIL,))["id"]
gone = lambda sql, p=(uid_a,): one(sql, p)["n"] == 0
uu = one("SELECT * FROM users WHERE id=?", (uid_a,))
check(uu["email"] == f"deleted-{uid_a}@deleted.invalid" and uu["terms_version"] is None and uu["cert_subject"] is None, "identidad suprimida")
check(one("SELECT user_id FROM arguments WHERE id=?", (a1.get("id") or a1.get("argument_id"),))["user_id"] == anon,
      "su argumento pasa al autor anónimo (texto conservado)")
check(gone("SELECT COUNT(*) AS n FROM arguments WHERE user_id=?") and gone("SELECT COUNT(*) AS n FROM proposals WHERE user_id=?")
      and gone("SELECT COUNT(*) AS n FROM citizen_docs WHERE user_id=?"), "ninguna aportación queda ligada a su id")
check(one("SELECT COUNT(*) AS n FROM citizen_docs WHERE user_id=?", (anon,))["n"] == 1, "su documento sigue (anónimo)")
check(gone("SELECT COUNT(*) AS n FROM supports WHERE user_id=?") and gone("SELECT COUNT(*) AS n FROM argument_utiles WHERE user_id=?"),
      "apoyos y «útil» borrados")
check(gone("SELECT COUNT(*) AS n FROM credential_issued WHERE user_id=?"), "registro «ha votado» borrado")
check(one("SELECT COUNT(*) AS n FROM bulletin_board WHERE election_id=? AND kind='ballot'", (eid,))["n"] == ballots_before
      and s.audit(eid)["recuento_reproducible"], "las papeletas y el recuento no cambian")
check(gone("SELECT COUNT(*) AS n FROM notifications WHERE user_id=?") and gone("SELECT COUNT(*) AS n FROM user_blocks WHERE blocker_id=?"),
      "avisos y bloqueos borrados")
check(gone("SELECT COUNT(*) AS n FROM reports WHERE reporter_id=?") and
      one("SELECT COUNT(*) AS n FROM reports WHERE reporter_id=? AND status='pending'", (anon,))["n"] == 1,
      "su denuncia pendiente sigue para moderación, pero anónima")
check(one("SELECT COUNT(*) AS n FROM org_invites WHERE email='autor@sfera.org'")["n"] == 0, "invitaciones a su email borradas")
pay = one("SELECT * FROM payments WHERE external_id='ext-1'")
check(pay["email"] is None and pay["raw"] is None and pay["amount_cents"] == 200, "pago: sin email ni payload; importe conservado")
check(one("SELECT COUNT(*) AS n FROM support_tickets WHERE from_email LIKE '%autor@sfera.org%'")["n"] == 0, "tickets de soporte borrados")
check(gone("SELECT COUNT(*) AS n FROM expert_profiles WHERE user_id=?"), "perfil de experto borrado")
check(one("SELECT created_by FROM debates WHERE id=?", (did,))["created_by"] is None, "ya no figura como proponente")
err(lambda: s.get_user(anon), 401, "el autor anónimo no tiene sesión")
try:
    s.login(s.ANON_EMAIL, "x"); check(False, "el autor anónimo no puede entrar")
except s.SferaError:
    check(True, "el autor anónimo no puede entrar")
# Un segundo borrado reutiliza el mismo autor anónimo
v1 = s.get_user(s.login("otro@sfera.org", "clave-test-123")["user_id"])
s.delete_account(v1["id"], "clave-test-123")
check(one("SELECT COUNT(*) AS n FROM users WHERE email=?", (s.ANON_EMAIL,))["n"] == 1, "un único autor anónimo")
lst = s.list_arguments(did3, None)
check(all("is_mine" in it for it in lst["items"]) and not any(it["is_mine"] for it in lst["items"]), "is_mine en los listados")

print("9 · Retención (purge_expired)")
now = db.now()
u9 = reg("ret@sfera.org")
run("INSERT INTO notifications(user_id,kind,text,read,created) VALUES(?,?,?,0,?)", (u9["id"], "x", "viejo", now - 181 * 86400))
run("INSERT INTO notifications(user_id,kind,text,read,created) VALUES(?,?,?,0,?)", (u9["id"], "x", "nuevo", now - 10 * 86400))
run("INSERT INTO cert_challenges(user_id,nonce,expires,used,created) VALUES(?,?,?,0,?)", (u9["id"], "n1", now - 2 * 86400, now - 2 * 86400))
run("INSERT INTO cert_challenges(user_id,nonce,expires,used,created) VALUES(?,?,?,0,?)", (u9["id"], "n2", now + 300, now))
run("UPDATE users SET twofa_code='h$x', twofa_created=? WHERE id=?", (now - 2 * 86400, u9["id"]))
org9 = s.create_org(u9, "Org retención")["org_id"]
run("INSERT INTO org_invites(org_id,email,token,used,created) VALUES(?,?,?,0,?)", (org9, "a@x.org", "t-old", now - 61 * 86400))
run("INSERT INTO org_invites(org_id,email,token,used,created) VALUES(?,?,?,0,?)", (org9, "b@x.org", "t-new", now - 40 * 86400))
run("INSERT INTO support_tickets(msg_uid,from_email,subject,status,created,updated) VALUES(?,?,?,?,?,?)", ("s-old", "a@x.org", "x", "resuelto", now - 400 * 86400, now - 370 * 86400))
run("INSERT INTO support_tickets(msg_uid,from_email,subject,status,created,updated) VALUES(?,?,?,?,?,?)", ("s-open", "b@x.org", "x", "nuevo", now - 400 * 86400, now - 370 * 86400))
run("INSERT INTO payments(org_id,provider,external_id,status,amount_cents,units,email,raw,created) VALUES(?,?,?,?,?,?,?,?,?)",
    (org9, "paddle", "p-old", "paid", 100, 1, "c@x.org", "{}", now - 31 * 86400))
run("INSERT INTO payments(org_id,provider,external_id,status,amount_cents,units,email,raw,created) VALUES(?,?,?,?,?,?,?,?,?)",
    (org9, "paddle", "p-new", "paid", 100, 1, "c@x.org", "{}", now - 5 * 86400))
run("INSERT INTO reports(reporter_id,target_type,target_id,reason,status,resolved_at,created) VALUES(?,?,?,?,?,?,?)",
    (u9["id"], "debate", 999, "spam", "kept", now - 366 * 86400, now - 370 * 86400))
run("INSERT INTO reports(reporter_id,target_type,target_id,reason,status,created) VALUES(?,?,?,?,?,?)",
    (u9["id"], "debate", 998, "spam", "pending", now - 370 * 86400))
# «ha votado»: votación cerrada hace > 90 días
ve = reg("ve@sfera.org")
run("INSERT INTO credential_issued(election_id,user_id,via,issued_at) VALUES(?,?,?,?)", (eid, ve["id"], "open", now))
run("UPDATE elections SET closed_at=? WHERE id=?", (now - 91 * 86400, eid))
votes_before = s.get_debate(did)["election"]["n_votos"]
out = s.purge_expired(now)
print("   ", out)
check(one("SELECT COUNT(*) AS n FROM notifications WHERE user_id=?", (u9["id"],))["n"] == 1, "avisos de > 180 días borrados (los recientes no)")
check(one("SELECT COUNT(*) AS n FROM cert_challenges WHERE user_id=?", (u9["id"],))["n"] == 1, "retos de certificado de > 24 h borrados")
check(one("SELECT twofa_code FROM users WHERE id=?", (u9["id"],))["twofa_code"] is None, "códigos de verificación de > 24 h anulados")
check(one("SELECT COUNT(*) AS n FROM org_invites WHERE token='t-old'")["n"] == 0 and
      one("SELECT COUNT(*) AS n FROM org_invites WHERE token='t-new'")["n"] == 1, "invitaciones: 30 días tras caducar")
check(one("SELECT COUNT(*) AS n FROM support_tickets WHERE msg_uid='s-old'")["n"] == 0 and
      one("SELECT COUNT(*) AS n FROM support_tickets WHERE msg_uid='s-open'")["n"] == 1, "tickets: 12 meses desde el cierre (los abiertos no)")
check(one("SELECT raw FROM payments WHERE external_id='p-old'")["raw"] is None and
      one("SELECT raw FROM payments WHERE external_id='p-new'")["raw"] == "{}" and
      one("SELECT amount_cents FROM payments WHERE external_id='p-old'")["amount_cents"] == 100, "pagos: payload a los 30 días; importe se conserva")
check(one("SELECT COUNT(*) AS n FROM reports WHERE target_id=999")["n"] == 0 and
      one("SELECT COUNT(*) AS n FROM reports WHERE target_id=998")["n"] == 1, "denuncias: 12 meses tras resolverse (pendientes no)")
check(one("SELECT COUNT(*) AS n FROM credential_issued WHERE election_id=?", (eid,))["n"] == 0, "«ha votado»: cierre + 90 días")
check(s.get_debate(did)["election"]["n_votos"] == votes_before and s.audit(eid)["recuento_reproducible"],
      "la participación y el recuento no dependen de credential_issued")
check(all(v == 0 for k, v in s.purge_expired(now).items() if k != "codigos_verificacion"), "idempotente (2ª pasada sin cambios)")

print("10 · IA nunca en privados")
import ia_participante as ia
dpriv = s.create_debate("Privado RGPD", "", "Vivienda", "", u9, org_id=org9)["debate_id"]
with db.session() as conn:
    dd = dict(conn.execute("SELECT * FROM debates WHERE id=?", (dpriv,)).fetchone())
    check(ia._eligible(conn, dd) is not None, "_eligible excluye los asuntos privados")
check(ia.enabled() is False or os.environ.get("SFERA_IA_ON") == "1", "la IA sigue apagada por defecto")

print("7/11/12 · API (main.py, comprobación estática: FastAPI no está en el entorno de pruebas)")
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py"), encoding="utf-8").read()
tree = ast.parse(src)
check("accept_terms: bool = False" in src and "accept_privacy: bool = False" in src and "age_14: bool = False" in src,
      "RegisterIn exige los tres consentimientos (por defecto False)")
check('@app.get("/api/legal")' in src and '@app.get("/api/account/export")' in src, "rutas /api/legal y /api/account/export")
check(re.search(r'elections/\\d\+/credential\$"\), "credential",\s*\(int\(os.environ.get\("SFERA_RL_CREDENTIAL", "20"\)\), 600\)', src) is not None,
      "límite por IP en /credential (20/10 min)")
check(re.search(r'elections/\\d\+/cast\$"\), "cast",\s*\(int\(os.environ.get\("SFERA_RL_CAST", "30"\)\), 600\)', src) is not None,
      "límite por IP en /cast (30/10 min)")
for h in ("X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Strict-Transport-Security"):
    check(h in src, f"cabecera {h}")
check('"https://app.sferacivitas.org", "https://sferacivitas.org", "capacitor://localhost"' in src and "SFERA_CORS_ORIGINS" in src,
      "CORS cerrado por defecto (sobrescribible con SFERA_CORS_ORIGINS)")
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "strip_private_ids")
keys = next(n for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "_PRIVATE_ID_KEYS")
ns = {}
exec(compile(ast.Module(body=[keys, fn], type_ignores=[]), "main_excerpt", "exec"), ns)
pubd = json.loads(json.dumps(s.get_debate(did3, None), default=str))
stripped = ns["strip_private_ids"](pubd)
blob = json.dumps(stripped)
check('"user_id"' in json.dumps(pubd) and '"user_id"' not in blob and '"created_by"' not in blob, "sin sesión: sin user_id/created_by")
check(stripped.get("title") == pubd.get("title") and len(stripped["arguments"]) == len(pubd["arguments"]), "el resto de la ficha intacto")

print(f"\nRESULTADO RGPD v64: {OK} OK · {FAIL} fallos")
if FAIL:
    raise SystemExit(1)
