"""Prueba v59 — correcciones de la auditoría (privacidad, cuentas, voto, archivos, pagos…).
Cada bloque lleva el número del hallazgo que comprueba (1-33).
Ejecuta: python3 test_auditoria_v59.py"""
import ast, base64, datetime, hashlib, hmac, io, json, os, re, secrets, tempfile, time, zipfile
os.environ.setdefault("SFERA_CERT_SIM_ALLOWED", "1")
DBP = "/tmp/sfera_test_auditoria_v59.db"
os.environ["SFERA_DB"] = DBP
os.environ.setdefault("SFERA_ADMIN_EMAILS", "aadmin@sfera.org,anuevo@sfera.org")
os.environ.pop("SFERA_DEMO_PASSWORD", None)
if os.path.exists(DBP):
    os.remove(DBP)
import db; db.init_db()
import service as s, docs_service as ds, citizen_docs as cd, experts_service as xs, roles as rl
import moderation as mod, uploads, demo_files, demo_seed, support_service as sup, cert_service as cs
import crypto_core as cc, crypto_zk as zk
from crypto_core import P, G, Q

DAY = 86400
PASSED, FAILED = 0, 0
def check(cond, label):
    global PASSED, FAILED
    if cond: PASSED += 1; print("  ok  ·", label)
    else: FAILED += 1; print("  FALLO ·", label)
def expect_error(fn, status, label, contains=None):
    try: fn()
    except s.SferaError as e:
        check(e.status == status and (contains is None or contains in e.msg), f"{label} (HTTP {e.status}: {e.msg})"); return
    except cs.CertError as e:
        check(e.code == status and (contains is None or contains in e.msg), f"{label} (HTTP {e.code}: {e.msg})"); return
    check(False, label + " (no lanzó error)")
def reg(email, verify=True):
    r = s.register(email, "clave-test-123")
    if verify:
        s.verify(email, r.get("codigo_piloto"))
    return s.get_user(s.login(email, "clave-test-123")["user_id"])
def sql(q, p=()):
    with db.session() as conn:
        conn.execute(q, p); conn.commit()
def one(q, p=()):
    with db.session() as conn:
        r = conn.execute(q, p).fetchone()
    return dict(r) if r else None
b64 = lambda raw: base64.b64encode(raw).decode()
PDF = demo_files.pdf("Informe", ["Contenido de prueba."])

def _enc(H, v):
    y = secrets.randbelow(Q - 2) + 2
    return (pow(G, y, P), (pow(G, v, P) * pow(H, y, P)) % P), y
def make_ballot(H, n_opts, chosen):
    ballot, ys, bit_proofs = [], [], []
    for i in range(n_opts):
        b = 1 if i == chosen else 0
        (c1, c2), y = _enc(H, b)
        ballot.append({"c1": str(c1), "c2": str(c2)}); ys.append(y)
        bit_proofs.append(zk.prove_bit(H, c1, c2, y, b))
    C1, C2 = zk.combine_ballot([(int(b["c1"]), int(b["c2"])) for b in ballot])
    return ballot, bit_proofs, zk.prove_sum_one(H, C1, C2, sum(ys) % Q)
def votar(eid, user, chosen, via="open", viewer=None):
    pub = s.election_public(eid, viewer or user)
    bpub = cc.BlindPubKey(int(pub["blind_pub"][via]["n"]), int(pub["blind_pub"][via]["e"]))
    token = secrets.token_bytes(32)
    blinded, r = cc.BlindSigner.blind(bpub, token)
    sig = cc.BlindSigner.unblind(bpub, int(s.issue_credential(eid, user, str(blinded), via)["blind_sig"]), r)
    ballot, bp, sp = make_ballot(int(pub["elgamal_pub"]["h"]), len(pub["options"]), chosen)
    return s.cast_vote(eid, token.hex(), str(sig), ballot, bp, sp, via)

# Funciones de main.py (sin FastAPI): se extraen del código real.
src_main = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")).read()
from collections import defaultdict, deque
ns = {"s": s, "re": re, "os": os, "time": time, "defaultdict": defaultdict, "deque": deque}
WANT_F = ("_limit_for", "_client_ip", "_prune_hits", "_hit", "_too_big")
WANT_A = ("_HITS", "_LIMITS", "_PATTERN_LIMITS", "_HITS_MAX_KEYS", "MAX_BODY_BYTES")
for node in ast.parse(src_main).body:
    if (isinstance(node, ast.FunctionDef) and node.name in WANT_F) or \
       (isinstance(node, (ast.Assign, ast.AnnAssign)) and any(getattr(t, "id", "") in WANT_A
                                                             for t in (node.targets if isinstance(node, ast.Assign) else [node.target]))):
        exec(compile(ast.Module([node], []), "main.py", "exec"), ns)

admin = reg("aadmin@sfera.org")
dueno = reg("adueno@sfera.org"); socio = reg("asocio@sfera.org"); ajeno = reg("aajeno@sfera.org")
gadmin = reg("agadmin@sfera.org"); gexp = reg("agexp@sfera.org"); pexp = reg("apexp@sfera.org")
u = [reg(f"aciu{i}@sfera.org") for i in range(4)]
rl.grant_role(admin, "agadmin@sfera.org", "admin", "global")
rl.grant_role(admin, "agexp@sfera.org", "expert", "global")
gadmin = s.get_user(gadmin["id"]); gexp = s.get_user(gexp["id"])

oid = s.create_org(dueno, "Cooperativa del barrio")["org_id"]
s.invite_member(dueno, oid, "asocio@sfera.org")
pdid = s.create_debate("Reforma del local social", "Cuerpo", "Vivienda", "Privado", dueno, org_id=oid)["debate_id"]

print("5) El ORGANIZADOR lleva su proceso privado de principio a fin")
check(s.get_debate(pdid, dueno)["can_admin"] is True, "el organizador es administración de su asunto privado")
doc = ds.create_document(pdid, dueno, "informe", "Presupuesto de la reforma", "text", "Tres presupuestos.")
docid = doc["document_id"]
expect_error(lambda: s.set_phase(pdid, "proponer", gadmin), 403, "admin GLOBAL por ámbito: NO administra lo privado")
expect_error(lambda: s.extend_phase(pdid, 3, "Motivo suficientemente largo", gadmin), 403, "admin global: no amplía plazos privados")
expect_error(lambda: s.extend_phase(pdid, 3, "Motivo suficientemente largo", socio), 403, "un socio (no organizador) no administra")
s.extend_phase(pdid, 3, "Pedimos más tiempo para leer los presupuestos", dueno)
check(len(s.get_debate(pdid, socio)["extensions"]) == 1, "el organizador amplía el plazo")
s.add_argument(pdid, socio["id"], "favor", "Hace falta ya")
s.set_phase(pdid, "proponer", dueno)
check(s.get_debate(pdid, socio)["phase"] == "proponer", "el organizador avanza de fase")
expect_error(lambda: s.add_expert_proposal(pdid, gexp, "Opción de experto global", "Texto"), 403,
             "experto con permiso GLOBAL: no publica en lo privado")
ds.assign_expert(pdid, "apexp@sfera.org", dueno)
check(s.get_debate(pdid, pexp)["can_author"] is True, "experto ASIGNADO por el organizador: ve el asunto privado y es autor")
ep1 = s.add_expert_proposal(pdid, pexp, "Reforma completa", "Cambiar suelo, luz y baños.")["id"]
ep2 = s.add_expert_proposal(pdid, dueno, "Solo lo urgente", "Arreglar los baños.")["id"]
check(ep1 and ep2, "experto asignado y organizador publican propuestas de expertos")
expect_error(lambda: s.add_proposal(pdid, pexp["id"], "Yo también propongo"), 403,
             "el experto asignado NO participa como socio (no está en el censo)")
s.set_phase(pdid, "votar", dueno)
eid_p = s.get_debate(pdid, socio)["election"]["id"]
rec_p = votar(eid_p, socio, 0)
expect_error(lambda: votar(eid_p, pexp, 0, viewer=pexp), 403, "el experto asignado no vota en un espacio privado")
res = s.close_election(eid_p, dueno)
check(res["open"]["recuento"][0] == 1 and s.get_debate(pdid, socio)["phase"] == "publicar",
      "el organizador cierra la votación: resultado publicado")

print("1) Contenido de versiones de documentos privados")
expect_error(lambda: ds.get_version_content(docid, 1), 403, "sin sesión: no se lee el contenido privado")
expect_error(lambda: ds.get_version_content(docid, 1, ajeno), 403, "persona ajena: no se lee")
check(ds.get_version_content(docid, 1, socio)["content_text"] == "Tres presupuestos.", "socio: sí lo lee")

print("2) Biblioteca, registro y expertos de un asunto privado")
for fn, lbl in ((lambda: ds.list_documents(pdid, ajeno), "list_documents"),
                (lambda: ds.get_document(docid, ajeno), "get_document"),
                (lambda: ds.get_ledger(pdid, ajeno), "get_ledger"),
                (lambda: ds.audit_ledger(pdid, ajeno), "audit_ledger"),
                (lambda: ds.list_experts(pdid, ajeno), "list_experts"),
                (lambda: xs.list_debate_profiles(pdid, None), "list_debate_profiles (sin sesión)"),
                (lambda: ds.list_expert_proposal_docs(ep1, ajeno), "list_expert_proposal_docs")):
    expect_error(fn, 403, f"{lbl}: ajeno no ve lo privado")
check(len(ds.list_documents(pdid, socio)) == 1 and ds.get_document(docid, socio)["id"] == docid
      and ds.audit_ledger(pdid, socio)["cadena_integra"] and len(ds.get_ledger(pdid, socio)) >= 1
      and isinstance(xs.list_debate_profiles(pdid, socio), list), "socio: ve biblioteca, registro y expertos")
# propuesta experta oculta por moderación (asunto público)
pub = s.create_debate("Sombra en la plaza", "Cuerpo", "Urbanismo", "Ayuntamiento", u[0])["debate_id"]
s.set_phase(pub, "proponer", admin)
epx = s.add_expert_proposal(pub, admin, "Toldos en la plaza", "Instalar toldos.")["id"]
mod.resolve(admin, "expert_proposal", epx, "hide")
expect_error(lambda: ds.list_expert_proposal_docs(epx, u[1]), 404, "propuesta experta oculta por moderación: 404")
check(ds.list_expert_proposal_docs(epx, admin)["proposal"]["id"] == epx, "el moderador sí la ve")
mod.resolve(admin, "expert_proposal", epx, "keep")

print("3) Votaciones privadas: datos, urna, auditoría y comprobantes")
for fn, lbl in ((lambda: s.election_public(eid_p, ajeno), "election_public"),
                (lambda: s.election_public(eid_p), "election_public sin sesión"),
                (lambda: s.get_board(eid_p, ajeno), "get_board"),
                (lambda: s.audit(eid_p, ajeno), "audit"),
                (lambda: s.check_receipt(eid_p, rec_p["code"], ajeno), "check_receipt")):
    expect_error(fn, 403, f"{lbl}: ajeno no ve la votación privada")
check(s.check_receipt(eid_p, rec_p["code"], socio)["found"] and s.audit(eid_p, socio)["cadena_integra"]
      and len(s.get_board(eid_p, socio)) > 1, "socio: comprueba su voto, la urna y la auditoría")

print("6) No se revela la existencia ni la fase de un asunto privado")
expect_error(lambda: s.support_debate(pdid, ajeno), 403, "support_debate: ajeno → 403 antes de mirar la fase")
expect_error(lambda: rl.my_role(ajeno, pdid), 403, "my_role: ajeno → 403")
check(rl.my_role(dueno, pdid)["can_admin"] is True, "my_role: el organizador administra")

print("4) Aportaciones a documentos: censo y ocultos")
pdid2 = s.create_debate("Horario del local", "", "Vivienda", "Privado", dueno, org_id=oid)["debate_id"]
doc2 = ds.create_document(pdid2, dueno, "informe", "Horarios actuales", "text", "De 9 a 21.")["document_id"]
expect_error(lambda: ds.add_contribution(doc2, ajeno, "comentario", "Opino"), 403, "ajeno no comenta un documento privado")
check(ds.add_contribution(doc2, socio, "comentario", "Bien")["ok"], "socio comenta")
mod.resolve(admin, "document", doc2, "hide")
expect_error(lambda: ds.add_contribution(doc2, socio, "comentario", "Otra"), 404, "documento oculto: no admite comentarios")
mod.resolve(admin, "document", doc2, "keep")

print("8) Asunto oculto por moderación: no admite escrituras")
hid = s.create_debate("Asunto que se ocultará", "", "Varios", "Ayuntamiento", u[0])["debate_id"]
s.set_phase(hid, "deliberar", admin)
dochid = ds.create_document(hid, admin, "informe", "Informe", "text", "x")["document_id"]
mod.resolve(admin, "debate", hid, "hide")
expect_error(lambda: s.add_argument(hid, u[1]["id"], "favor", "hola"), 404, "argumento en asunto oculto: no")
expect_error(lambda: cd.add_doc(hid, u[1], "dato", "Un dato", "texto"), 404, "documento ciudadano en asunto oculto: no")
expect_error(lambda: ds.add_contribution(dochid, u[1], "comentario", "x"), 404, "comentario en asunto oculto: no")
check(s.add_argument(hid, admin["id"], "favor", "Nota de moderación")["ok"], "moderadores: exentos")
hid2 = s.create_debate("Otro asunto oculto", "", "Varios", "Ayuntamiento", u[0])["debate_id"]
mod.resolve(admin, "debate", hid2, "hide")
expect_error(lambda: s.support_debate(hid2, u[1]), 404, "apoyo a un asunto oculto: no")

print("9) Cuentas SIN verificar: entran, pero no participan")
nover = reg("anover@sfera.org", verify=False)
check(s.login("anover@sfera.org", "clave-test-123")["token"], "una cuenta sin verificar puede entrar (para verificarse)")
pub2 = s.create_debate("Bancos en la parada", "", "Movilidad", "Ayuntamiento", u[0])["debate_id"]
arg_id = None
for fn, lbl in ((lambda: s.create_debate("X", "", "", "", nover), "create_debate"),
                (lambda: s.support_debate(pub2, nover), "support_debate"),
                (lambda: s.add_argument(pub2, nover["id"], "favor", "x"), "add_argument"),
                (lambda: s.add_proposal(pub2, nover["id"], "x"), "add_proposal"),
                (lambda: s.support_proposal(1, nover), "support_proposal"),
                (lambda: s.toggle_util("argument", 1, nover), "toggle_util"),
                (lambda: mod.report_content(nover, "debate", pub2, "spam"), "report_content"),
                (lambda: s.create_org(nover, "Org"), "create_org"),
                (lambda: s.invite_member(nover, oid, "x@y.org"), "invite_member")):
    expect_error(fn, 403, f"{lbl}: «Verifica tu email para participar»", "Verifica tu email para participar")

print("10) Admin (SFERA_ADMIN_EMAILS) solo tras verificar el email")
r = s.register("anuevo@sfera.org", "clave-test-123")
check(one("SELECT is_admin FROM users WHERE email='anuevo@sfera.org'")["is_admin"] == 0, "registro: aún NO es admin")
check(s.login("anuevo@sfera.org", "clave-test-123")["is_admin"] is False, "login sin verificar: no es admin")
s.verify("anuevo@sfera.org", r["codigo_piloto"])
check(one("SELECT is_admin FROM users WHERE email='anuevo@sfera.org'")["is_admin"] == 1, "tras verificar: admin")
check(s.login("anuevo@sfera.org", "clave-test-123")["is_admin"] is True, "login verificado: admin")

print("11) Código de verificación: máximo 5 intentos")
r = s.register("aintentos@sfera.org", "clave-test-123")
good = r["codigo_piloto"]; bad = "000000" if good != "000000" else "111111"
for i in range(4):
    expect_error(lambda: s.verify("aintentos@sfera.org", bad), 400, f"fallo {i + 1}", "Código incorrecto")
expect_error(lambda: s.verify("aintentos@sfera.org", bad), 400, "5º fallo: «Demasiados intentos»", "Demasiados intentos: pide un código nuevo")
expect_error(lambda: s.verify("aintentos@sfera.org", good), 400, "después, ni el código bueno vale (se anuló)")
r2 = s.resend_code("aintentos@sfera.org")
check(one("SELECT twofa_attempts FROM users WHERE email='aintentos@sfera.org'")["twofa_attempts"] == 0, "código nuevo: intentos a 0")
check(s.verify("aintentos@sfera.org", r2["codigo_piloto"])["verified"], "con el código nuevo, verifica")
f1 = s.forgot_password("adueno@sfera.org")["codigo_piloto"]
f2 = s.forgot_password("adueno@sfera.org")["codigo_piloto"]
if f1 != f2:
    expect_error(lambda: s.reset_password("adueno@sfera.org", f1, "nueva-clave-1"), 400, "contraseña: un código nuevo anula el anterior")
for i in range(5):
    try: s.reset_password("adueno@sfera.org", "999999" if f2 != "999999" else "888888", "nueva-clave-1")
    except s.SferaError: pass
expect_error(lambda: s.reset_password("adueno@sfera.org", f2, "nueva-clave-1"), 400, "contraseña: tras 5 fallos, ni el bueno vale", "Demasiados intentos")

print("12) Sesiones: versión de sesión, compatibles con las antiguas")
tok = s.login("aciu0@sfera.org", "clave-test-123")["token"]
check(s.parse_token(tok) == u[0]["id"], "sesión nueva válida")
exp = int(time.time()) + 3600
old_payload = f"{u[0]['id']}.{exp}"
old_tok = base64.urlsafe_b64encode(f"{old_payload}.{hmac.new(s._SECRET, old_payload.encode(), hashlib.sha256).hexdigest()}".encode()).decode()
check(s.parse_token(old_tok) == u[0]["id"], "sesión con el formato ANTERIOR: sigue valiendo (nadie sale con el despliegue)")
forged = base64.urlsafe_b64encode(f"{u[0]['id']}.{exp}.0.{'0' * 64}".encode()).decode()
check(s.parse_token(forged) is None, "sesión falsificada: no vale")
cp = s.change_password(u[0]["id"], "clave-test-123", "clave-test-456")
check(s.parse_token(tok) is None and s.parse_token(old_tok) is None, "cambiar contraseña cierra las sesiones anteriores (también las antiguas)")
check(s.parse_token(cp["token"]) == u[0]["id"], "change_password devuelve una sesión nueva válida")
tok2 = s.login("aciu0@sfera.org", "clave-test-456")["token"]
code = s.forgot_password("aciu0@sfera.org")["codigo_piloto"]
s.reset_password("aciu0@sfera.org", code, "clave-test-789")
check(s.parse_token(tok2) is None, "recuperar contraseña cierra las sesiones")
victim = reg("aborrar@sfera.org"); tok3 = s.login("aborrar@sfera.org", "clave-test-123")["token"]
s.delete_account(victim["id"], "clave-test-123")
check(s.parse_token(tok3) is None, "borrar la cuenta cierra sus sesiones")

print("13) SFERA_SECRET: aviso ruidoso en producción (sin caer)")
src_s = open(s.__file__).read(); src_c = open(cs.__file__).read()
check('not os.environ.get("SFERA_SECRET") and db.BACKEND == "postgres"' in src_s and "stderr" in src_s, "service.py avisa por stderr")
check('not os.environ.get("SFERA_SECRET") and db.BACKEND == "postgres"' in src_c and "stderr" in src_c, "cert_service.py avisa por stderr")

print("14) Límite de envíos por IP (main.py)")
class _Req:
    def __init__(self, headers, host="10.0.0.1"):
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.client = type("C", (), {"host": host})()
check(ns["_client_ip"](_Req({"x-nf-client-connection-ip": "1.2.3.4", "x-forwarded-for": "9.9.9.9, 8.8.8.8"})) == "1.2.3.4",
      "prefiere x-nf-client-connection-ip (Netlify)")
check(ns["_client_ip"](_Req({"x-forwarded-for": "9.9.9.9, 8.8.8.8"})) == "9.9.9.9", "si no, el primero de X-Forwarded-For")
check(ns["_client_ip"](_Req({})) == "10.0.0.1", "si no, la IP de la conexión")
lim, key = ns["_limit_for"]("/api/orgs/7/invite")
check(lim == (20, 3600) and key == "invite", "invitaciones: 20 por hora y por IP")
check(ns["_limit_for"]("/api/verify")[0] is not None, "verify: con límite por IP")
ok = [ns["_hit"]("5.5.5.5", "invite", lim, 1000.0) for _ in range(21)]
check(all(ok[:20]) and not ok[20], "la invitación nº 21 en una hora se rechaza")
ns["_HITS"][("6.6.6.6", "invite")] = deque([1.0])
ns["_prune_hits"](10 ** 6)
check(("6.6.6.6", "invite") not in ns["_HITS"], "los contadores caducados se borran (memoria acotada)")
ns["_HITS_MAX_KEYS"] = 3
for i in range(10):
    ns["_hit"](f"7.7.7.{i}", "invite", lim, 2 * 10 ** 6 + i)
check(len(ns["_HITS"]) <= 4, f"tope de claves del limitador ({len(ns['_HITS'])})")
check(ns["_too_big"](_Req({"content-length": str(17 * 1024 * 1024)})) and not ns["_too_big"](_Req({"content-length": "1000"})),
      "petición de más de 16 MB: 413")
check("demasiado grande (máximo 16 MB)" in src_main, "mensaje 413 en español")

print("15) Reenviar código: no revela si el email existe")
a = s.resend_code("no-existe-nadie@sfera.org"); b = s.resend_code("aadmin@sfera.org")
check(a == b == {"ok": True, "email_enviado": s._mail_configured()}, "misma respuesta exista o no (y esté o no verificada)")

print("16) Invitaciones: sin errores de integridad y caducan a los 30 días")
s.invite_member(dueno, oid, "asocio@sfera.org")
check(len(s.list_org_members(dueno, oid)) == 2, "invitar a quien ya es socio: sin error ni duplicado")
inv = s.invite_member(dueno, oid, "afuturo@sfera.org")["token_piloto"]
futuro = reg("afuturo@sfera.org")
check(s.accept_invite(futuro, inv)["org_id"] == oid, "aceptar una invitación")
inv2 = s.invite_member(dueno, oid, "afuturo2@sfera.org")["token_piloto"]
s.invite_member(dueno, oid, "afuturo@sfera.org")
expect_error(lambda: s.accept_invite(futuro, inv2), 403, "v61: una invitación personal no vale para otra cuenta", "otro email")
inv3 = s.invite_member(dueno, oid, "atarde@sfera.org")["token_piloto"]
sql("UPDATE org_invites SET created=? WHERE token=?", (db.now() - 31 * DAY, inv3))
expect_error(lambda: s.accept_invite(reg("atarde@sfera.org"), inv3), 410, "invitación de hace 31 días: caducada", "ha caducado")

print("17) Borrar la cuenta del organizador: el socio más antiguo pasa a organizar")
own = reg("aorg@sfera.org"); m1 = reg("amiem1@sfera.org"); m2 = reg("amiem2@sfera.org")
oid2 = s.create_org(own, "Club")["org_id"]
s.invite_member(own, oid2, "amiem1@sfera.org"); s.invite_member(own, oid2, "amiem2@sfera.org")
s.delete_account(own["id"], "clave-test-123")
check(one("SELECT owner_id FROM organizations WHERE id=?", (oid2,))["owner_id"] == m1["id"]
      and one("SELECT role FROM org_members WHERE org_id=? AND user_id=?", (oid2, m1["id"]))["role"] == "owner",
      "el miembro más antiguo es el nuevo organizador")
solo = reg("asolo@sfera.org"); oid3 = s.create_org(solo, "Solo yo")["org_id"]
s.delete_account(solo["id"], "clave-test-123")
check(one("SELECT owner_id FROM organizations WHERE id=?", (oid3,))["owner_id"] == solo["id"], "sin más miembros: la organización se deja igual")

print("18) Certificado: sesión obligatoria y cadena más estricta (modo piloto)")
check(re.search(r"def cert_challenge\(i: CertChallengeIn, u=Depends\(current_user\)\): return _wrap_cert\(cs\.start_challenge, u\[\"email\"\]\)", src_main)
      and 'cs.verify, u["email"]' in src_main, "challenge/verify exigen sesión y usan el email de la sesión")
check("email: Optional[str] = None" in src_main, "el email del cuerpo sigue admitido (opcional) pero se ignora")
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
NOW = datetime.datetime.now(datetime.timezone.utc)
def mk(name, issuer_name, issuer_key, ca, ku_sign=True, ku_certsign=False, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name),
                                                            x509.NameAttribute(NameOID.SERIAL_NUMBER, "IDCES-12345678Z")]))
         .issuer_name(issuer_name or x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name),
                                                x509.NameAttribute(NameOID.SERIAL_NUMBER, "IDCES-12345678Z")]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - datetime.timedelta(days=1)).not_valid_after(NOW + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=ku_sign, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=ku_certsign,
                                      crl_sign=ku_certsign, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    return b.sign(issuer_key or key, hashes.SHA256()), key
root, rk = mk("Raiz", None, None, True, False, True)
inter, ik = mk("Intermedia", root.subject, rk, True, False, True)
leaf, lk = mk("Persona", inter.subject, ik, False, True, False)
bad_inter, bik = mk("Intermedia", root.subject, rk, False, True, False, key=ik)   # misma clave, pero NO es CA
ca_leaf, _ = mk("Persona CA", inter.subject, ik, True, True, True)
nosign_leaf, _ = mk("Persona sin firma", inter.subject, ik, False, False, False)
tdir = tempfile.mkdtemp()
open(os.path.join(tdir, "raiz.pem"), "wb").write(root.public_bytes(serialization.Encoding.PEM))
open(os.path.join(tdir, "AC_RAIZ_FNMT-RCM_ServidoresSeguros.pem"), "wb").write(
    mk("TLS", None, None, True, False, True)[0].public_bytes(serialization.Encoding.PEM))
cs.TRUSTDIR, cs.MODE = tdir, "pilot"
check(len(cs._load_trust_roots()) == 1, "la raíz de servidores TLS (ServidoresSeguros) se ignora")
check(not os.path.exists(os.path.join(os.path.dirname(cs.__file__), "trust_store", "AC_RAIZ_FNMT-RCM_ServidoresSeguros.pem")),
      "y se ha quitado del trust_store del servidor")
try:
    cs._validate_certificate(leaf, [inter]); check(True, "cadena correcta (persona → intermedia CA → raíz): válida")
except cs.CertError as e:
    check(False, f"cadena correcta rechazada: {e.msg}")
expect_error(lambda: cs._validate_certificate(leaf, [bad_inter]), 403, "intermedio que NO es CA: rechazado", "autoridad de certificación")
expect_error(lambda: cs._validate_certificate(ca_leaf, [inter]), 403, "certificado de persona que es CA: rechazado")
expect_error(lambda: cs._validate_certificate(nosign_leaf, [inter]), 403, "certificado sin uso de firma: rechazado", "no sirve para firmar")
other, ok_ = mk("Otra persona", inter.subject, ik, False, True, False)
nonce = b"reto-123"
cms = (pkcs7.PKCS7SignatureBuilder().set_data(nonce).add_signer(leaf, lk, hashes.SHA256())
       .add_certificate(other).add_certificate(inter)
       .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature]))
signer, certs = cs._verify_cms_detached(cms, nonce)
check(signer.serial_number == leaf.serial_number and len(certs) >= 2,
      "CMS con varias hojas: se elige el firmante por emisor + número de serie del SignerInfo")
cs.MODE = "sim"

print("19) Cuenta demo de las tiendas: sin contraseña en el código")
check(s.ensure_demo_account()["demo"] is False and not one("SELECT id FROM users WHERE email='demo@sferacivitas.org'"),
      "sin SFERA_DEMO_PASSWORD: no se crea nada")
sql("INSERT INTO users(email,pass_hash,verified,loa,is_admin,created) VALUES('demo@sferacivitas.org',?,1,'open',0,?)",
    (s._hash_pw("ClaveQueUsaApple-1"), db.now()))
before = one("SELECT pass_hash FROM users WHERE email='demo@sferacivitas.org'")["pass_hash"]
s.ensure_demo_account()
check(one("SELECT pass_hash FROM users WHERE email='demo@sferacivitas.org'")["pass_hash"] == before
      and s.login("demo@sferacivitas.org", "ClaveQueUsaApple-1")["token"], "cuenta demo existente: intacta (Apple sigue entrando)")
check("SferaDemo-2026" not in src_s, "la contraseña antigua ya no está en el código")

print("20-23) Voto: una papeleta por persona, entradas mal formadas, secreto y comprobantes")
vd = s.create_debate("Iluminación del parque", "", "Urbanismo", "Ayuntamiento", u[1])["debate_id"]
s.set_phase(vd, "proponer", admin)
s.add_expert_proposal(vd, admin, "Farolas LED", "Cambiar a LED.")
s.set_phase(vd, "votar", admin)
eid = s.get_debate(vd)["election"]["id"]
rec = votar(eid, u[1], 0, "open")
expect_error(lambda: votar(eid, u[1], 0, "open"), 409, "20) segunda papeleta misma vía: no", "Ya has pedido tu papeleta para esta votación")
s.verify_certificate("aciu1@sfera.org", "CERT:aciu1")
u1v = s.get_user(u[1]["id"])
expect_error(lambda: votar(eid, u1v, 0, "verified"), 409, "20) tras verificarse con certificado, tampoco por la otra vía",
             "Ya has pedido tu papeleta")
s.verify_certificate("aciu2@sfera.org", "CERT:aciu2")
u2v = s.get_user(u[2]["id"])
expect_error(lambda: votar(eid, u2v, 0, "open"), 403, "20) cuenta con certificado: debe votar en la vía verificada", "certificado")
check(votar(eid, u2v, 1, "verified")["via"] == "verified", "20) y en la vía verificada vota")
for blinded, lbl in (("no-es-un-numero", "texto"), ("1", "b=1"), ("0", "b=0"),
                     (s.election_public(eid)["blind_pub"]["open"]["n"], "b=n")):
    expect_error(lambda: s.issue_credential(eid, u[3], blinded, "open"), 400, f"21) papeleta pedida con {lbl}: 400",
                 "Tu voto no se ha podido leer. Vuelve a intentarlo.")
n_opts = len(s.election_public(eid)["options"])
good_ballot, good_bp, good_sp = make_ballot(int(s.election_public(eid)["elgamal_pub"]["h"]), n_opts, 0)
for args, lbl in (((("zz", "123", good_ballot, good_bp, good_sp)), "token no hexadecimal"),
                  (((secrets.token_hex(32), "abc", good_ballot, good_bp, good_sp)), "firma no numérica"),
                  (((secrets.token_hex(32), "123", [{"c1": "1"}] * n_opts, good_bp, good_sp)), "papeleta sin c2"),
                  (((secrets.token_hex(32), "123", good_ballot, [{"a1": [1]}] * n_opts, good_sp)), "pruebas incompletas"),
                  (((secrets.token_hex(32), "123", good_ballot, good_bp, {"a1": "x"})), "prueba de suma rota")):
    expect_error(lambda: s.cast_vote(eid, *args, "open"), 400, f"21) voto con {lbl}: 400 (no 500)")
ci = one("SELECT issued_at FROM credential_issued WHERE election_id=? AND user_id=?", (eid, u[1]["id"]))
check(ci["issued_at"] % 86400 == 0, "22) la emisión de la papeleta se guarda solo con el DÍA")
check(one("SELECT COUNT(*) AS n FROM bulletin_board WHERE election_id=? AND kind='ballot' AND created IS NOT NULL", (eid,))["n"] == 0,
      "22) las papeletas de la urna no llevan hora")
check(s.audit(eid)["cadena_integra"] and s.audit(eid)["papeletas_zk_validas"], "22) la auditoría sigue funcionando")
check(rec["receipt"].startswith(f"REC-") and s.check_receipt(eid, rec["receipt"])["found"],
      f"23) el recibo largo ({rec['receipt']}) se encuentra en la urna")
check(s.check_receipt(eid, rec["receipt"].lower())["found"], "23) también en minúsculas")
check(s.check_receipt(eid, rec["receipt"][:-4] + "0099")["found"] is False, "23) un recibo largo que no existe: no encontrado")
check(s.check_receipt(eid, rec["code"])["found"], "23) el comprobante corto sigue valiendo")

print("28) Auditorías en caché mientras no cambie la urna / el registro")
s._AUDIT_CACHE.clear()
a1 = s.audit(eid); n_cache = len(s._AUDIT_CACHE); a2 = s.audit(eid)
check(n_cache == 1 and a1 == a2, "segunda auditoría: desde la caché")
votar(eid, u[3], 0, "open")
a3 = s.audit(eid)
check(a3["votos"] == a1["votos"] + 1 and len(s._AUDIT_CACHE) == 2, "un voto nuevo invalida la caché (se recalcula)")
l1 = ds.audit_ledger(hid, admin); l2 = ds.audit_ledger(hid, admin)
check(l1 == l2 and any(k[0] == "ledger" for k in s._AUDIT_CACHE), "auditoría de la biblioteca también en caché")

print("24) Fases: un plazo vencido hace mucho no encadena fases en la misma petición")
fd = s.create_debate("Papeleras en el paseo", "", "Limpieza", "Ayuntamiento", u[3])["debate_id"]
s.set_phase(fd, "proponer", admin)
s.add_expert_proposal(fd, admin, "Más papeleras", "Una cada 50 m.")
sql("UPDATE debates SET phase_deadline=? WHERE id=?", (db.now() - 40 * DAY, fd))
d = s.get_debate(fd)
check(d["phase"] == "votar" and d["election"]["status"] == "abierta" and d["phase_deadline"] > db.now() + (s.VOTACION_DIAS - 1) * DAY,
      "proponer vencido hace 40 días → votación ABIERTA con su plazo completo")

print("25) Apoyos fuera de plazo")
cv = s.create_debate("Fuente en la plaza", "", "Urbanismo", "Ayuntamiento", u[3])["debate_id"]
sql("UPDATE debates SET conv_deadline=? WHERE id=?", (db.now() - 3600, cv))
expect_error(lambda: s.support_debate(cv, u[0]), 409, "apoyo tras el fin del plazo: rechazado",
             "Este asunto no reunió los apoyos a tiempo: ya no se puede apoyar")
cv2 = s.create_debate("Banco en la plaza", "", "Urbanismo", "Ayuntamiento", admin, quorum_override=2)["debate_id"]
dl = db.now() - 3600
sql("UPDATE debates SET conv_deadline=? WHERE id=?", (dl, cv2))
sql("UPDATE supports SET created=? WHERE debate_id=?", (dl - 600, cv2))     # el de quien convoca: dentro de plazo
sql("INSERT INTO supports(debate_id,user_id,via,created) VALUES(?,?,'abierto',?)", (cv2, u[0]["id"], dl + 60))
d = s.get_debate(cv2)
check(d["phase"] == "convocar" and d["conv_status"] == "caducado" and d["apoyos_abierto"] == 1,  # solo el de quien convoca
      "un apoyo colado DESPUÉS del plazo no cuenta para el quórum")

print("26) Retirar un perfil de experto le quita el permiso de publicar")
ed = s.create_debate("Arbolado", "", "Medio ambiente", "Ayuntamiento", u[3])["debate_id"]
expu = reg("aexpu@sfera.org")
prof = xs.create_profile(admin, "Ana Experta", "Botánica", email="aexpu@sfera.org", debate_id=ed)["profile"]["id"]
check(s.get_debate(ed, expu)["can_author"] is True, "perfil asignado (con cuenta): puede publicar")
xs.unassign_profile(admin, ed, prof)
check(s.get_debate(ed, expu)["can_author"] is False, "retirado: ya no puede publicar en ese asunto")

print("27) Cambiar a exprés sin indicar quórum conserva el quórum rebajado")
qd = s.create_debate("Pasos de cebra", "", "Movilidad", "Ayuntamiento", admin, quorum_override=40)["debate_id"]
r = s.set_plan(qd, "express", admin)
check(r["plan"] == "express" and r["quorum_override"] == 40, "quórum 40 conservado al pasar a exprés")
r = s.set_plan(qd, "estandar", admin, 0)
check(r["quorum_override"] is None, "con 0, se quita")

print("29) Archivos: bomba zip, y validación DESPUÉS de los permisos")
def zipdoc(entries, ext="docx"):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
        for n, c in entries.items():
            z.writestr(n, c)
    return bio.getvalue()
many = {"[Content_Types].xml": "<x/>", "word/document.xml": "<x/>"}
many.update({f"word/m{i}.xml": "" for i in range(2001)})
expect_error(lambda: uploads.validate("muchos.docx", b64(zipdoc(many))), 413, "más de 2000 ficheros dentro: rechazado", "demasiado complejo")
bio = io.BytesIO()
with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("[Content_Types].xml", "<x/>")
    with z.open("word/document.xml", "w") as w:
        chunk = b"\0" * (1024 * 1024)
        for _ in range(201):
            w.write(chunk)
bomb = bio.getvalue()
check(len(bomb) < uploads.MAX_FILE_BYTES, f"(la bomba ocupa {len(bomb) // 1024} KB comprimida)")
expect_error(lambda: uploads.validate("bomba.docx", b64(bomb)), 413, "más de 200 MB descomprimido: rechazado", "demasiado complejo")
big_mt = zipdoc({"mimetype": uploads.ALLOWED["odt"][0] + " " * 200, "content.xml": "<x/>"})
expect_error(lambda: uploads.validate("raro.odt", b64(big_mt)), 415, "«mimetype» de más de 100 bytes: rechazado")
ok_odt = zipdoc({"mimetype": uploads.ALLOWED["odt"][0], "content.xml": "<x/>"})
check(uploads.validate("bien.odt", b64(ok_odt))["label"] == "Documento", "un OpenDocument normal sigue valiendo")
garbage = b64(b"no es un pdf")
expect_error(lambda: cd.add_doc(pdid2, ajeno, "estudio", "Archivo", "", "", file_name="x.pdf", data_b64=garbage), 403,
             "archivo inválido de alguien de fuera del censo: 403 (no se procesa el archivo)")
expect_error(lambda: ds.create_document(pub2, u[0], "informe", "Informe", "file", None, "x.pdf", "application/pdf", garbage), 403,
             "documento de experto inválido de quien no es experto: 403")
expect_error(lambda: s.add_expert_proposal(pub2, u[0], "T", "x", formal_file_name="x.pdf", formal_data_b64=garbage), 403,
             "propuesta de expertos con archivo inválido de quien no es experto: 403")
expect_error(lambda: ds.add_version(docid, ajeno, "file", None, "x.pdf", "application/pdf", garbage), 403,
             "nueva versión con archivo inválido de quien no es experto: 403")

print("30) Webhook de Polar (Standard Webhooks)")
s.BILLING_PROVIDER, s.POLAR_WEBHOOK_SECRET = "polar", ""
body = json.dumps({"type": "order.paid", "data": {"id": "ord_1", "metadata": {"org_id": str(oid)}}}).encode()
def hdrs(secret_key: bytes, wid="msg_1", ts=None, body=body):
    ts = str(int(time.time()) if ts is None else ts)
    sig = base64.b64encode(hmac.new(secret_key, f"{wid}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
    return {"webhook-id": wid, "webhook-timestamp": ts, "webhook-signature": "v1," + sig}
expect_error(lambda: s.handle_webhook("polar", hdrs(b"x"), body), 401, "sin secreto configurado: 401 (antes se aceptaba)")
s.POLAR_WEBHOOK_SECRET = "polar_whs_abc123"
expect_error(lambda: s.handle_webhook("polar", hdrs(b"otra"), body), 401, "firma inválida: 401")
expect_error(lambda: s.handle_webhook("polar", hdrs(b"polar_whs_abc123", ts=int(time.time()) - 3600), body), 401,
             "sello de tiempo de hace 1 hora: 401")
r = s.handle_webhook("polar", hdrs(b"polar_whs_abc123"), body)
check(r.get("credited_units") and r.get("org_id") == oid, "firma correcta (secreto de Polar): pago acreditado")
raw_key = secrets.token_bytes(24)
s.POLAR_WEBHOOK_SECRET = "whsec_" + base64.b64encode(raw_key).decode()
body2 = json.dumps({"type": "order.paid", "data": {"id": "ord_2", "metadata": {}}}).encode()
check(s.handle_webhook("polar", hdrs(raw_key, body=body2), body2)["ok"], "secreto «whsec_…» (base64): también vale")
expect_error(lambda: s.handle_webhook("lemonsqueezy", {}, body), 400, "otro proveedor distinto del configurado: rechazado")
expect_error(lambda: s.handle_webhook("paddle", {}, body), 400, "paddle sin estar configurado: rechazado")

print("31) Casos de demostración: un fallo a medias no deja un caso roto marcado como hecho")
orig = demo_seed._insert_cdoc
def boom(*a, **k): raise RuntimeError("fallo simulado")
demo_seed._insert_cdoc = boom
r = demo_seed.seed(admin, max_new=1)
demo_seed._insert_cdoc = orig
first_key = f"demo-{demo_seed.DEMO_VERSION}-{demo_seed.CASES[0]['key']}"
check(r["items"][0]["status"] == "error" and not one("SELECT id FROM debates WHERE demo_key=?", (first_key,)),
      "tras el fallo, el caso NO queda marcado como existente")
check(one("SELECT COUNT(*) AS n FROM debates WHERE is_demo=1 AND COALESCE(hidden,0)=0")["n"] == 0, "el asunto parcial queda oculto")
r = demo_seed.seed(admin, max_new=1)
check(r["items"][0]["status"] == "creado" and one("SELECT hidden FROM debates WHERE demo_key=?", (first_key,))["hidden"] == 0,
      "la siguiente ejecución lo crea entero y visible")

print("32) reset_expires con precisión doble en Postgres")
check(("users", "reset_expires", "{REAL}") in db._NEW_COLUMNS, "columna declarada con {REAL} (DOUBLE PRECISION en Postgres)")
check("ALTER TABLE users ALTER COLUMN reset_expires TYPE DOUBLE PRECISION" in open(db.__file__).read(), "migración idempotente en Postgres")
check(("users", "token_ver", "INTEGER DEFAULT 0") in db._NEW_COLUMNS and ("users", "twofa_attempts", "INTEGER DEFAULT 0") in db._NEW_COLUMNS,
      "columnas nuevas token_ver y twofa_attempts")

print("33) Soporte: si la respuesta automática no sale, se escala")
orig_send = s._send_email
sent = []
def fake_send(to, subject, body):
    sent.append((to, subject)); return not subject.startswith("Re:")
s._send_email = fake_send
summary = {}
sup._handle_message("msg-faq-1", "vecina@correo.org", "No me llega el código de verificación", "Hola", summary)
s._send_email = orig_send
t = one("SELECT status FROM support_tickets WHERE msg_uid='msg-faq-1'")
check(t["status"] == "escalado" and summary.get("escalados") == 1 and any(x[1].startswith("[SOPORTE]") for x in sent),
      "FAQ encontrada pero el correo falló: ticket escalado (no se pierde)")

print("7) Denuncias: verificado, visibilidad y sin auto-ocultar lo de expertos")
arg_p = one("SELECT id FROM arguments WHERE debate_id=?", (pdid,))["id"]
expect_error(lambda: mod.report_content(ajeno, "argument", arg_p, "spam"), 403, "denunciar algo de un espacio privado ajeno: no")
check(mod.report_content(dueno, "argument", arg_p, "spam")["ok"], "un miembro sí puede denunciar")
ep_pub = s.add_expert_proposal(pub, admin, "Árboles en la plaza", "Plantar árboles.")["id"]
for i in range(3):
    mod.report_content([u[0], u[1], u[3]][i], "expert_proposal", ep_pub, "spam")
with db.session() as conn:
    check(ep_pub not in mod.hidden_ids(conn, "expert_proposal"), "propuesta de expertos con 3 denuncias: NO se oculta sola")
docp = ds.create_document(pub, admin, "informe", "Informe plaza", "text", "x")["document_id"]
for x in (u[0], u[1], u[3]):
    mod.report_content(x, "document", docp, "spam")
with db.session() as conn:
    check(docp not in mod.hidden_ids(conn, "document"), "documento de expertos con 3 denuncias: NO se oculta solo")
dd = s.create_debate("Para denunciar", "", "Varios", "Ayuntamiento", u[0])["debate_id"]
s.set_phase(dd, "deliberar", admin)
aid = s.add_argument(dd, u[0]["id"], "favor", "Contenido feo")["id"]
for x in (u[1], u[3], dueno):
    mod.report_content(x, "argument", aid, "ofensivo")
with db.session() as conn:
    check(aid in mod.hidden_ids(conn, "argument"), "un argumento normal sí se oculta solo al llegar al umbral")

print(f"\nRESULTADO auditoría v59: {PASSED} OK · {FAILED} fallos")
raise SystemExit(1 if FAILED else 0)
