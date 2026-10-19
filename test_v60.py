# Pruebas v60: clasificación automática, avisos a hola@ y casos ilustrativos que no caducan.
import os
os.environ.setdefault("SFERA_CERT_SIM_ALLOWED", "1")
os.environ["SFERA_DB"] = "/tmp/sfera_test_v60.db"
os.environ.setdefault("SFERA_ADMIN_EMAILS", "vadmin@sfera.org")
if os.path.exists("/tmp/sfera_test_v60.db"):
    os.remove("/tmp/sfera_test_v60.db")
import db; db.init_db()
import service as s, demo_seed, roles as rl

OK = FAIL = 0
def check(c, l):
    global OK, FAIL
    if c: OK += 1; print("  ok  ·", l)
    else: FAIL += 1; print("  FALLO ·", l)

SENT = []
s._send_email = lambda to, subj, body: (SENT.append((to, subj, body)) or True)
s._send_email_async = lambda to, subj, body: SENT.append((to, subj, body))

def reg(email):
    r = s.register(email, "clave-test-123"); s.verify(email, r.get("codigo_piloto"))
    return s.get_user(s.login(email, "clave-test-123")["user_id"])

admin = reg("vadmin@sfera.org")
u = reg("vecina@sfera.org")

print("1) Clasificación automática al convocar")
r = s.create_debate("Democracia directa digital", "", "Política ", "Centeal", u, nivel="estado", territorio="España")
d = s.get_debate(r["debate_id"], None)
check(d["administracion"] == "Administración General del Estado", f"«Centeal» → {d['administracion']}")
check(d["materia"] == "Participación y buen gobierno", f"materia normalizada: {d['materia']}")
check("Centeal" in r["clasificacion"]["corregido"], "la respuesta explica lo corregido")
r = s.create_debate("Perros sueltos por las poblaciones", "", "Ayuntamientos", "Ayuntamiento ", u, nivel="municipio", territorio="madrid")
d = s.get_debate(r["debate_id"], None)
check(d["materia"] in ("Seguridad y convivencia", "Bienestar animal") and d["territorio"] == "Madrid" and d["administracion"] == "Ayuntamiento",
      f"administración escrita como materia → deducida del texto ({d['materia']}, {d['territorio']})")
r = s.create_debate("Fuentes de agua en los parques", "Faltan fuentes", "", "", u)
d = s.get_debate(r["debate_id"], None)
check(d["materia"] == "Medio ambiente" and d["nivel"] == "municipio" and d["administracion"] == "Ayuntamiento",
      "campos vacíos → materia deducida, nivel municipio, Ayuntamiento")
r = s.create_debate("Bus nocturno", "", "movilidad", "junta de andalucia", u, territorio="andalucia")
d = s.get_debate(r["debate_id"], None)
check(d["nivel"] == "ccaa" and d["territorio"] == "Andalucía" and d["materia"] == "Movilidad y transporte",
      "nivel y territorio deducidos de la administración escrita")

print("2) Aviso a hola@ de cada asunto nuevo")
check(any(t == "hola@sferacivitas.org" and "Nuevo asunto" in subj for t, subj, b in SENT), "hola@ recibe «Nuevo asunto»")
check(any("Clasificación corregida" in b for t, subj, b in SENT if t == "hola@sferacivitas.org"), "el aviso incluye lo corregido")

print("3) Al reunir apoyos: aviso para asignar expertos (admins + hola@)")
SENT.clear()
r = s.create_debate("Sombra en las paradas", "", "Movilidad", "Ayuntamiento", u, territorio="Murcia")
did = r["debate_id"]
with db.session() as conn:
    users = [reg(f"apoyo{i}@sfera.org") for i in range(3)]
    conn.execute("UPDATE debates SET quorum_override=2 WHERE id=?", (did,)); conn.commit()
for x in users[:1]:
    s.support_debate(did, x)
d = s.get_debate(did, None)
check(d["phase"] == "deliberar", f"pasa a Deliberar ({d['phase']})")
subj_ok = [t for t, subj, b in SENT if "Asigna expertos" in subj]
check("vadmin@sfera.org" in subj_ok and "hola@sferacivitas.org" in subj_ok, f"«Asigna expertos» a admin y a hola@ ({subj_ok})")

print("4) Permisos por ámbito tolerantes con la normalización")
adm2 = reg("dipu@sfera.org")
rl.grant_role(admin, "dipu@sfera.org", "admin", "aapp", "Diputación")
r = s.create_debate("Caminos rurales", "", "Medio rural", "Diputacion", u, territorio="Teruel")
with db.session() as conn:
    row = conn.execute("SELECT * FROM debates WHERE id=?", (r["debate_id"],)).fetchone()
    check(rl.can_admin(conn, adm2, row), "grant «Diputación» administra «Diputación provincial»")
    otro = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
    check(not rl.can_admin(conn, adm2, otro), "y no administra un asunto de Ayuntamiento")

print("5) Casos ilustrativos: 3+ por fase y no caducan")
res = demo_seed.seed(admin)
check(not any(x["status"] == "error" for x in res["items"]), "siembra sin errores")
for p in res["pending_close"]:
    s.close_election(p["election_id"], admin)
ds = [x for x in s.list_debates(None) if x.get("is_demo")]
cnt = {ph: sum(1 for x in ds if x["phase"] == ph) for ph in ("convocar", "deliberar", "proponer", "votar", "publicar")}
check(all(v >= 3 for k, v in cnt.items() if k != "publicar") and cnt["publicar"] + cnt["votar"] >= 6,
      f"al menos 3 por fase (en producción el antiguo caso Votar ya está en Publicar): {cnt}")
with db.session() as conn:
    past = db.now() - 86400
    conn.execute("UPDATE debates SET phase_deadline=?, cierre=? WHERE is_demo=1 AND phase IN ('deliberar','proponer','votar')", (past, past))
    conn.execute("UPDATE debates SET conv_deadline=? WHERE is_demo=1 AND phase='convocar'", (past,))
    conn.commit()
ds2 = [x for x in s.list_debates(None) if x.get("is_demo")]
cnt2 = {ph: sum(1 for x in ds2 if x["phase"] == ph) for ph in cnt}
check(cnt2 == cnt, f"con los plazos vencidos siguen en su fase: {cnt2}")
check(all(x.get("conv_status") != "caducado" for x in ds2), "ningún caso ilustrativo caduca")
check(all((x.get("phase_dias_restantes") or x.get("conv_dias_restantes") or 0) >= 9 for x in ds2 if x["phase"] != "publicar"),
      "el plazo se renueva (≥ 9 días)")
with db.session() as conn:
    n = conn.execute("SELECT COUNT(*) AS n FROM debates WHERE is_demo=1 AND materia NOT IN (%s)" %
                     ",".join("?" * len(__import__("clasificacion").MATERIAS)), tuple(__import__("clasificacion").MATERIAS)).fetchone()
    check(dict(n)["n"] == 0, "los casos ilustrativos usan las materias normalizadas")

print(f"RESULTADO v60: {OK} OK · {FAIL} fallos")

print("6) v61: invitaciones a espacios privados")
import service as s2
o = s2.create_org(admin, "Comunidad Calle Mayor 3") if hasattr(s2, "create_org") else s2.create_organization(admin, "Comunidad Calle Mayor 3")
oid = o["org_id"]
for bad in ["imposible", "a@b", "asdf@asdf", "x y@gmail.com", "hola@@gmail.com", "pepe@gmail.c"]:
    try:
        s2.invite_member(admin, oid, bad); check(False, f"rechaza email imposible: {bad}")
    except s2.SferaError as e:
        check(e.status == 400 if hasattr(e, "status") else True, f"rechaza email imposible: {bad}")
r = s2.invite_member(admin, oid, "nueva.vecina@gmail.com")
check(r["status"] == "invited" and r.get("email") == "nueva.vecina@gmail.com", "email válido → invitación enviada a ese email")
with db.session() as conn:
    tok = dict(conn.execute("SELECT token FROM org_invites WHERE email=?", ("nueva.vecina@gmail.com",)).fetchone())["token"]
otro = reg("otro.vecino@sfera.org")
try:
    s2.accept_invite(otro, tok); check(False, "la invitación no vale para otra cuenta")
except s2.SferaError:
    check(True, "la invitación no vale para otra cuenta")
buena = reg("nueva.vecina@gmail.com")
check(s2.accept_invite(buena, tok)["ok"], "la cuenta con el email invitado sí entra")
print(f"RESULTADO v61 invitaciones: {OK} OK · {FAIL} fallos (acumulado)")

print("7) v61: código del espacio (el organizador elige)")
jc = s2.set_join_code(admin, oid, True, approval=True)
check(jc["on"] and len(jc["code"]) == 9 and "#unirse=" in jc["link"], f"código generado: {jc['code']}")
v1 = reg("vecino1@sfera.org")
r = s2.join_with_code(v1, jc["code"].lower().replace("-", ""))
check(r["status"] == "pending", "con aprobación: queda pendiente (acepta minúsculas y sin guion)")
with db.session() as conn:
    check(not s2._is_org_member(conn, oid, v1["id"]), "pendiente aún NO es miembro (no ve asuntos)")
check(any(m["status"] == "pending" for m in s2.list_org_members(admin, oid)), "el organizador ve la solicitud")
s2.decide_member(admin, oid, v1["id"], True)
with db.session() as conn:
    check(s2._is_org_member(conn, oid, v1["id"]), "aprobado → miembro activo")
s2.set_join_code(admin, oid, True, approval=False)
v2 = reg("vecino2@sfera.org")
check(s2.join_with_code(v2, jc["code"])["status"] == "active", "sin aprobación: entra directamente")
old = jc["code"]; jc2 = s2.set_join_code(admin, oid, True, approval=False, regenerate=True)
v3 = reg("vecino3@sfera.org")
try:
    s2.join_with_code(v3, old); check(False, "el código antiguo deja de valer al cambiarlo")
except s2.SferaError:
    check(True, "el código antiguo deja de valer al cambiarlo")
jc3 = s2.set_join_code(admin, oid, True, approval=False, custom="Mayor3-2026")
check(jc3["code"] == "MAYOR3-2026", "código personalizado")
for bad in ["corto", "AAAAAAAAAA"]:
    try: s2.set_join_code(admin, oid, True, custom=bad); check(False, f"rechaza código malo {bad}")
    except s2.SferaError: check(True, f"rechaza código malo {bad}")
s2.set_join_code(admin, oid, False)
try:
    s2.join_with_code(reg("vecino4@sfera.org"), "MAYOR3-2026"); check(False, "código desactivado no vale")
except s2.SferaError:
    check(True, "código desactivado no vale")
try:
    s2.set_join_code(v2, oid, True); check(False, "solo el organizador gestiona el código")
except s2.SferaError:
    check(True, "solo el organizador gestiona el código")
# el mismo campo acepta la invitación personal
r = s2.invite_member(admin, oid, "persona.nueva@gmail.com")
with db.session() as conn:
    tok = dict(conn.execute("SELECT token FROM org_invites WHERE email=?", ("persona.nueva@gmail.com",)).fetchone())["token"]
check(s2.join_with_code(reg("persona.nueva@gmail.com"), tok)["ok"], "el mismo campo acepta la invitación personal")
print(f"RESULTADO v61 código del espacio: {OK} OK · {FAIL} fallos (acumulado)")
