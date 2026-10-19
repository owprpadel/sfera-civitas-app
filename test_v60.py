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
