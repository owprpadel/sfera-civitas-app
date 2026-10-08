"""Prueba SIN dependencias (stdlib) de las novedades de oct-2026:
  1) Aportaciones documentales ciudadanas en TODAS las fases activas + validación + moderación.
  2) Perfiles de experto con nombre: atribución, permisos estrictos, sin emails en público.
  3) Proceso EXPRÉS: duraciones propias por asunto, avance perezoso, quórum rebajado, cambio de modalidad.
  4) Casos de demostración: marcador oculto, idempotencia, ocultar/mostrar (también ejemplos antiguos).
  5) «Ya lo apoyas»: supported_by_me en la ficha y en la lista; apoyos a un asunto caducado.
  6) Email sin distinción de mayúsculas al entrar.
Ejecuta: python3 test_docs_expertos.py"""
import json
import os

os.environ["SFERA_DB"] = "/tmp/sfera_test_docs_expertos.db"
os.environ.setdefault("SFERA_ADMIN_EMAILS", "dadmin@sfera.org")
if os.path.exists("/tmp/sfera_test_docs_expertos.db"):
    os.remove("/tmp/sfera_test_docs_expertos.db")
import db; db.init_db()
import service as s, roles as rl, docs_service as ds, moderation as mod
import citizen_docs as cd, experts_service as xs, demo_seed

PASSED, FAILED = 0, 0
DAY = 86400


def check(cond, label):
    global PASSED, FAILED
    if cond:
        PASSED += 1; print("  ok  ·", label)
    else:
        FAILED += 1; print("  FALLO ·", label)


def expect_error(fn, status, label, contains=None):
    try:
        fn()
    except s.SferaError as e:
        ok = e.status == status and (contains is None or contains in e.msg)
        check(ok, f"{label} (HTTP {e.status}: {e.msg})")
        return
    check(False, label + " (no lanzó error)")


def reg(email, verify=True):
    r = s.register(email, "clave-test-123")
    if verify:
        s.verify(email, r.get("codigo_piloto"))
    return s.get_user(s.login(email, "clave-test-123")["user_id"])


def sql(q, params=()):
    with db.session() as conn:
        conn.execute(q, params); conn.commit()


def one(q, params=()):
    with db.session() as conn:
        r = conn.execute(q, params).fetchone()
    return dict(r) if r else None


def past(did, days_ago=1):
    sql("UPDATE debates SET phase_deadline=? WHERE id=?", (db.now() - days_ago * DAY, did))


admin = reg("dadmin@sfera.org")
autor = reg("dautor@sfera.org")
u = [reg(f"du{i}@sfera.org") for i in range(5)]
sinverificar = reg("dnover@sfera.org", verify=False)
experto = reg("dexperto@sfera.org")
admin_aapp = reg("daapp@sfera.org")
rl.grant_role(admin, "daapp@sfera.org", "admin", "aapp", "Diputación")

# ─────────────────────────────────────────────────────────────────────────────
print("1) Aportaciones documentales ciudadanas en cada fase activa")
did = s.create_debate("Iluminación de los caminos escolares", "Cuerpo", "Seguridad", "Ayuntamiento", autor)["debate_id"]
for ph in ("convocar", "deliberar", "proponer"):
    if ph != "convocar":
        s.set_phase(did, ph, admin)
    r = cd.add_doc(did, u[0], "dato", f"Dato en {ph}", "Un dato relevante", "")
    check(r["ok"] and r["phase"] == ph, f"{ph}: aportación documental aceptada (fase registrada)")
s.add_expert_proposal(did, admin, "Farolas LED en los caminos", "Texto de la propuesta.")
s.set_phase(did, "votar", admin)
# v55: en Votar la biblioteca es de solo lectura (todo sigue visible)
expect_error(lambda: cd.add_doc(did, u[1], "enlace", "Fuente oficial", "", "https://datos.gob.es/catalogo"), 409,
             "votar: la biblioteca ya no admite documentos nuevos", "votación ya ha empezado")
lst = cd.list_docs(did)
check(lst["total"] == 3 and lst["items"][0]["title"] == "Dato en proponer", "lista pública: 3 aportaciones, la más reciente primero")
check(all("email" not in json.dumps(i) for i in lst["items"]), "la lista no expone emails")
e = s._latest_election(db.connect(), did)
s.close_election(e["id"], admin)
expect_error(lambda: cd.add_doc(did, u[0], "otro", "Tarde", "texto"), 409, "publicar: ya no admite aportaciones", "no admite documentos nuevos")
cad = s.create_debate("Asunto que caducará", "", "Movilidad", "Ayuntamiento", autor)["debate_id"]
sql("UPDATE debates SET conv_deadline=? WHERE id=?", (db.now() - DAY, cad))
expect_error(lambda: cd.add_doc(cad, u[0], "otro", "Tarde", "texto"), 409, "caducado: no admite aportaciones", "no reunió los apoyos")

print("   validación")
d2 = s.create_debate("Zonas de sombra en paradas de autobús", "", "Movilidad", "Ayuntamiento", autor)["debate_id"]
expect_error(lambda: cd.add_doc(d2, u[0], "enlace", "Malo", "", "javascript:alert(1)"), 400, "URL javascript: rechazada")
expect_error(lambda: cd.add_doc(d2, u[0], "enlace", "Malo", "", "data:text/html,hola"), 400, "URL data: rechazada")
expect_error(lambda: cd.add_doc(d2, u[0], "enlace", "Malo", "", "ftp://x.org/a"), 400, "URL ftp: rechazada")
expect_error(lambda: cd.add_doc(d2, u[0], "enlace", "Malo", "", "https://sin-punto"), 400, "URL sin dominio válido rechazada")
expect_error(lambda: cd.add_doc(d2, u[0], "pdf", "Tipo malo", "x"), 400, "tipo no permitido rechazado")
expect_error(lambda: cd.add_doc(d2, u[0], "dato", "ab", "x"), 400, "título demasiado corto rechazado")
expect_error(lambda: cd.add_doc(d2, u[0], "dato", "Sin contenido", "", ""), 400, "sin texto ni enlace rechazado")
expect_error(lambda: cd.add_doc(d2, u[0], "dato", "Muy largo", "x" * 4001), 400, "texto > 4000 rechazado")
expect_error(lambda: cd.add_doc(d2, sinverificar, "dato", "No verificado", "x"), 403, "email sin verificar: 403")
check(cd.valid_url("https://www.ine.es/jaxi/Tabla.htm?t=2852") and not cd.valid_url("http://a b.com"), "valid_url acepta https real y rechaza espacios")

print("   moderación (denunciar / ocultar / bloquear)")
cid = cd.add_doc(d2, u[0], "noticia", "Noticia dudosa", "texto")["id"]
expect_error(lambda: mod.report_content(u[0], "citizen_doc", cid, "spam"), 400, "no se denuncia lo propio")
for i in (1, 2, 3):
    mod.report_content(u[i], "citizen_doc", cid, "spam")
check(cd.list_docs(d2)["total"] == 0, "3 denuncias: la aportación queda oculta para todos")
check(any(r["target_type"] == "citizen_doc" for r in mod.list_reports(admin)), "aparece en la cola de moderación")
mod.resolve(admin, "citizen_doc", cid, "keep")
check(cd.list_docs(d2)["total"] == 1, "moderador «mantener»: vuelve a ser visible")
mod.block_user(u[4], u[0]["id"])
check(cd.list_docs(d2, u[4])["total"] == 0 and cd.list_docs(d2, u[3])["total"] == 1, "bloqueo: quien bloquea deja de verla; el resto la ve")
check(s.get_debate(d2, None)["citizen_docs_total"] == 1, "get_debate expone citizen_docs_total")

# ─────────────────────────────────────────────────────────────────────────────
print("2) Perfiles de experto con nombre y atribución")
d3 = s.create_debate("Renovar el alumbrado del polígono", "", "Energía", "Diputación", autor)["debate_id"]
s.set_phase(d3, "deliberar", admin)
expect_error(lambda: xs.create_profile(u[0], "Ana Ruiz Gil", "Energía"), 403, "ciudadano no crea perfiles")
expect_error(lambda: xs.create_profile(admin, "An", "Energía"), 400, "nombre demasiado corto")
expect_error(lambda: xs.create_profile(admin, "Ana Ruiz Gil", ""), 400, "especialidad obligatoria")
expect_error(lambda: xs.create_profile(admin, "ana@x.org", "Energía"), 400, "el nombre público no puede ser un email")
p1 = xs.create_profile(admin, "Dra. Ana Ruiz Gil", "Eficiencia energética", "Ingeniera industrial; 15 años en alumbrado público.",
                       "Consultoría independiente")["profile"]
check(p1["has_account"] is False and p1["verified"] is True, "perfil sin cuenta de acceso creado")
p_ext = xs.create_profile(admin, "Luis Pardo Ros", "Hacienda local")["profile"]
expect_error(lambda: ds.create_document(d3, admin, "informe", "Informe", "text", "x", author_profile_id=p1["id"]), 409,
             "no se publica en nombre de un perfil NO asignado al asunto", "no está asignado")
expect_error(lambda: xs.assign_profile(u[0], d3, p1["id"]), 403, "ciudadano no asigna expertos")
xs.assign_profile(admin, d3, p1["id"])
r = ds.create_document(d3, admin, "informe", "Informe de consumos", "text", "Consumo aprox.", author_profile_id=p1["id"])
docs = ds.list_documents(d3)
check(docs[0]["author"]["name"] == "Dra. Ana Ruiz Gil" and docs[0]["author"]["specialty"] == "Eficiencia energética",
      "documento atribuido: nombre y especialidad públicos")
check(one("SELECT created_by FROM documents WHERE id=?", (r["document_id"],))["created_by"] == admin["id"],
      "auditoría: created_by = admin que publicó")
check("@" not in json.dumps(docs), "documentos sin emails")
check(ds.get_document(r["document_id"])["author"]["name"] == "Dra. Ana Ruiz Gil", "get_document incluye la autoría")
expect_error(lambda: ds.create_document(d3, u[0], "informe", "X", "text", "x", author_profile_id=p1["id"]), 403,
             "ciudadano no publica documentos oficiales")
# admin de ámbito: puede en su ámbito (Diputación), no en otro
xs.assign_profile(admin_aapp, d3, p_ext["id"])
check(ds.create_document(d3, admin_aapp, "datos", "Datos", "text", "y", author_profile_id=p_ext["id"])["author_profile_id"] == p_ext["id"],
      "admin de ámbito publica en nombre de un experto asignado a SU asunto")
d_otro = s.create_debate("Asunto de otro ámbito", "", "Energía", "Ayuntamiento", autor)["debate_id"]
expect_error(lambda: xs.assign_profile(admin_aapp, d_otro, p_ext["id"]), 403, "admin de ámbito no asigna fuera de su ámbito")
# experto con cuenta vinculada: asignar perfil con cuenta le da autoría propia
p2 = xs.create_profile(admin, "Marta Gil Soto", "Iluminación urbana", "", "", "DEXPERTO@sfera.org", d3)["profile"]
check(p2["has_account"] is True, "perfil vinculado a una cuenta (email sin distinción de mayúsculas)")
check(rl.my_role(experto, d3)["can_author"] is True, "asignar el perfil con cuenta da autoría en el asunto")
s.set_phase(d3, "proponer", admin)
ep = s.add_expert_proposal(d3, experto, "Sustitución por LED con telegestión", "Texto")
check(ep["author_profile_id"] == p2["id"], "el experto con cuenta firma automáticamente con su perfil")
ep2 = s.add_expert_proposal(d3, admin, "Sustitución progresiva en 3 años", "Texto", "", author_profile_id=p1["id"])
expect_error(lambda: s.add_expert_proposal(d3, experto, "Otra", "Texto", "", author_profile_id=p1["id"]), 403,
             "un experto NO publica en nombre de otro (solo la administración)")
gd = s.get_debate(d3, None)
labels = {p["title"]: p for p in gd["expert_proposals"]}
check(labels["Sustitución progresiva en 3 años"]["author"]["name"] == "Dra. Ana Ruiz Gil"
      and labels["Sustitución progresiva en 3 años"]["author_label"] == "Dra. Ana Ruiz Gil · Eficiencia energética",
      "propuesta experta: «Nombre · Especialidad» en público")
check(one("SELECT author_id FROM expert_proposals WHERE id=?", (ep2["id"],))["author_id"] == admin["id"],
      "auditoría: author_id = admin que publicó en su nombre")
check({x["name"] for x in gd["experts"]} >= {"Dra. Ana Ruiz Gil", "Marta Gil Soto"}, "get_debate lista los expertos (perfiles) del asunto")
check("@" not in json.dumps(gd), "la ficha completa del asunto no contiene ningún email")
pub = ds.list_experts(d3, None)
check(all("email" not in x for x in pub), "list_experts: sin emails para el público")
check(any("email" in x for x in ds.list_experts(d3, admin)), "list_experts: emails solo para la administración")
expect_error(lambda: xs.update_profile(u[0], p1["id"], "Hack Hack", "x"), 403, "ciudadano no edita perfiles")
xs.update_profile(admin, p1["id"], "Dra. Ana Ruiz Gil", "Eficiencia energética y alumbrado")
check(ds.list_documents(d3)[-1]["author"]["specialty"] == "Eficiencia energética y alumbrado", "editar el perfil actualiza la autoría mostrada")
xs.unassign_profile(admin, d3, p1["id"])
check(ds.list_documents(d3)[-1]["author"]["name"] == "Dra. Ana Ruiz Gil", "retirar el perfil del asunto conserva la autoría publicada")

# ─────────────────────────────────────────────────────────────────────────────
print("3) Proceso EXPRÉS (duraciones por asunto)")
expect_error(lambda: s.create_debate("Urgente", "", "Sanidad", "Ayuntamiento", u[0], plan="express"), 403,
             "un ciudadano no crea un proceso exprés")
expect_error(lambda: s.create_debate("Urgente", "", "Sanidad", "Ayuntamiento", u[0], quorum_override=5), 403,
             "un ciudadano no rebaja el quórum")
expect_error(lambda: s.create_debate("Urgente", "", "Sanidad", "Ayuntamiento", admin, plan="rapidisimo"), 400, "modalidad desconocida")
expect_error(lambda: s.create_debate("Urgente", "", "Sanidad", "Ayuntamiento", admin, quorum_override=500), 400,
             "el quórum solo puede rebajarse")
x = s.create_debate("Cierre temporal de un paso inferior inundable", "", "Seguridad", "Ayuntamiento", admin,
                    plan="express", quorum_override=3)
xd = x["debate_id"]
check(x["plan"] == "express" and x["plan_dias"] == {"convocar": 3, "deliberar": 5, "proponer": 3, "votar": 3},
      "exprés por defecto = 3/5/3/3 días")
d = s.get_debate(xd)
check(abs(d["conv_deadline"] - (db.now() + 3 * DAY)) < 60 and d["quorum_abierto"] == 3, "convocar exprés: 3 días y quórum 3")
check(d["phase_rules"]["conv_dias"] == 3 and d["phase_rules"]["votacion_dias"] == 3 and d["plan"] == "express",
      "phase_rules refleja las duraciones del asunto")
s.support_debate(xd, u[0]); s.support_debate(xd, u[1])
d = s.get_debate(xd)
check(d["phase"] == "deliberar" and abs(d["phase_deadline"] - (db.now() + 5 * DAY)) < 60,
      "quórum rebajado alcanzado → Deliberar con 5 días")
past(xd, 60 / DAY); d = s.get_debate(xd)
check(d["phase"] == "proponer" and d["phase_dias_restantes"] == 3, "vence Deliberar → Proponer con 3 días")
s.add_expert_proposal(xd, admin, "Cierre con desvío señalizado", "Texto")
past(xd, 60 / DAY); d = s.get_debate(xd)
check(d["phase"] == "votar" and d["phase_dias_restantes"] == 3 and d["election"]["status"] == "abierta",
      "vence Proponer → Votar con 3 días y papeleta abierta")
past(xd); d = s.get_debate(xd)
check(d["phase"] == "publicar" and d["election"]["status"] == "cerrada", "vence Votar → Publicar (recuento automático)")
# sin propuestas expertas en exprés: la ampliación automática no supera la duración de Proponer
x2 = s.create_debate("Exprés sin propuestas", "", "Seguridad", "Ayuntamiento", admin, plan="express")["debate_id"]
s.set_phase(x2, "proponer", admin)
check(abs(s.get_debate(x2)["phase_deadline"] - (db.now() + 3 * DAY)) < 60, "set_phase usa la duración exprés (3 días)")
past(x2); s.get_debate(x2)
ext = one("SELECT days FROM phase_extensions WHERE debate_id=? AND auto=1", (x2,))
check(ext and ext["days"] == 3, "ampliación automática exprés = 3 días (no 7)")
print("   cambio de modalidad")
y = s.create_debate("Pasará a exprés", "", "Movilidad", "Ayuntamiento", autor)["debate_id"]
expect_error(lambda: s.set_plan(y, "express", autor), 403, "el proponente (no admin) no cambia la modalidad")
r = s.set_plan(y, "express", admin)
check(r["plan"] == "express" and abs(r["conv_deadline"] - (db.now() + 3 * DAY)) < 60, "estándar → exprés en Convocar: plazo 3 días")
r = s.set_plan(y, "estandar", admin)
check(r["plan"] == "estandar" and r["plan_dias"]["deliberar"] == 14, "exprés → estándar: vuelve a 14 días")
s.set_phase(y, "deliberar", admin)
expect_error(lambda: s.set_plan(y, "express", admin), 409, "fuera de Convocar no se cambia la modalidad")
std = s.create_debate("Asunto estándar", "", "Movilidad", "Ayuntamiento", autor)
check(std["plan"] == "estandar" and abs(std["conv_deadline"] - (db.now() + 14 * DAY)) < 60, "estándar intacto: 14 días")
check(s.get_config()["plans"]["express"] == {"convocar": 3, "deliberar": 5, "proponer": 3, "votar": 3}, "get_config publica las dos modalidades")

# ─────────────────────────────────────────────────────────────────────────────
print("4) «Ya lo apoyas» y apoyos")
z = s.create_debate("Bancos a la sombra en el paseo", "", "Urbanismo", "Ayuntamiento", autor)["debate_id"]
check(s.get_debate(z, u[2])["supported_by_me"] is False, "antes de apoyar: supported_by_me = False")
r = s.support_debate(z, u[2])
check(r["already"] is False and r["supported_by_me"] is True, "apoyar devuelve supported_by_me")
check(s.get_debate(z, u[2])["supported_by_me"] is True, "ficha: supported_by_me = True")
check(s.support_debate(z, u[2])["already"] is True, "segundo apoyo: already = True (no cuenta doble)")
check(next(x for x in s.list_debates(u[2]) if x["id"] == z)["supported_by_me"] is True, "lista: supported_by_me = True")
check("supported_by_me" not in next(x for x in s.list_debates(None) if x["id"] == z), "lista anónima: sin el campo")
check(s.get_debate(z, autor)["supported_by_me"] is True, "quien convoca ya lo apoya")
expect_error(lambda: s.support_debate(cad, u[3]), 409, "asunto caducado: no admite apoyos", "no reunió los apoyos")

print("5) Email sin distinción de mayúsculas")
check(s.login("DU0@Sfera.org", "clave-test-123")["user_id"] == u[0]["id"], "entrar con mayúsculas funciona")
expect_error(lambda: s.register("Du0@sfera.ORG", "clave-test-123"), 400, "no se duplica la cuenta por mayúsculas", "registrado")

# ─────────────────────────────────────────────────────────────────────────────
print("6) Casos de demostración y ejemplos antiguos")
legacy = s.create_debate("Ejemplo · Fuentes de agua potable en los parques", "", "Medio ambiente", "Ayuntamiento", admin)["debate_id"]
legacy2 = s.create_debate("Peatonalizar la calle mayor los domingos", "", "Movilidad", "Ayuntamiento", admin)["debate_id"]
mod.resolve(admin, "debate", legacy2, "hide", "Ejemplo antiguo")      # como hacía el botón anterior
real = s.create_debate("Democracia Directa", "", "Democracia", "todas", u[3])["debate_id"]
expect_error(lambda: demo_seed.seed(u[0]), 403, "solo el Super Admin crea casos de demostración")
r = demo_seed.seed(admin)
items = r["items"]
check(len(items) == 7 and all(i["status"] == "creado" for i in items), "7 casos creados")
phases = [i["phase"] for i in items]
check(phases.count("deliberar") == 2 and phases.count("proponer") == 2 and {"convocar", "votar", "publicar"} <= set(phases),
      "uno por fase + segundo en Deliberar y en Proponer")
check(len(r["pending_close"]) == 1, "el caso Publicar queda pendiente del voto del admin (el servidor no vota)")
check(one("SELECT COUNT(*) AS n FROM bulletin_board WHERE kind='ballot' AND election_id=?",
          (r["pending_close"][0]["election_id"],))["n"] == 0, "el servidor no ha emitido ninguna papeleta")
r2 = demo_seed.seed(admin)
check(all(i["status"] == "ya existía" for i in r2["items"]) and len(r2["pending_close"]) == 1, "idempotente (marcador oculto demo_key)")
s.close_election(r["pending_close"][0]["election_id"], admin)
dids = {i["key"]: i["id"] for i in items}
for k, v in dids.items():
    g = s.get_debate(v, None)
    check(g["is_demo"] is True and "Ejemplo" not in g["title"], f"{k}: is_demo y título sin «Ejemplo»")
    check("@" not in json.dumps(g), f"{k}: sin emails")
    if k != "convocar":
        check(g["apoyos_abierto"] >= s.CONV_QUORUM and len(g["experts"]) >= 2 and len(ds.list_documents(v)) >= 2,
              f"{k}: apoyos ≥ quórum real, 2+ expertos con nombre, 2+ documentos de expertos")
        check(8 <= g["arguments_total"] <= 15, f"{k}: {g['arguments_total']} argumentos")
    else:
        check(g["phase"] == "convocar" and g["arguments_total"] == 0 and g["apoyos_abierto"] < s.CONV_QUORUM,
              "convocar: sin argumentos (fase no alcanzada) y apoyos por debajo del quórum")
    li = cd.list_docs(v, scope="issue")
    check(3 <= li["total"] <= 5 and any(i.get("file_url") for i in li["items"]),
          f"{k}: 3–5 documentos ciudadanos del asunto, con algún archivo real")
    if g["phase"] in ("proponer", "votar", "publicar"):
        check(5 <= g["proposals_total"] <= 8 and 1 <= len(g["expert_proposals"]) <= 4
              and all(p.get("author") for p in g["expert_proposals"]), f"{k}: propuestas ciudadanas y expertas firmadas")
check(s.get_debate(dids["publicar"])["phase"] == "publicar", "Publicar: votación cerrada y resultado publicado")
check(one("SELECT COUNT(*) AS n FROM expert_profiles WHERE is_demo=1 AND user_id IS NOT NULL")["n"] == 0,
      "expertos ficticios SIN cuentas de acceso")
check(one("SELECT COUNT(*) AS n FROM users WHERE is_demo=1 AND verified=1")["n"] == 0, "ciudadanía ficticia sin acceso (no verificada)")
expect_error(lambda: s.login("ciudadania-demo-001@demo.sferacivitas.invalid", "demo-disabled"), 401, "las cuentas ficticias no pueden entrar")
st = demo_seed.status(admin)
check(st["demo"]["total"] == 7 and st["legacy"]["total"] == 2, "estado: 7 casos y 2 ejemplos antiguos")
expect_error(lambda: demo_seed.set_visibility(u[0], "legacy", "hide"), 403, "solo el Super Admin oculta ejemplos")
demo_seed.set_visibility(admin, "legacy", "hide")
ids_vis = {x["id"] for x in s.list_debates(admin)}
check(legacy not in ids_vis and legacy2 not in ids_vis and real in ids_vis, "ocultar antiguos: fuera de la lista; «Democracia Directa» intacto")
demo_seed.set_visibility(admin, "legacy", "show")
ids_vis = {x["id"] for x in s.list_debates(admin)}
check(legacy in ids_vis and legacy2 in ids_vis, "mostrar antiguos: vuelven (también el que ocultó el botón anterior)")
demo_seed.set_visibility(admin, "demo", "hide")
check(not (set(dids.values()) & {x["id"] for x in s.list_debates(None)}), "ocultar casos de demostración")
demo_seed.set_visibility(admin, "demo", "show")
check(set(dids.values()) <= {x["id"] for x in s.list_debates(None)}, "mostrar casos de demostración")
check(one("SELECT hidden FROM debates WHERE id=?", (real,))["hidden"] in (0, None), "el asunto real nunca se tocó")

print(f"\nRESULTADO documentos/expertos/exprés/demostración: {PASSED} OK · {FAILED} fallos")
raise SystemExit(1 if FAILED else 0)
