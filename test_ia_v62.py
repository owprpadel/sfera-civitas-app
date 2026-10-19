# Pruebas v62: «Participante IA» — delibera y propone como un ciudadano más, pero NO vota.
# La API de Anthropic se SIMULA (monkeypatch de ia._http_post): no sale nada a la red.
import os
import json
import re
os.environ.setdefault("SFERA_CERT_SIM_ALLOWED", "1")
os.environ["SFERA_DB"] = "/tmp/sfera_test_ia_v62.db"
os.environ.setdefault("SFERA_ADMIN_EMAILS", "iadmin@sfera.org")
os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("SFERA_IA_MAX_DIA", None)
if os.path.exists("/tmp/sfera_test_ia_v62.db"):
    os.remove("/tmp/sfera_test_ia_v62.db")
import db; db.init_db()
import service as s, moderation as mod, citizen_docs as cdocs, roles as rl
import ia_participante as ia

OK = FAIL = 0
def check(c, l):
    global OK, FAIL
    if c: OK += 1; print("  ok  ·", l)
    else: FAIL += 1; print("  FALLO ·", l)

def expect_error(fn, status, label, contains=None):
    try:
        fn()
    except s.SferaError as e:
        check(e.status == status and (contains is None or contains in e.msg), f"{label} (HTTP {e.status}: {e.msg})")
        return
    except Exception as e:
        check(False, f"{label} (error inesperado {type(e).__name__}: {e})"); return
    check(False, label + " (no lanzó error)")

s._send_email = lambda to, subj, body: True
s._send_email_async = lambda to, subj, body: None

def reg(email):
    r = s.register(email, "clave-test-123"); s.verify(email, r.get("codigo_piloto"))
    return s.get_user(s.login(email, "clave-test-123")["user_id"])

def one(q, p=()):
    with db.session() as conn:
        r = conn.execute(q, p).fetchone()
    return dict(r) if r else None

def sql(q, p=()):
    with db.session() as conn:
        conn.execute(q, p); conn.commit()

# ── API simulada ──
CALLS = []
MODE = {"m": "ok"}
def fake_http(payload):
    CALLS.append(payload)
    msg = payload["messages"][0]["content"]
    if MODE["m"] == "badjson":
        return {"content": [{"type": "text", "text": "Claro, aquí tienes: {argumentos: [favor]"}]}
    if "fase DELIBERAR" in msg:
        sts = re.findall(r'stance "(\w+)"', msg)
        if MODE["m"] == "badstance":
            sts = ["opinion" for _ in sts]
        txt = {"favor": "Ampliar el servicio ayudaría a quien estudia por la noche y no tiene un sitio tranquilo en casa.",
               "contra": "El coste de personal y seguridad nocturna puede ser alto; conviene saber cuánta gente lo usaría de verdad.",
               "matiz": "Se podría probar solo en época de exámenes y medir el uso antes de decidir si se mantiene."}
        if MODE["m"] == "party":
            txt["favor"] = "Esto es lo que siempre ha defendido el PSOE y tiene sentido apoyarlo ahora."
        if MODE["m"] == "long":
            txt["favor"] = " ".join(["palabra"] * 120)
        body = {"argumentos": [{"stance": st, "text": txt.get(st, "Texto de prueba suficientemente largo aquí.")} for st in sts]}
    else:
        n = int(re.search(r"exactamente (\d+) propuesta", msg).group(1))
        props = ["Abrir dos bibliotecas por distrito hasta medianoche durante exámenes, con vigilancia compartida entre centros.",
                 "Habilitar aulas de institutos como salas de estudio los fines de semana, gestionadas por voluntariado y conserjes."]
        body = {"propuestas": [{"text": t} for t in props[:n]]}
    return {"content": [{"type": "text", "text": json.dumps(body, ensure_ascii=False)}]}
ia._http_post = fake_http
ia.AUTO = False          # los disparos automáticos se prueban aparte (sección 9)

admin = reg("iadmin@sfera.org")
u = reg("ivecina@sfera.org")
u2 = reg("ivecino@sfera.org")
check(admin.get("is_admin"), "Super Admin de prueba")

def nuevo(title="Ampliar el horario de las bibliotecas", phase="deliberar"):
    did = s.create_debate(title, "¿Abrir por la noche en exámenes?", "Cultura", "Ayuntamiento", u)["debate_id"]
    if phase != "convocar":
        s.set_phase(did, phase if phase in ("deliberar", "proponer") else "deliberar", admin)
    return did

def ia_args(did):
    uid = ia.ensure_ai_user()
    with db.session() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM arguments WHERE debate_id=? AND user_id=?", (did, uid)).fetchall()]

def ia_props(did):
    uid = ia.ensure_ai_user()
    with db.session() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM proposals WHERE debate_id=? AND user_id=?", (did, uid)).fetchall()]

print("1) Cuenta de sistema «Participante IA»")
uid1 = ia.ensure_ai_user(); uid2 = ia.ensure_ai_user()
ai = one("SELECT * FROM users WHERE id=?", (uid1,))
check(uid1 == uid2 and ai["is_ai"] == 1, "ensure_ai_user idempotente (una sola cuenta, is_ai=1)")
check(ai["email"] == ia.AI_EMAIL and ai["email"].endswith(".invalid"), "email no utilizable (.invalid)")
check(ai["pass_hash"].startswith("ia-disabled$") and not ai["verified"] and not ai["is_admin"], "contraseña inutilizable, sin verificar, sin roles")
expect_error(lambda: s.login(ia.AI_EMAIL, "lo-que-sea-123"), 401, "login imposible")
expect_error(lambda: s.get_user(uid1), 401, "una sesión de la IA nunca es válida (get_user)")
r = s.forgot_password(ia.AI_EMAIL)
check("codigo_piloto" not in r and one("SELECT reset_code_hash FROM users WHERE id=?", (uid1,))["reset_code_hash"] is None,
      "recuperar contraseña no da acceso a la cuenta IA")
expect_error(lambda: s.verify_certificate(ia.AI_EMAIL, "CN=IA"), 403, "no se puede verificar con certificado")
expect_error(lambda: rl.grant_role(admin, ia.AI_EMAIL, "expert", "global"), 400, "no recibe permisos de experto/admin")

print("2) Sin clave: el módulo es INERTE")
did0 = nuevo("Asunto inerte")
r = ia.run_for_debate(did0)
check(not r["ok"] and "inerte" in r["skipped"], "run_for_debate sin clave → no hace nada")
check(ia.trigger(did0, "deliberar") is False and ia.maybe_trigger(did0, {"phase": "deliberar"}) is False, "disparos sin clave → nada")
check(ia.status()["inerte"] and not ia.status()["enabled"], "status() indica inerte")
check(not ia_args(did0) and not CALLS, "no crea nada ni llama a la API")
d = s.get_debate(did0, u)
check(d["phase"] == "deliberar", "get_debate funciona igual sin clave")

os.environ["ANTHROPIC_API_KEY"] = "sk-test-falsa"
check(ia.status()["enabled"] and ia.status()["model"] == "claude-haiku-5-5", "con clave: activo · modelo por defecto")

print("3) Deliberar: hasta 3 argumentos equilibrados, y no más")
did = nuevo()
s.add_argument(did, u["id"], "favor", "Hay mucha demanda en época de exámenes en mi barrio.")
r = ia.run_for_debate(did)
A = ia_args(did)
check(r["ok"] and r["created"] == 3 and len(A) == 3, f"crea 3 argumentos ({r})")
check(sorted(a["stance"] for a in A) == ["contra", "favor", "matiz"], "uno a favor, uno en contra y un matiz")
check(all(len(a["text"].split()) <= ia.ARG_MAX_WORDS for a in A), "longitud acotada")
p = CALLS[-1]
check(p["model"] == "claude-haiku-5-5" and "no partidista" in p["system"] and "aprox." in p["system"], "prompt de sistema neutral (sin cifras inventadas)")
check("Hay mucha demanda" in p["messages"][0]["content"], "el contexto incluye los argumentos existentes")
n = len(CALLS)
r = ia.run_for_debate(did, force=True)
check(len(ia_args(did)) == 3 and len(CALLS) == n and r.get("created") == 0, "segunda llamada: no crea más ni llama a la API")
sql("UPDATE debates SET is_demo=1 WHERE id=?", (did0,))
r = ia.run_for_debate(did0)
check(r.get("created") == 3, "también participa en los casos ilustrativos (is_demo)")
did_p = nuevo("Solo falta lo que falta")
sql("INSERT INTO arguments(debate_id,user_id,stance,text,created) VALUES(?,?,?,?,?)",
    (did_p, uid1, "favor", "Argumento previo de la IA a favor.", db.now() - 20 * 3600))
r = ia.run_for_debate(did_p)
check(r.get("created") == 2 and sorted(a["stance"] for a in ia_args(did_p)) == ["contra", "favor", "matiz"],
      "si ya tiene una postura, solo aporta las que faltan")
check(re.findall(r'stance "(\w+)"', CALLS[-1]["messages"][0]["content"]) == ["contra", "matiz"], "pide solo contra y matiz")
# privado (nace en deliberar)
org = s.create_org(u, "Comunidad de vecinos")
oid = org.get("org_id") or org.get("id")
dpriv = s.create_debate("Pintar el portal", "¿Color?", "Vivienda", "", u, org_id=oid)["debate_id"]
r = ia.run_for_debate(dpriv)
check(r.get("created") == 3, "también en asuntos privados")

print("4) get_debate marca is_ai; la gente puede marcar «útil»")
d = s.get_debate(did, u)
ai_items = [a for a in d["arguments"] if a["is_ai"]]
check(len(ai_items) == 3 and all(not a["is_ai"] for a in d["arguments"] if a["user_id"] != uid1), "is_ai true solo en lo de la IA")
r = s.toggle_util("argument", ai_items[0]["id"], u2)
check(r["utiles"] == 1, "una persona marca «útil» un argumento de la IA")
la = s.list_arguments(did, u)
check(any(i["is_ai"] for i in la["items"]), "list_arguments también lleva is_ai")

print("5) Proponer: hasta 2 propuestas")
s.set_phase(did, "proponer", admin)
s.add_proposal(did, u["id"], "Abrir la biblioteca central 24 horas en junio.")
r = ia.run_for_debate(did)
P = ia_props(did)
check(r.get("created") == 2 and len(P) == 2, f"crea 2 propuestas ({r})")
check("Abrir la biblioteca central 24 horas" in CALLS[-1]["messages"][0]["content"], "ve las propuestas existentes")
n = len(CALLS)
r = ia.run_for_debate(did, force=True)
check(len(ia_props(did)) == 2 and len(CALLS) == n, "no crea más de 2 ni vuelve a llamar")
check(len(ia_args(did)) == 3, "en Proponer no añade argumentos")
d = s.get_debate(did, u)
pai = [p for p in d["proposals"] if p["is_ai"]]
check(len(pai) == 2, "get_debate marca is_ai en propuestas")
r = s.support_proposal(pai[0]["id"], u2)
check(r["supports"] == 1, "una persona apoya una propuesta de la IA")
r = s.toggle_util("proposal", pai[0]["id"], u2)
check(r["utiles"] == 1, "y la marca «útil»")

print("6) Nada en Convocar, Votar ni Publicar")
dconv = nuevo("Asunto en convocar", phase="convocar")
n = len(CALLS)
r = ia.run_for_debate(dconv)
check(not r["ok"] and not ia_args(dconv) and len(CALLS) == n, "Convocar: nada")
s.add_expert_proposal(did, admin, "Ampliar horario en exámenes", "Abrir hasta las 24 h durante exámenes con refuerzo.")
s.set_phase(did, "votar", admin)
nA, nP = len(ia_args(did)), len(ia_props(did))
r = ia.run_for_debate(did, force=True)
check(not r["ok"] and len(CALLS) == n, "Votar: nada")
check(ia.trigger(did, "votar") is False, "trigger no actúa en Votar")
s.set_phase(did, "publicar", admin)
r = ia.run_for_debate(did, force=True)
check(not r["ok"] and len(CALLS) == n and (len(ia_args(did)), len(ia_props(did))) == (nA, nP), "Publicar: nada")

print("7) La IA no puede votar, apoyar, marcar «útil», convocar, subir documentos ni denunciar")
aiu = one("SELECT * FROM users WHERE id=?", (uid1,))
aiu_hack = dict(aiu, verified=1)          # aunque alguien la marcara como verificada…
aiu_noflag = dict(aiu_hack); aiu_noflag.pop("is_ai")   # …o el dict no trajera el flag (se mira la BBDD)
dv = nuevo("Asunto para votar")
s.set_phase(dv, "proponer", admin)
s.add_expert_proposal(dv, admin, "Opción A", "Texto de la opción A con detalle.")
s.set_phase(dv, "votar", admin)
eid = s.get_debate(dv, None)["election"]["id"]
for who, lbl in ((aiu_hack, "flag"), (aiu_noflag, "BBDD")):
    expect_error(lambda: s.issue_credential(eid, who, "12345", "open"), 403, f"no recibe credencial de voto ({lbl})")
check(one("SELECT COUNT(*) AS n FROM credential_issued WHERE user_id=?", (uid1,))["n"] == 0, "ninguna credencial emitida a la IA")
expect_error(lambda: s.support_debate(dconv, aiu_hack), 403, "no apoya asuntos")
expect_error(lambda: s.support_debate(dconv, aiu_noflag), 403, "no apoya asuntos (comprobación en BBDD)")
dpp = nuevo("Asunto para propuestas")
s.set_phase(dpp, "proponer", admin)
pid = s.add_proposal(dpp, u["id"], "Propuesta humana de prueba con texto.")["id"]
expect_error(lambda: s.support_proposal(pid, aiu_noflag), 403, "no apoya propuestas")
expect_error(lambda: s.toggle_util("proposal", pid, aiu_noflag), 403, "no marca «útil»")
expect_error(lambda: s.create_debate("Asunto de la IA", "", "Cultura", "Ayuntamiento", aiu_noflag), 403, "no convoca asuntos")
expect_error(lambda: s.create_debate("Asunto de la IA", "", "Cultura", "Ayuntamiento", aiu_hack), 403, "no convoca asuntos (flag)")
expect_error(lambda: cdocs.add_doc(dpp, aiu_noflag, "dato", "Dato de la IA", text="x"), 403, "no sube documentos")
expect_error(lambda: mod.report_content(aiu_hack, "proposal", pid, "spam"), 403, "no denuncia")
expect_error(lambda: s.add_argument(dpp, uid1, "favor", "texto"), 403, "no usa la vía normal de argumentos")
expect_error(lambda: s.add_proposal(dpp, uid1, "texto"), 403, "no usa la vía normal de propuestas")

print("8) Sus apoyos no cuentan para el quórum")
dq = nuevo("Asunto con quórum", phase="convocar")
sql("UPDATE debates SET quorum_override=2 WHERE id=?", (dq,))
sql("INSERT INTO supports(debate_id,user_id,via,created) VALUES(?,?,?,?)", (dq, uid1, "abierto", db.now()))
d = s.get_debate(dq, None)
check(d["phase"] == "convocar" and d["apoyos_abierto"] == 1, f"apoyo de la IA (forzado en BBDD) no cuenta ({d['apoyos_abierto']})")

print("9) Disparos: transiciones (segundo plano) sin bloquear")
LAUNCH = []
real_launch = ia._launch
ia._launch = lambda did_, ph, force=False: (LAUNCH.append((did_, ph, force)) or True)
ia.AUTO = True
dt = nuevo("Disparo por transición", phase="convocar")
s.set_phase(dt, "deliberar", admin)
check((dt, "deliberar", True) in LAUNCH, "set_phase → Deliberar dispara a la IA")
s.set_phase(dt, "proponer", admin)
check((dt, "proponer", True) in LAUNCH, "set_phase → Proponer dispara a la IA")
dt2 = nuevo("Disparo por quórum", phase="convocar")
sql("UPDATE debates SET quorum_override=2 WHERE id=?", (dt2,))
s.support_debate(dt2, u2)
check((dt2, "deliberar", True) in LAUNCH, "al prosperar (_conv_apply) dispara a la IA")
dt3 = nuevo("Disparo por plazo", phase="deliberar")
sql("UPDATE debates SET phase_deadline=? WHERE id=?", (db.now() - 60, dt3))
s.get_debate(dt3, None)
check((dt3, "proponer", True) in LAUNCH, "deliberar→proponer por plazo (_phase_apply) dispara a la IA")
dp2 = s.create_debate("Privado nuevo", "", "Vivienda", "", u, org_id=oid)["debate_id"]
check((dp2, "deliberar", True) in LAUNCH, "asunto privado nuevo (nace en Deliberar) dispara a la IA")
dt4 = nuevo("Disparo en votar", phase="convocar")
LAUNCH.clear()
s.get_debate(dconv, None)
check(not LAUNCH, "leer un asunto en Convocar no dispara nada")

print("10) Perezoso con enfriamiento de 12 h y una tanda a la vez")
dl = nuevo("Perezoso")
LAUNCH.clear()
sql("INSERT INTO arguments(debate_id,user_id,stance,text,created) VALUES(?,?,?,?,?)",
    (dl, uid1, "favor", "Aportación reciente de la IA.", db.now() - 3600))
s.get_debate(dl, u)
check(not LAUNCH, "aportación hace 1 h → no dispara (enfriamiento)")
sql("UPDATE arguments SET created=? WHERE debate_id=? AND user_id=?", (db.now() - 13 * 3600, dl, uid1))
sql("DELETE FROM ia_runs WHERE debate_id=?", (dl,))
s.get_debate(dl, u)
check((dl, "deliberar", False) in LAUNCH, "aportación hace 13 h y cupo sin completar → dispara")
ia._launch = real_launch
ia.SYNC = True
n = len(CALLS)
s.get_debate(dl, u)                                  # ahora se ejecuta de verdad (síncrono en la prueba)
check(len(ia_args(dl)) == 3 and len(CALLS) == n + 1, "la tanda perezosa completa el cupo (3)")
s.get_debate(dl, u); s.get_debate(dl, u)
check(len(ia_args(dl)) == 3 and len(CALLS) == n + 1, "lecturas siguientes: nada más (cupo lleno)")
ia.AUTO = False; dl2 = nuevo("Sin aportaciones aún"); dl3 = nuevo("Tanda en curso"); ia.AUTO = True
check(not ia_args(dl2), "(asunto creado sin disparo por transición)")
n = len(CALLS)
s.get_debate(dl2, u)
check(len(ia_args(dl2)) == 3 and len(CALLS) == n + 1, "sin ninguna aportación → la primera lectura dispara")
sql("INSERT INTO ia_runs(debate_id,phase,status,lock_key,created) VALUES(?,?,?,?,?)", (dl3, "deliberar", "running", str(dl3), db.now()))
n = len(CALLS)
s.get_debate(dl3, u)
r = ia.run_for_debate(dl3, force=True)
check(len(CALLS) == n and not ia_args(dl3) and "en curso" in r.get("skipped", ""), "con una tanda en curso no se lanza otra (cerrojo)")
sql("UPDATE ia_runs SET created=? WHERE debate_id=?", (db.now() - 3600, dl3))
r = ia.run_for_debate(dl3, force=True)
check(r.get("created") == 3, "una tanda colgada (> 15 min) se libera y la siguiente funciona")
ia.SYNC = False; ia.AUTO = False

print("10b) Hilo real en segundo plano (sin bloquear la petición)")
import time as _t
ia.AUTO = False; dth = nuevo("Hilo real", phase="convocar"); dth2 = nuevo("Hilo real por plazo"); ia.AUTO = True
s.set_phase(dth, "deliberar", admin)
for _ in range(100):
    if len(ia_args(dth)) == 3: break
    _t.sleep(0.1)
check(len(ia_args(dth)) == 3, "set_phase → el hilo publica los 3 argumentos")
s.add_argument(dth2, u["id"], "favor", "Argumento humano.")
sql("UPDATE debates SET phase_deadline=? WHERE id=?", (db.now() - 60, dth2))
s.get_debate(dth2, None)                               # transición dentro de la transacción → el hilo espera al commit
for _ in range(150):
    if len(ia_props(dth2)) == 2: break
    _t.sleep(0.1)
check(len(ia_props(dth2)) == 2, "deliberar→proponer por plazo → el hilo publica las 2 propuestas")
ia.AUTO = False

print("11) Respuesta no válida → no publica nada")
for m, lbl in (("badjson", "JSON roto"), ("badstance", "postura no válida"), ("party", "nombra un partido"), ("long", "demasiado largo")):
    MODE["m"] = m
    dx = nuevo(f"Inválido {m}")
    r = ia.run_for_debate(dx)
    check(not ia_args(dx) and r.get("invalid"), f"{lbl}: no publica nada")
    check(one("SELECT status FROM ia_runs WHERE debate_id=? ORDER BY id DESC LIMIT 1", (dx,))["status"] == "invalid", f"{lbl}: tanda registrada como inválida")
MODE["m"] = "ok"
r = ia.run_for_debate(dx)
check(not r["ok"] and "enfriamiento" in r.get("skipped", ""), "tras un fallo, el perezoso espera 12 h (sin bucles de coste)")

print("12) Límite diario de llamadas")
hoy = one("SELECT calls FROM ia_daily WHERE day=?", (ia._today(),))["calls"]
check(hoy == len(CALLS), f"contador diario en BBDD = llamadas reales ({hoy})")
os.environ["SFERA_IA_MAX_DIA"] = str(hoy)
dlim = nuevo("Límite diario")
n = len(CALLS)
r = ia.run_for_debate(dlim)
check(not r["ok"] and "límite diario" in r["skipped"] and len(CALLS) == n and not ia_args(dlim), "al llegar al límite no llama ni publica")
os.environ["SFERA_IA_MAX_DIA"] = str(hoy + 1)
r = ia.run_for_debate(dlim, force=True)
check(r.get("created") == 3, "con cupo diario disponible vuelve a funcionar")
os.environ.pop("SFERA_IA_MAX_DIA")

print("13) Moderación: se puede denunciar y ocultar lo de la IA")
d = s.get_debate(dl2, u)
aid = [a for a in d["arguments"] if a["is_ai"]][0]["id"]
mod.report_content(u2, "argument", aid, "spam")
mod.resolve(admin, "argument", aid, "hide")
d = s.get_debate(dl2, u)
check(all(a["id"] != aid for a in d["arguments"]), "un argumento de la IA ocultado por la administración no se muestra")
r = ia.run_for_debate(dl2, force=True)
check(r.get("created") == 0, "la IA no vuelve a publicar lo que se le ocultó (cuenta para su cupo)")

print("14) Endpoints de administración")
expect_error(lambda: ia.status(u), 403, "status solo Super Admin")
expect_error(lambda: ia.admin_run(u, dl2), 403, "run solo Super Admin")
st = ia.status(admin)
check(st["ai_user_id"] == uid1 and st["llamadas_hoy"] >= 1 and st["ultimas_tandas"] and "sk-test" not in json.dumps(st),
      "status: usuario, llamadas de hoy y tandas (sin exponer la clave)")
dadm = nuevo("Forzado por admin")
sql("INSERT INTO ia_runs(debate_id,phase,status,lock_key,created,finished) VALUES(?,?,?,NULL,?,?)",
    (dadm, "deliberar", "done", db.now() - 60, db.now() - 60))
r = ia.admin_run(admin, dadm)
check(r.get("created") == 3, "admin_run ignora el enfriamiento")
os.environ.pop("ANTHROPIC_API_KEY")
r = ia.admin_run(admin, nuevo("Sin clave de nuevo"))
check(not r["ok"] and r.get("inerte"), "admin_run sin clave: inerte")

print(f"RESULTADO v62: {OK} OK · {FAIL} fallos")
