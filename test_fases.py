"""Prueba SIN dependencias (stdlib) del MOTOR DE FASES con plazo propio:
orden estricto de fases, solo la fase actual admite acciones, avance PEREZOSO
deliberar → proponer → votar → publicar (recuento automático), puesta al día de
cadenas vencidas, ampliaciones de plazo justificadas (admin), permisos y apoyos únicos.
DECISIÓN DEL FUNDADOR (oct-2026): SOLO se votan PROPUESTAS EXPERTAS (máx. 5, de los
expertos del asunto o su admin) + «Ninguna / mantener como está»; las propuestas
ciudadanas son insumo. Sin propuestas expertas: +7 días una vez y después se detiene
('sin_propuestas_expertas'). Escala: «Útil» y listados paginados/filtrados.
Ejecuta: python test_fases.py"""
import os
import secrets
import threading

os.environ["SFERA_DB"] = "/tmp/sfera_test_fases.db"
os.environ.setdefault("SFERA_ADMIN_EMAILS", "fadmin@sfera.org")
if os.path.exists("/tmp/sfera_test_fases.db"):
    os.remove("/tmp/sfera_test_fases.db")
import db; db.init_db()
import service as s, crypto_core as cc, crypto_zk as zk, roles as rl, docs_service as ds, moderation as mod
from crypto_core import P, G, Q

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


def reg(email):
    r = s.register(email, "clave-test-123"); s.verify(email, r.get("codigo_piloto"))
    return s.get_user(s.login(email, "clave-test-123")["user_id"])


def sql(q, params=()):
    with db.session() as conn:
        conn.execute(q, params); conn.commit()


def one(q, params=()):
    with db.session() as conn:
        r = conn.execute(q, params).fetchone()
    return dict(r) if r else None


def past(did, days_ago=1):
    """Simula el paso del tiempo: el plazo de la fase actual venció hace N días."""
    sql("UPDATE debates SET phase_deadline=? WHERE id=?", (db.now() - days_ago * DAY, did))


def _enc(H, v):
    y = secrets.randbelow(Q - 2) + 2
    return (pow(G, y, P), (pow(G, v, P) * pow(H, y, P)) % P), y


def votar(eid, user, chosen):
    pub = s.election_public(eid); H = int(pub["elgamal_pub"]["h"])
    bpub = cc.BlindPubKey(int(pub["blind_pub"]["open"]["n"]), int(pub["blind_pub"]["open"]["e"]))
    token = secrets.token_bytes(32)
    blinded, r = cc.BlindSigner.blind(bpub, token)
    sig = cc.BlindSigner.unblind(bpub, int(s.issue_credential(eid, user, str(blinded), "open")["blind_sig"]), r)
    ballot, ys, bps = [], [], []
    for i in range(len(pub["options"])):
        b = 1 if i == chosen else 0
        (c1, c2), y = _enc(H, b)
        ballot.append({"c1": str(c1), "c2": str(c2)}); ys.append(y); bps.append(zk.prove_bit(H, c1, c2, y, b))
    C1, C2 = zk.combine_ballot([(int(b["c1"]), int(b["c2"])) for b in ballot])
    sp = zk.prove_sum_one(H, C1, C2, sum(ys) % Q)
    return s.cast_vote(eid, token.hex(), str(sig), ballot, bps, sp, "open")


admin = reg("fadmin@sfera.org")
autor = reg("fautor@sfera.org")
u = [reg(f"fu{i}@sfera.org") for i in range(4)]
experto = reg("fexperto@sfera.org")          # se asignará a asuntos concretos (debate_experts)
experto_mat = reg("fexpmat@sfera.org")       # experto por MATERIA (grant de ámbito)
rl.grant_role(admin, "fexpmat@sfera.org", "expert", "materia", "Educación")


def ep(did, who, title, text="Texto de la propuesta experta con detalle suficiente.", just=""):
    return s.add_expert_proposal(did, who, title, text, just)

print("1) Orden de fases: solo la fase actual admite acciones")
did = s.create_debate("Plan de sombra en los patios escolares", "", "Educación", "Ayuntamiento", autor)["debate_id"]
expect_error(lambda: s.add_argument(did, autor["id"], "favor", "x"), 409, "convocar: no se argumenta", "aún no se ha abierto")
expect_error(lambda: s.add_proposal(did, autor["id"], "x"), 409, "convocar: no se propone", "aún no se ha abierto")
d = s.get_debate(did)
check(d["phase"] == "convocar" and d["phase_deadline"] == d["conv_deadline"], "convocar: phase_deadline = plazo de convocatoria")
check(d["can_admin"] is False, "anónimo: can_admin = False")
check(s.get_debate(did, autor)["can_admin"] is False, "registrado no admin: can_admin = False")
check(s.get_debate(did, admin)["can_admin"] is True, "admin: can_admin = True")
expect_error(lambda: s.set_phase(did, "deliberar", autor), 403, "no-admin no cambia la fase")
s.set_phase(did, "deliberar", admin)
d = s.get_debate(did)
check(d["phase"] == "deliberar" and abs(d["phase_deadline"] - (db.now() + s.DELIB_DIAS * DAY)) < 60,
      f"deliberar: plazo = ahora + {s.DELIB_DIAS} días")
check(d["phase_dias_restantes"] == s.DELIB_DIAS, "phase_dias_restantes correcto")
s.add_argument(did, autor["id"], "favor", "Más árboles y toldos")
expect_error(lambda: s.add_argument(did, autor["id"], "favor", "   "), 400, "argumento vacío rechazado")
expect_error(lambda: s.add_proposal(did, autor["id"], "x"), 409, "deliberar: aún no se propone", "aún no se ha abierto")
expect_error(lambda: s.set_phase(did, "convocar", admin), 409, "no se retrocede de fase")

print("2) Avance perezoso deliberar → proponer al vencer el plazo")
past(did, 1)
old_dl = one("SELECT phase_deadline FROM debates WHERE id=?", (did,))["phase_deadline"]
d = s.get_debate(did)
check(d["phase"] == "proponer", "al leer, pasa sola a proponer")
check(abs(d["phase_deadline"] - (old_dl + s.PROP_DIAS * DAY)) < 1, "plazo de proponer encadenado desde el vencimiento")
d2 = s.get_debate(did)
check(d2["phase"] == "proponer" and d2["phase_deadline"] == d["phase_deadline"], "idempotente (segunda lectura no cambia nada)")
expect_error(lambda: s.add_argument(did, autor["id"], "favor", "tarde"), 409, "proponer: deliberación cerrada",
             "La fase Deliberar de este asunto ya ha terminado")
check(any("Proponer" in n["text"] for n in s.list_notifications(autor)["items"]), "aviso al proponente del cambio de fase")

print("3) Propuestas CIUDADANAS y apoyos (insumo; no se votan)")
pids = []
for i in range(7):
    s.add_proposal(did, (u[i % 4])["id"], f"Propuesta P{i + 1}")
pids = [p["id"] for p in s.list_proposals(did, sort="recientes", limit=50)["items"]][::-1]
P1, P2, P3, P4, P5, P6, P7 = pids
for who, pid in [(u[0], P3), (u[1], P3), (u[2], P3), (u[0], P5), (u[1], P5), (u[2], P5),
                 (u[0], P1), (u[1], P1), (u[3], P2), (u[3], P7)]:
    s.support_proposal(pid, who)
r = s.support_proposal(P3, u[0])
check(r["already"] and r["supports"] == 3, "apoyo repetido no suma (unicidad)")
check(one("SELECT COUNT(*) AS n FROM proposal_supports WHERE proposal_id=? AND user_id=?", (P3, u[0]["id"]))["n"] == 1,
      "una sola fila por (propuesta, usuario)")
d = s.get_debate(did, u[0])
by = {p["id"]: p for p in d["proposals"]}
check(by[P3]["supports"] == 3 and by[P3]["supported_by_me"] and not by[P2]["supported_by_me"], "recuentos y «ya apoyada» por usuario")
check(s.get_debate(did)["proposals"][0]["supported_by_me"] is False, "anónimo: supported_by_me = False")
check(not any(p["en_papeleta"] for p in d["proposals"]), "ninguna propuesta ciudadana va a la papeleta")
check([p["id"] for p in d["proposals"][:3]] == [P3, P5, P1], "get_debate: propuestas ciudadanas ordenadas por apoyos")
expect_error(lambda: s.support_proposal(999999, u[0]), 404, "apoyar propuesta inexistente")

print("3b) Propuestas EXPERTAS: permisos, fase, máximo 5, títulos")
check(s.get_debate(did, autor)["can_author"] is False and s.get_debate(did, admin)["can_author"] is True,
      "can_author: registrado no / admin sí")
expect_error(lambda: ep(did, autor, "Sombra con toldos"), 403, "registrado no experto: no publica propuesta experta", "Solo los expertos")
expect_error(lambda: ep(did, experto, "Sombra con toldos"), 403, "experto NO asignado a este asunto: no publica")
ds.assign_expert(did, "fexperto@sfera.org", admin)
check(s.get_debate(did, experto)["can_author"] is True, "experto asignado: can_author = True")
r1 = ep(did, experto, "Toldos en todos los patios", "Instalar toldos retráctiles en los 40 patios.",
        "Recoge P3 (la más apoyada) y los argumentos sobre golpes de calor.")
check(r1["author_role"] == "experto" and r1["count"] == 1, "experto asignado publica (rol 'experto')")
r2 = ep(did, experto_mat, "Arbolado en los patios")
check(r2["author_role"] == "experto", "experto por materia (grant de ámbito) publica")
r3 = ep(did, admin, "Plan mixto toldos y árboles")
check(r3["author_role"] == "admin", "admin del asunto publica (rol 'admin')")
did_x = s.create_debate("Admin que además es experto", "", "Varios", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did_x, "proponer", admin); ds.assign_expert(did_x, "fadmin@sfera.org", admin)
check(ep(did_x, admin, "Propuesta firmada como experto")["author_role"] == "experto",
      "admin asignado como experto del asunto firma como «experto/a»")
expect_error(lambda: ep(did, experto, "toldos EN todos   los patios"), 409, "título repetido (sin distinguir mayúsculas/espacios)", "ese título")
expect_error(lambda: ep(did, experto, s.NONE_OPTION), 400, "título reservado «Ninguna / mantener como está»")
expect_error(lambda: ep(did, experto, "  "), 400, "título obligatorio")
expect_error(lambda: ep(did, experto, "Sin texto", text=" "), 400, "texto obligatorio")
ep(did, experto, "Horario de recreo de mañana")
r5 = ep(did, experto, "Fuentes y zonas húmedas")
check(r5["count"] == 5, "quinta propuesta experta admitida")
expect_error(lambda: ep(did, experto, "Sexta propuesta"), 409, "6ª propuesta experta: error claro", "máximo de 5")
expect_error(lambda: s.withdraw_expert_proposal(r1["id"], autor), 403, "no-autor no retira")
s.withdraw_expert_proposal(r5["id"], experto)
check(len(s.get_debate(did)["expert_proposals"]) == 4, "retirada: deja de contar (4)")
r5b = ep(did, experto, "Fuentes de agua en los patios")
dd = s.get_debate(did)
eps = dd["expert_proposals"]
check(len(eps) == 5 and dd["expert_proposals_max"] == 5, "5 propuestas expertas visibles")
check(all("email" not in e for e in eps) and {e["author_label"] for e in eps} == {"Experto/a del asunto", "Administración del asunto"},
      "etiqueta de rol pública, sin email")
check(eps[0]["justification"].startswith("Recoge P3"), "justificación guardada (cita propuestas ciudadanas)")
check(len(s.list_expert_proposals(did)["items"]) == 5, "GET propuestas expertas (público)")

print("4) Avance perezoso proponer → votar: papeleta = propuestas EXPERTAS + «Ninguna»")
past(did, 1)
d = s.get_debate(did)
check(d["phase"] == "votar" and d["election"] and d["election"]["status"] == "abierta", "al vencer, se abre la votación cifrada")
opts = d["election"]["options"]
check(opts == ["Toldos en todos los patios", "Arbolado en los patios", "Plan mixto toldos y árboles",
               "Horario de recreo de mañana", "Fuentes de agua en los patios", s.NONE_OPTION],
      f"papeleta = títulos expertos (orden de publicación) + «Ninguna» → {opts}")
check(not any(o.startswith("Propuesta P") for o in opts), "las propuestas ciudadanas NO están en la papeleta")
check(d["election"]["question"] == d["title"], "pregunta = título del asunto")
check(d["election"]["n_votos"] == 0, "n_votos = 0 al abrir")
check(one("SELECT COUNT(*) AS n FROM elections WHERE debate_id=?", (did,))["n"] == 1, "una sola elección creada")
check(d["phase_dias_restantes"] == s.VOTACION_DIAS or d["phase_dias_restantes"] == s.VOTACION_DIAS - 1, "plazo de votación fijado")
expect_error(lambda: s.add_proposal(did, autor["id"], "tarde"), 409, "votar: propuestas cerradas", "ya ha terminado")
expect_error(lambda: s.support_proposal(P4, u[0]), 409, "votar: apoyos cerrados", "ya ha terminado")
expect_error(lambda: ep(did, experto, "Tardía"), 409, "votar: propuestas expertas cerradas", "ya ha terminado")
expect_error(lambda: s.withdraw_expert_proposal(r1["id"], experto), 409, "votar: no se retira una propuesta experta", "ya ha terminado")
expect_error(lambda: s.toggle_util("proposal", P4, u[0]), 409, "votar: «útil» en propuestas cerrado", "ya ha terminado")
eid = d["election"]["id"]
expect_error(lambda: s.close_election(eid, autor), 403, "no-admin no cierra la votación")
expect_error(lambda: s.extend_phase(did, 3, "Motivo suficientemente largo", autor), 403, "no-admin no amplía plazos")
expect_error(lambda: s.open_election(did, "¿?", ["a", "b"], admin), 409, "no se abre una 2ª votación simultánea")
votar(eid, u[0], 0); votar(eid, u[1], 0); votar(eid, u[2], 5); votar(eid, autor, 1)
check(s.get_debate(did)["election"]["n_votos"] == 4, "n_votos cuenta las papeletas del tablón")

print("5) Ampliación de plazo (admin, justificación pública)")
expect_error(lambda: s.extend_phase(did, 3, "corto", admin), 400, "justificación obligatoria (mín. 10)")
expect_error(lambda: s.extend_phase(did, 0, "Motivo suficientemente largo", admin), 400, "días fuera de rango")
before = s.get_debate(did)["phase_deadline"]
r = s.extend_phase(did, 3, "Incidencia técnica en el envío de avisos", admin)
d = s.get_debate(did)
check(abs(d["phase_deadline"] - (before + 3 * DAY)) < 1, "votar: plazo +3 días")
check(abs(one("SELECT cierre FROM debates WHERE id=?", (did,))["cierre"] - d["phase_deadline"]) < 1, "votar: 'cierre' sincronizado")
ext = d["extensions"][-1]
check(ext["justification"] == "Incidencia técnica en el envío de avisos" and ext["days"] == 3 and ext["phase"] == "votar"
      and not ext["auto"], "ampliación registrada y pública en el asunto")

print("6) Avance perezoso votar → publicar con recuento automático")
past(did, 1)
lst = {x["id"]: x for x in s.list_debates()}
check(lst[did]["phase"] == "publicar", "list_debates también pone al día (votar → publicar)")
d = s.get_debate(did)
res = d["election"]["result"]
check(d["election"]["status"] == "cerrada" and res["open"]["recuento"] == [2, 1, 0, 0, 0, 1], f"recuento automático correcto {res['open']['recuento']}")
check(s.audit(eid)["recuento_reproducible"] and s.audit(eid)["cadena_integra"], "tablón íntegro y recuento reproducible")
expect_error(lambda: votar(eid, u[3], 0), 409, "tras el cierre no se puede votar", "no está abierta")
expect_error(lambda: s.issue_credential(eid, u[3], "12345", "open"), 409, "publicar: no se emiten credenciales", "no está abierta")
expect_error(lambda: s.close_election(eid, admin), 409, "no se cierra dos veces")
expect_error(lambda: s.extend_phase(did, 3, "Motivo suficientemente largo", admin), 409, "publicado: sin plazo que ampliar")
check(d["phase_deadline"] is None and d["phase_dias_restantes"] is None, "publicar: sin plazo")

print("7) Cadena vencida: deliberar → proponer → votar → publicar en una sola lectura")
did2 = s.create_debate("Horario de verano de las piscinas", "", "Deportes", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did2, "proponer", admin)
s.add_proposal(did2, u[0]["id"], "Abrir hasta las 22h")
ep(did2, admin, "Abrir hasta las 22h en julio y agosto")
ep(did2, admin, "Abrir también los lunes")
sql("UPDATE debates SET phase='deliberar', phase_deadline=? WHERE id=?", (db.now() - 60 * DAY, did2))
d = s.get_debate(did2)
check(d["phase"] == "publicar", "cadena entera puesta al día")
check(d["election"] and d["election"]["status"] == "cerrada"
      and d["election"]["options"] == ["Abrir hasta las 22h en julio y agosto", "Abrir también los lunes", s.NONE_OPTION],
      "papeleta con <5 propuestas expertas: todas + «Ninguna»")
check(d["election"]["result"]["open"]["total_votos"] == 0, "recuento (vacío) publicado")

print("8) Sin propuestas EXPERTAS: +7 días una vez, aviso y después 'sin_propuestas_expertas'")
did3 = s.create_debate("Fuentes de agua potable en parques", "", "Medio ambiente", "Ayuntamiento", autor)["debate_id"]
ds.assign_expert(did3, "fexperto@sfera.org", admin)
s.set_phase(did3, "proponer", admin)
check(abs(s.get_debate(did3)["phase_deadline"] - (db.now() + s.PROP_DIAS * DAY)) < 60 and s.PROP_DIAS == 14,
      "proponer dura 14 días por defecto (SFERA_PROP_DIAS)")
check(any("propuestas de expertos" in n["text"] for n in s.list_notifications(experto)["items"]),
      "al abrirse Proponer se avisa a los expertos del asunto")
s.add_proposal(did3, u[0]["id"], "Una fuente cada 300 metros")   # hay propuestas CIUDADANAS, pero no cuentan
past(did3, 1)
d = s.get_debate(did3)
check(d["phase"] == "proponer" and d["conv_status"] not in s.STOPPED and d["phase_dias_restantes"] in (s.PROP_EXT_DIAS - 1, s.PROP_EXT_DIAS),
      "1ª vez: se amplía PROP_EXT_DIAS (7) aunque haya propuestas ciudadanas")
check(len(d["extensions"]) == 1 and d["extensions"][0]["auto"] and "propuesta de expertos" in d["extensions"][0]["justification"]
      and d["extensions"][0]["days"] == s.PROP_EXT_DIAS, "ampliación automática registrada y visible")
check(any("no tiene propuestas de expertos" in n["text"] for n in s.list_notifications(admin)["items"]), "aviso a admins")
check(any("no tiene propuestas de expertos" in n["text"] for n in s.list_notifications(experto)["items"]), "aviso a expertos del asunto")
past(did3, 1)
d = s.get_debate(did3)
check(d["phase"] == "proponer" and d["conv_status"] == "sin_propuestas_expertas" and d["phase_deadline"] is None,
      "2ª vez: se detiene (sin_propuestas_expertas)")
check(not d["election"], "no se abre votación vacía")
check(any("se detiene" in n["text"] for n in s.list_notifications(experto)["items"]), "aviso de detención a expertos")
past(did3, 1); d = s.get_debate(did3)
check(d["conv_status"] == "sin_propuestas_expertas" and len(d["extensions"]) == 1, "detenido es estable (no amplía otra vez)")
expect_error(lambda: s.add_proposal(did3, autor["id"], "tarde"), 409, "detenido: no admite propuestas ciudadanas", "ya ha terminado")
expect_error(lambda: s.set_phase(did3, "votar", admin), 409, "set_phase votar sin propuestas expertas: error claro", "Aún no hay propuestas de expertos")
s.extend_phase(did3, 5, "Reabrimos tras petición vecinal registrada", admin)
d = s.get_debate(did3)
check(d["conv_status"] == "avanzado" and d["phase_dias_restantes"] == 5, "admin reabre con ampliación justificada")
s.add_proposal(did3, autor["id"], "Una fuente por parque")
check(s.get_debate(did3)["proposals_total"] == 2, "vuelve a admitir propuestas ciudadanas")
past(did3, 1); d = s.get_debate(did3)
check(d["conv_status"] == "sin_propuestas_expertas", "tras la reapertura sin propuestas expertas, se detiene de nuevo")
ep(did3, experto, "Una fuente accesible por parque")
check(any("ya tiene una propuesta de expertos" in n["text"] for n in s.list_notifications(admin)["items"]),
      "detenido: un experto aún puede publicar y se avisa a la administración")
expect_error(lambda: s.set_phase(did3, "votar", autor), 403, "no-admin no abre la votación")
s.set_phase(did3, "votar", admin)
d = s.get_debate(did3)
check(d["phase"] == "votar" and d["conv_status"] == "avanzado" and d["election"]["options"] == ["Una fuente accesible por parque", s.NONE_OPTION],
      "admin avanza a votar con ≥1 propuesta experta")
did3b = s.create_debate("Bancos a la sombra", "", "Urbanismo", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did3b, "proponer", admin)
s.add_proposal(did3b, autor["id"], "Bancos bajo los árboles")
expect_error(lambda: s.set_phase(did3b, "votar", admin), 409, "set_phase votar con solo propuestas ciudadanas: rechazado", "Aún no hay propuestas de expertos")
expect_error(lambda: s.open_election(did3b, "¿?", ["Sí", "No"], admin), 409, "apertura manual sin propuestas expertas: rechazada", "Aún no hay propuestas de expertos")
ep(did3b, admin, "Veinte bancos con sombra")
r = s.open_election(did3b, "¿Qué hacemos con los bancos?", ["Sí", "No"], admin)
check(r["options"] == ["Veinte bancos con sombra", s.NONE_OPTION], "apertura manual: ignora opciones propias, usa las expertas")
expect_error(lambda: ep(s.create_debate("Deliberando", "", "Educación", "Ayuntamiento", autor)["debate_id"], experto_mat, "X"),
             409, "convocar: no se publican propuestas expertas", "aún no se ha abierto")
did3c = s.create_debate("Legado detenido", "", "Varios", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did3c, "proponer", admin)
sql("UPDATE debates SET conv_status='sin_propuestas' WHERE id=?", (did3c,))
d = s.get_debate(did3c)
check(d["phase_deadline"] is None and d["phase"] == "proponer", "estado legado 'sin_propuestas' se trata como detenido")
s.extend_phase(did3c, 4, "Reapertura de un asunto legado", admin)
check(s.get_debate(did3c)["conv_status"] == "avanzado", "la ampliación también reactiva el estado legado")

print("9) Asuntos previos (sin phase_deadline): plazo en la 1ª lectura")
did4 = s.create_debate("Asunto legado", "", "Varios", "Ayuntamiento", autor)["debate_id"]
sql("UPDATE debates SET phase='deliberar', conv_status='avanzado', phase_deadline=NULL WHERE id=?", (did4,))
d = s.get_debate(did4)
check(d["phase"] == "deliberar" and abs(d["phase_deadline"] - (db.now() + s.DELIB_DIAS * DAY)) < 60, "legado deliberar → ahora + DELIB_DIAS")
did5 = s.create_debate("Asunto legado en votación", "", "Varios", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did5, "proponer", admin)
ep(did5, admin, "Opción única experta")
s.set_phase(did5, "votar", admin)
sql("UPDATE debates SET phase_deadline=NULL, cierre=? WHERE id=?", (db.now() - 30 * DAY, did5))
d = s.get_debate(did5)
check(d["phase"] == "votar" and d["election"]["status"] == "abierta" and d["phase_dias_restantes"] >= s.VOTACION_DIAS - 1,
      "legado votar con 'cierre' vencido → ventana nueva (no se cierra por sorpresa)")
# Votación LEGADA con opciones ciudadanas (como el asunto #8 en producción): se respeta tal cual.
did5b = s.create_debate("Legado con papeleta ciudadana", "", "Varios", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did5b, "proponer", admin)
with db.session() as conn:
    s._create_election(conn, did5b, "¿Qué uso le damos?", ["Zona verde", "Huerto", s.NONE_OPTION])
    conn.execute("UPDATE debates SET phase='votar', phase_deadline=NULL, cierre=? WHERE id=?", (db.now() + 5 * DAY, did5b))
    conn.commit()
d = s.get_debate(did5b)
check(d["phase"] == "votar" and d["election"]["options"] == ["Zona verde", "Huerto", s.NONE_OPTION]
      and d["phase_dias_restantes"] in (4, 5), "votación legada abierta: conserva sus opciones y su cierre")

print("10) Concurrencia: lecturas simultáneas de un asunto vencido → una sola transición")
did6 = s.create_debate("Iluminación del carril bici", "", "Movilidad", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did6, "proponer", admin)
ep(did6, admin, "LED con sensor de presencia")
past(did6, 1)
errs = []
def _rd():
    try: s.get_debate(did6)
    except Exception as ex: errs.append(ex)
ths = [threading.Thread(target=_rd) for _ in range(4)]
[t.start() for t in ths]; [t.join() for t in ths]
check(one("SELECT COUNT(*) AS n FROM elections WHERE debate_id=?", (did6,))["n"] == 1, f"una sola elección (errores: {errs})")
check(s.get_debate(did6)["phase"] == "votar", "fase votar tras la carrera")

print("10b) Moderación: una propuesta experta oculta no entra en la papeleta")
did6b = s.create_debate("Aparcabicis seguros", "", "Movilidad", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did6b, "proponer", admin)
ok1 = ep(did6b, admin, "Aparcabicis cubiertos en cada colegio")["id"]
bad = ep(did6b, admin, "Propuesta denunciada")["id"]
mod.report_content(u[0], "expert_proposal", bad, "spam", "")
mod.resolve(admin, "expert_proposal", bad, "hide")
check([e["id"] for e in s.get_debate(did6b)["expert_proposals"]] == [ok1], "oculta por moderación: fuera de la lista")
s.set_phase(did6b, "votar", admin)
check(s.get_debate(did6b)["election"]["options"] == ["Aparcabicis cubiertos en cada colegio", s.NONE_OPTION],
      "y fuera de la papeleta")

print("12) «Útil»: una marca por persona, se puede quitar, solo en la fase actual")
did7 = s.create_debate("Carril bus en la avenida", "", "Movilidad", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did7, "deliberar", admin)
a1 = s.add_argument(did7, autor["id"], "favor", "El bus ganaría 4 minutos por trayecto.")["id"]
r = s.toggle_util("argument", a1, u[0])
check(r["util_by_me"] and r["utiles"] == 1, "marcar útil")
r = s.toggle_util("argument", a1, u[0])
check(not r["util_by_me"] and r["utiles"] == 0, "volver a pulsar: se quita (toggle)")
s.toggle_util("argument", a1, u[0], on=True); r = s.toggle_util("argument", a1, u[0], on=True)
check(r["utiles"] == 1, "on=True dos veces: idempotente")
check(one("SELECT COUNT(*) AS n FROM argument_utiles WHERE argument_id=? AND user_id=?", (a1, u[0]["id"]))["n"] == 1,
      "una sola fila por (argumento, usuario)")
s.toggle_util("argument", a1, u[1])
dd = s.get_debate(did7, u[0])
check(dd["arguments"][0]["utiles"] == 2 and dd["arguments"][0]["util_by_me"] and not s.get_debate(did7)["arguments"][0]["util_by_me"],
      "get_debate: útiles y util_by_me por usuario (anónimo: False)")
expect_error(lambda: s.toggle_util("argument", 999999, u[0]), 404, "útil en argumento inexistente")
expect_error(lambda: s.toggle_util("proposal", P1, u[0]), 409, "útil en propuesta fuera de Proponer", "ya ha terminado")
s.set_phase(did7, "proponer", admin)
expect_error(lambda: s.toggle_util("argument", a1, u[2]), 409, "útil en argumentos con la deliberación cerrada", "ya ha terminado")
pp = s.add_proposal(did7, autor["id"], "Carril bus de 7 a 21h")["id"]
r = s.toggle_util("proposal", pp, u[0]); s.toggle_util("proposal", pp, u[1])
check(s.list_proposals(did7, u[0])["items"][0]["utiles"] == 2 and s.list_proposals(did7, u[0])["items"][0]["util_by_me"],
      "útil en propuestas ciudadanas (en Proponer)")
expect_error(lambda: s.toggle_util("debate", 1, u[0]), 400, "tipo no válido")

print("13) Listados paginados: orden, filtros por postura, recuentos y tope de get_debate")
did8 = s.create_debate("Zonas de bajas emisiones", "", "Movilidad", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did8, "deliberar", admin)
voters = u + [autor, admin, experto]
aids = []
for i in range(25):
    st = ("favor", "contra", "matiz")[i % 3]
    aids.append(s.add_argument(did8, voters[i % 7]["id"], st, f"Argumento {i:02d} ({st})")["id"])
# útiles: a[5] 4, a[17] 3, a[2] 2, a[11] 1
for k, n in ((5, 4), (17, 3), (2, 2), (11, 1)):
    for v in voters[:n]:
        s.toggle_util("argument", aids[k], v)
L = s.list_arguments(did8, sort="utiles", limit=10)
check([x["id"] for x in L["items"][:4]] == [aids[5], aids[17], aids[2], aids[11]], "sort=utiles: más útiles primero")
check([x["id"] for x in L["items"][4:6]] == [aids[0], aids[1]], "empate en útiles: el más antiguo primero")
check(L["total"] == 25 and L["counts"] == {"favor": 9, "contra": 8, "matiz": 8, "todos": 25}, f"total y recuento por postura {L['counts']}")
check(L["has_more"] and len(L["items"]) == 10, "primera página de 10, hay más")
R = s.list_arguments(did8, sort="recientes", limit=5)
check([x["id"] for x in R["items"]] == aids[::-1][:5], "sort=recientes: el más nuevo primero")
F = s.list_arguments(did8, sort="recientes", stance="contra", limit=50)
check(F["total"] == 8 and len(F["items"]) == 8 and all(x["stance"] == "contra" for x in F["items"]) and F["counts"]["todos"] == 25,
      "stance=contra: solo en contra; recuentos globales intactos")
seen = []
off = 0
while True:
    pg = s.list_arguments(did8, sort="utiles", limit=7, offset=off)
    seen += [x["id"] for x in pg["items"]]; off += 7
    if not pg["has_more"]:
        break
check(len(seen) == 25 and len(set(seen)) == 25, "paginación por offset: sin huecos ni duplicados")
check(len(s.list_arguments(did8, limit=999)["items"]) == 25 and s.list_arguments(did8, limit=999)["limit"] == s.PAGE_MAX,
      "limit acotado a PAGE_MAX")
check(s.list_arguments(did8, sort="xx", stance="yy")["sort"] == "utiles", "parámetros desconocidos → valores por defecto")
dd = s.get_debate(did8)
check(len(dd["arguments"]) == s.EMBED_MAX == 10 and dd["arguments_total"] == 25 and dd["arguments"][0]["id"] == aids[5],
      "get_debate incrusta solo el top-10 por útiles (+ total)")
check(dd["arguments_counts"]["favor"] == 9, "get_debate: recuento por postura")
with db.session() as conn:
    conn.execute("INSERT INTO content_moderation(target_type,target_id,status,updated) VALUES('argument',?,'hidden',?)", (aids[5], db.now()))
    conn.commit()
L = s.list_arguments(did8)
check(L["total"] == 24 and aids[5] not in [x["id"] for x in L["items"]], "oculto por moderación: fuera del listado y de los recuentos")
mod.block_user(u[0], voters[1]["id"])
L = s.list_arguments(did8, u[0], limit=50)
check(all(x["user_id"] != voters[1]["id"] for x in L["items"]) and L["total"] < 24, "bloqueados: fuera para quien bloquea")
s.set_phase(did8, "proponer", admin)
for i in range(13):
    s.add_proposal(did8, voters[i % 7]["id"], f"Propuesta ciudadana {i:02d}")
pl = s.list_proposals(did8, sort="recientes", limit=50)["items"]
pz = [x["id"] for x in pl][::-1]
for v in voters[:3]:
    s.support_proposal(pz[9], v)
s.support_proposal(pz[4], voters[0])
s.toggle_util("proposal", pz[7], voters[0]); s.toggle_util("proposal", pz[7], voters[1])
A = s.list_proposals(did8, sort="apoyos", limit=3)["items"]
check([x["id"] for x in A] == [pz[9], pz[4], pz[7]], "propuestas sort=apoyos (empate → útiles → antigüedad)")
U = s.list_proposals(did8, sort="utiles", limit=1)["items"]
check(U[0]["id"] == pz[7], "propuestas sort=utiles")
dd = s.get_debate(did8)
check(len(dd["proposals"]) == 10 and dd["proposals_total"] == 13 and dd["proposals"][0]["id"] == pz[9],
      "get_debate: top-10 propuestas ciudadanas por apoyos (+ total)")
expect_error(lambda: s.list_arguments(999999), 404, "listado de asunto inexistente")
oid = s.create_org(autor, "Colectivo de prueba")["org_id"]
pdid = s.create_debate("Asunto privado", "", "Varios", "Privado", autor, org_id=oid)["debate_id"]
expect_error(lambda: s.list_arguments(pdid, u[3]), 403, "listado de asunto privado: solo miembros")
check(s.list_arguments(pdid, autor)["total"] == 0, "miembro sí lista el asunto privado")

print("11) Configuración pública")
cfg = s.get_config()
check(cfg["delib_dias"] == s.DELIB_DIAS and cfg["prop_dias"] == s.PROP_DIAS and cfg["votacion_dias"] == s.VOTACION_DIAS,
      "get_config expone los plazos por fase")
check(cfg["expert_max"] == 5 and cfg["prop_ext_dias"] == 7 and cfg["ballot_source"] == "expertas" and cfg["prop_dias"] == 14,
      "get_config: máx. 5 propuestas expertas, +7 días, papeleta = expertas, Proponer 14 días")

print(f"\nRESULTADO fases: {PASSED} OK · {FAILED} fallos")
raise SystemExit(1 if FAILED else 0)
