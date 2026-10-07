"""Prueba SIN dependencias (stdlib) de la MODERACIÓN de contenido generado por usuarios
(App Store 1.2): denunciar, denuncia duplicada, ocultación automática por umbral,
resolución por moderador (keep/hide/remove) y bloqueo de usuarios.
Ejecuta: python test_moderation.py"""
import os
os.environ["SFERA_DB"] = "/tmp/sfera_test_mod.db"
os.environ.setdefault("SFERA_ADMIN_EMAILS", "modadmin@sfera.org")
os.environ["SFERA_REPORT_THRESHOLD"] = "3"
if os.path.exists("/tmp/sfera_test_mod.db"):
    os.remove("/tmp/sfera_test_mod.db")
import db; db.init_db()
import service as s, docs_service as ds, moderation as mod

PASSED, FAILED = 0, 0


def check(cond, label):
    global PASSED, FAILED
    if cond:
        PASSED += 1; print("  ok  ·", label)
    else:
        FAILED += 1; print("  FALLO ·", label)


def expect_error(fn, status, label):
    try:
        fn()
    except s.SferaError as e:
        check(e.status == status, f"{label} (HTTP {e.status})")
        return
    check(False, label + " (no lanzó error)")


def reg(email):
    r = s.register(email, "clave-test-123"); s.verify(email, r.get("codigo_piloto") or r.get("twofa_code_DEV"))
    return s.get_user(s.login(email, "clave-test-123")["user_id"])


admin = reg("modadmin@sfera.org")
autor = reg("autor@sfera.org")
r1, r2, r3, r4 = (reg(f"rep{i}@sfera.org") for i in range(1, 5))

did = s.create_debate("Carril bici en la avenida", "cuerpo", "Movilidad", "Ayuntamiento", autor)["debate_id"]
s.set_phase(did, "deliberar", admin)   # fases en orden: argumentos solo en Deliberar
s.add_argument(did, autor["id"], "favor", "Argumento del autor")
s.add_argument(did, r1["id"], "contra", "Argumento de rep1")
s.add_argument(did, autor["id"], "matiz", "Otro argumento del autor")   # (para el apartado 5)
s.add_argument(did, r2["id"], "favor", "Argumento de rep2")
s.set_phase(did, "proponer", admin)    # propuestas solo en Proponer
s.add_proposal(did, autor["id"], "Propuesta del autor")
d = s.get_debate(did)
arg_autor = [a for a in d["arguments"] if a["user_id"] == autor["id"]][0]["id"]
prop_autor = d["proposals"][0]["id"]

print("1) Denunciar")
out = mod.report_content(r1, "argument", arg_autor, "ofensivo", "insulta")
check(out["ok"] and out["reports"] == 1 and not out["hidden"], "denuncia registrada, aún visible")
expect_error(lambda: mod.report_content(r1, "argument", arg_autor, "spam"), 409, "denuncia duplicada rechazada")
expect_error(lambda: mod.report_content(r1, "argument", arg_autor, "inventado"), 400, "motivo inválido rechazado")
expect_error(lambda: mod.report_content(r1, "argument", 99999, "spam"), 404, "contenido inexistente")
expect_error(lambda: mod.report_content(r1, "comentario", 1, "spam"), 400, "tipo inválido")
expect_error(lambda: mod.report_content(autor, "argument", arg_autor, "spam"), 400, "no se denuncia lo propio")

print("2) Umbral de ocultación automática")
mod.report_content(r2, "argument", arg_autor, "odio_acoso")
check(any(a["id"] == arg_autor for a in s.get_debate(did)["arguments"]), "con 2 denuncias sigue visible")
out = mod.report_content(r3, "argument", arg_autor, "spam")
check(out["hidden"] and out["reports"] == 3, "a la 3ª denuncia distinta se oculta")
check(not any(a["id"] == arg_autor for a in s.get_debate(did)["arguments"]), "oculto en la vista pública")
check(any(n["kind"] == "moderacion" for n in s.list_notifications(admin)["items"]), "aviso in-app al administrador")

print("3) Asunto oculto por denuncias desaparece del listado")
for u in (r1, r2, r3):
    mod.report_content(u, "debate", did, "spam")
check(did not in [x["id"] for x in s.list_debates()], "asunto fuera del listado público")
expect_error(lambda: s.get_debate(did, r4), 404, "detalle oculto para usuarios")
check(s.get_debate(did, admin)["id"] == did, "el moderador sí lo ve")

print("4) Moderación (admin)")
expect_error(lambda: mod.list_reports(r4), 403, "no-admin no ve la cola")
q = mod.list_reports(admin)
keys = {(x["target_type"], x["target_id"]) for x in q}
check(("argument", arg_autor) in keys and ("debate", did) in keys, "cola de pendientes agrupada")
check(all(x["moderation_status"] == "auto_hidden" for x in q), "estado auto_hidden en la cola")
expect_error(lambda: mod.resolve(r4, "debate", did, "keep"), 403, "no-admin no resuelve")
expect_error(lambda: mod.resolve(admin, "debate", did, "borrar"), 400, "acción inválida")
mod.resolve(admin, "debate", did, "keep", "denuncias infundadas")
check(did in [x["id"] for x in s.list_debates()], "keep: el asunto vuelve al listado")
check(("debate", did) not in {(x["target_type"], x["target_id"]) for x in mod.list_reports(admin)},
      "keep: sale de la cola de pendientes")
mod.resolve(admin, "argument", arg_autor, "remove")
check(not any(a["id"] == arg_autor for a in s.get_debate(did)["arguments"]), "remove: sigue retirado")
check(len(mod.list_reports(admin, "removed")) == 1, "denuncias marcadas como 'removed'")
mod.report_content(r4, "proposal", prop_autor, "otro", "fuera de tema")
mod.resolve(admin, "proposal", prop_autor, "hide")
check(not s.get_debate(did)["proposals"], "hide: propuesta oculta tras una sola denuncia")

print("5) Bloqueo de usuarios")
check(any(a["user_id"] == autor["id"] for a in s.get_debate(did, r4)["arguments"]), "antes de bloquear se ve")
out = mod.block_user(r4, autor["id"])
check(out["ok"] and not out["already"], "bloqueo creado")
check(mod.block_user(r4, autor["id"])["already"], "bloqueo idempotente")
expect_error(lambda: mod.block_user(r4, r4["id"]), 400, "no puedes bloquearte")
expect_error(lambda: mod.block_user(r4, 99999), 404, "usuario inexistente")
args_r4 = s.get_debate(did, r4)["arguments"]
check(not any(a["user_id"] == autor["id"] for a in args_r4), "argumentos del bloqueado filtrados")
check(any(a["user_id"] == r2["id"] for a in args_r4), "los de otros siguen visibles")
check(did not in [x["id"] for x in s.list_debates(r4)], "asuntos del bloqueado fuera del listado")
check(did in [x["id"] for x in s.list_debates(r1)], "otros usuarios no se ven afectados")
check(any(a["user_id"] == autor["id"] for a in s.get_debate(did, r1)["arguments"]), "otro usuario sí ve al autor")
bl = mod.list_blocks(r4)
check(len(bl) == 1 and bl[0]["blocked_id"] == autor["id"] and "***@" in bl[0]["label"], "lista de bloqueos (email enmascarado)")
mod.unblock_user(r4, autor["id"])
check(not mod.list_blocks(r4) and did in [x["id"] for x in s.list_debates(r4)], "desbloqueo restaura la vista")

print("6) Aportaciones a documentos (biblioteca)")
with db.session() as conn:
    doc_id = conn.execute("INSERT INTO documents(debate_id,doc_type,title,created_by,created) VALUES(?,?,?,?,?)",
                          (did, "informe", "Informe", admin["id"], db.now()), returning=True).lastrowid
    cid = conn.execute("INSERT INTO document_contributions(document_id,user_id,kind,text,created) VALUES(?,?,?,?,?)",
                       (doc_id, autor["id"], "comentario", "comentario del autor", db.now()), returning=True).lastrowid
    conn.commit()
check(len(ds.get_document(doc_id, r4)["contributions"]) == 1, "aportación visible")
mod.block_user(r4, autor["id"])
check(not ds.get_document(doc_id, r4)["contributions"], "aportación del bloqueado filtrada")
for u in (r1, r2, r3):
    mod.report_content(u, "contribution", cid, "ilegal")
check(not ds.get_document(doc_id)["contributions"], "aportación oculta por umbral para todos")

print(f"\nRESULTADO moderación: {PASSED} OK · {FAILED} fallos")
raise SystemExit(1 if FAILED else 0)
