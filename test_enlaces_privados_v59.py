"""Prueba v59: documentos de ESPACIOS PRIVADOS que se abren fuera de la app (Safari, sin sesión).
  1) Enlace firmado por archivo: vale solo para ese archivo, esa persona y unas horas.
  2) Sin enlace válido, un archivo de asunto privado NO se descarga (antes, el de experto sí: corregido).
  3) Las respuestas a quien tiene sesión llevan los file_url ya firmados (?t=…), sin romper ?v=.
Ejecuta: python3 test_enlaces_privados_v59.py"""
import ast, base64, os, re, time
os.environ.setdefault("SFERA_CERT_SIM_ALLOWED", "1")
DBP = "/tmp/sfera_test_v59.db"
os.environ["SFERA_DB"] = DBP
os.environ.setdefault("SFERA_ADMIN_EMAILS", "padmin@sfera.org")
if os.path.exists(DBP):
    os.remove(DBP)
import db; db.init_db()
import service as s, docs_service as ds, citizen_docs as cd, demo_files

PASSED, FAILED = 0, 0
def check(cond, label):
    global PASSED, FAILED
    if cond: PASSED += 1; print("  ok  ·", label)
    else: FAILED += 1; print("  FALLO ·", label)
def expect_error(fn, status, label):
    try: fn()
    except s.SferaError as e:
        check(e.status == status, f"{label} (HTTP {e.status}: {e.msg})"); return
    check(False, label + " (no lanzó error)")
def reg(email):
    r = s.register(email, "clave-test-123"); s.verify(email, r.get("codigo_piloto"))
    return s.get_user(s.login(email, "clave-test-123")["user_id"])
b64 = lambda raw: base64.b64encode(raw).decode()

# Funciones de main.py (sin FastAPI): se extraen del código real.
src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.py")).read()
tree = ast.parse(src); ns = {"s": s, "re": re}
for node in tree.body:
    if (isinstance(node, ast.FunctionDef) and node.name in ("sign_file_urls", "_file_user")) or \
       (isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "_FILE_URL_RE" for t in node.targets)):
        exec(compile(ast.Module([node], []), "main.py", "exec"), ns)
sign_file_urls, _file_user = ns["sign_file_urls"], ns["_file_user"]

admin = reg("padmin@sfera.org"); dueno = reg("pdueno@sfera.org"); socio = reg("psocio@sfera.org"); ajeno = reg("pajeno@sfera.org")
oid = s.create_org(dueno, "Comunidad de vecinos")["org_id"]
s.invite_member(dueno, oid, "psocio@sfera.org")
with db.session() as conn:
    check(s._is_org_member(conn, oid, socio["id"]), "el socio está en el censo de la organización")
pdid = s.create_debate("Obras del portal", "Cuerpo", "Vivienda", "Privado", dueno, org_id=oid)["debate_id"]
PDF = demo_files.pdf("Presupuesto", ["Tres presupuestos del portal."])
c = cd.add_doc(pdid, dueno, "estudio", "Presupuestos", "", "", file_name="presupuestos.pdf", data_b64=b64(PDF))
cid = c["id"] if "id" in c else c["doc"]["id"]

print("1) Enlace firmado")
t = s.make_file_token(socio["id"], "cdoc", cid)
check(s.parse_file_token(t, "cdoc", cid) == socio["id"], "válido para ese archivo y esa persona")
check(s.parse_file_token(t, "cdoc", cid + 1) is None, "no vale para otro archivo")
check(s.parse_file_token(t, "doc", cid) is None, "no vale para otro tipo de archivo")
uid_, exp_, mac_ = t.split(".")
check(s.parse_file_token(f"{ajeno['id']}.{exp_}.{mac_}", "cdoc", cid) is None, "no se puede cambiar la persona")
check(s.parse_file_token(f"{uid_}.{int(exp_) + 99999}.{mac_}", "cdoc", cid) is None, "no se puede alargar la caducidad")
check(s.parse_file_token(s.make_file_token(socio["id"], "cdoc", cid, ttl=-5), "cdoc", cid) is None, "caducado: no vale")
check(s.parse_file_token("basura", "cdoc", cid) is None and s.parse_file_token("", "cdoc", cid) is None, "enlace roto o vacío: no vale")

print("2) Abrir el archivo fuera de la app")
raw, name, ctype = cd.file_content(cid, _file_user(None, t, "cdoc", cid))
check(raw == PDF and ctype == "application/pdf", "socio con enlace firmado: abre el PDF del espacio privado")
expect_error(lambda: cd.file_content(cid, _file_user(None, "", "cdoc", cid)), 403, "sin sesión ni enlace: no se abre")
t_ajeno = s.make_file_token(ajeno["id"], "cdoc", cid)
expect_error(lambda: cd.file_content(cid, _file_user(None, t_ajeno, "cdoc", cid)), 403, "enlace firmado de alguien de fuera del censo: no se abre")
check(_file_user(socio, "basura", "cdoc", cid) is socio, "con sesión en la app, manda la sesión")

# documento de experto en un asunto privado
if s.get_debate(pdid, dueno).get("phase") != "deliberar": s.set_phase(pdid, "deliberar", admin)  # los privados empiezan en Deliberar
r = ds.create_document(pdid, admin, "informe", "Informe técnico", "file", None, "informe.pdf", "application/pdf", b64(PDF))
did_doc = r["document_id"]
expect_error(lambda: ds.file_content(did_doc), 403, "experto, asunto privado, sin sesión: YA NO se descarga (antes sí)")
td = s.make_file_token(socio["id"], "doc", did_doc)
check(ds.file_content(did_doc, None, _file_user(None, td, "doc", did_doc))[0] == PDF, "experto, asunto privado, socio con enlace: se abre")
check(ds.file_content(did_doc, 1, socio)[0] == PDF, "con versión (?v=1) y sesión: se abre")
# asunto público: sigue abierto a todos
pub = s.create_debate("Bancos en las paradas", "Cuerpo", "Movilidad", "Ayuntamiento", dueno)["debate_id"]
c2 = cd.add_doc(pub, dueno, "estudio", "Plano", "", "", file_name="plano.pdf", data_b64=b64(PDF))
cid2 = c2["id"] if "id" in c2 else c2["doc"]["id"]
check(cd.file_content(cid2, None)[0] == PDF, "asunto público: se abre sin sesión, como siempre")

print("3) Las respuestas llevan los enlaces firmados")
data = {"items": [{"file_url": f"/api/files/cdoc/{cid}"}, {"x": [{"file_url": f"/api/files/doc/{did_doc}?v=2"}]},
                  {"file_url": "https://otra.web/archivo.pdf"}, {"file_url": None}]}
out = sign_file_urls(data, socio["id"])
u1 = out["items"][0]["file_url"]; u2 = out["items"][1]["x"][0]["file_url"]
check(u1.startswith(f"/api/files/cdoc/{cid}?t=") and s.parse_file_token(u1.split("t=")[1], "cdoc", cid) == socio["id"], "file_url ciudadano firmado")
check(u2.startswith(f"/api/files/doc/{did_doc}?v=2&t=") and s.parse_file_token(u2.split("t=")[1], "doc", did_doc) == socio["id"], "file_url de experto firmado sin romper ?v=")
check(out["items"][2]["file_url"] == "https://otra.web/archivo.pdf" and out["items"][3]["file_url"] is None, "enlaces externos o vacíos: intactos")
check(sign_file_urls(out, socio["id"])["items"][0]["file_url"] == u1, "no se firma dos veces")
lista = cd.list_docs(pdid, socio)
firmada = sign_file_urls(lista, socio["id"])
fu = [x["file_url"] for x in firmada["items"] if x.get("file_url")]
check(fu and all("t=" in x for x in fu), "lista real de la biblioteca privada: todos los archivos con enlace firmado")
check(cd.file_content(cid, _file_user(None, fu[0].split("t=")[1], "cdoc", cid))[0] == PDF, "y ese enlace abre el archivo sin sesión")

print(f"\nRESULTADO enlaces privados v59: {PASSED} OK · {FAILED} fallos")
raise SystemExit(1 if FAILED else 0)
