"""Prueba SIN dependencias (stdlib) de las novedades v55:
  1) Archivos en la Biblioteca: tipos permitidos / bloqueados, contenido real, tamaño, vacíos.
  2) Quién puede subir qué, POR FASE y ROL (ciudadanía, quien convoca, expertos, admin).
  3) Biblioteca de solo lectura en Votar y Publicar (todo sigue visible).
  4) Bibliotecas POR PROPUESTA (ciudadana y experta), recuentos y vista «Por propuesta».
  5) Propuesta experta con DOCUMENTO FORMAL (y aviso si falta; añadirlo después; no duplicar).
  6) Descarga de archivos: bytes exactos, tipo decidido por el servidor, oculto por moderación → 404.
  7) Comprobante de voto (AB12-CD34) y panel «Comprobar la votación» (estado del recuento en palabras).
Ejecuta: python3 test_biblioteca_v55.py"""
import base64
import io
import json
import os
import secrets
import zipfile

DBP = "/tmp/sfera_test_biblioteca_v55.db"
os.environ["SFERA_DB"] = DBP
os.environ.setdefault("SFERA_ADMIN_EMAILS", "badmin@sfera.org")
if os.path.exists(DBP):
    os.remove(DBP)
import db; db.init_db()
import service as s, docs_service as ds, moderation as mod, citizen_docs as cd, uploads, demo_files
import crypto_core as cc, crypto_zk as zk
from crypto_core import P, G, Q

PASSED, FAILED = 0, 0


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


def b64(raw): return base64.b64encode(raw).decode()


def zipdoc(entries: dict) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        for k, v in entries.items():
            z.writestr(k, v)
    return bio.getvalue()


PDF = demo_files.pdf("Informe de prueba", ["Un párrafo con acentos: año, acción."])
PNG = demo_files.bar_chart_png([3, 5, 2])
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
DOCX = zipdoc({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>"})
XLSX = zipdoc({"[Content_Types].xml": "<Types/>", "xl/workbook.xml": "<workbook/>"})
PPTX = zipdoc({"[Content_Types].xml": "<Types/>", "ppt/presentation.xml": "<p/>"})
ODT = zipdoc({"mimetype": "application/vnd.oasis.opendocument.text", "content.xml": "<office/>"})
DOCX_MACRO = zipdoc({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w/>", "word/vbaProject.bin": "x"})

admin = reg("badmin@sfera.org")
autor = reg("bautor@sfera.org")
u = [reg(f"bu{i}@sfera.org") for i in range(4)]
nover = reg("bnover@sfera.org", verify=False)
experto = reg("bexperto@sfera.org")

# ─────────────────────────────────────────────────────────────────────────────
print("1) Archivos: tipos permitidos y bloqueados")
for name, raw in (("a.pdf", PDF), ("b.png", PNG), ("c.jpg", JPG), ("c2.JPEG", JPG), ("d.docx", DOCX),
                  ("e.xlsx", XLSX), ("f.pptx", PPTX), ("g.odt", ODT)):
    try:
        f = uploads.validate(name, b64(raw))
        check(f["size"] == len(raw) and f["mime_type"] == uploads.ALLOWED[uploads.ext_of(name)][0], f"permitido: {name}")
    except s.SferaError as e:
        check(False, f"permitido: {name} ({e.msg})")
for name, raw, why in (("x.html", b"<html><script>alert(1)</script>", "html"),
                       ("x.js", b"alert(1)", "js"), ("x.svg", b"<svg onload=alert(1)></svg>", "svg"),
                       ("x.exe", b"MZ\x90\x00", "exe"), ("x", PDF, "sin extensión"),
                       ("x.docm", DOCX, "Word con macros (.docm)")):
    expect_error(lambda: uploads.validate(name, b64(raw)), 415, f"bloqueado: {why}", "no se admite")
expect_error(lambda: uploads.validate("falso.pdf", b64(b"<html>no soy un pdf</html>")), 415,
             "bloqueado: .pdf que no es un PDF (contenido real)", "no es lo que dice ser")
expect_error(lambda: uploads.validate("falso.png", b64(PDF)), 415, "bloqueado: .png que es otra cosa")
expect_error(lambda: uploads.validate("macro.docx", b64(DOCX_MACRO)), 415, "bloqueado: .docx con macros")
expect_error(lambda: uploads.validate("v.pdf", ""), 400, "archivo vacío")
expect_error(lambda: uploads.validate("v.pdf", "%%%no-base64%%%"), 400, "archivo ilegible")
_old = uploads.MAX_FILE_BYTES
uploads.MAX_FILE_BYTES = 1000
expect_error(lambda: uploads.validate("grande.pdf", b64(b"%PDF-1.4\n" + b"0" * 2000)), 413, "demasiado grande", "MB")
uploads.MAX_FILE_BYTES = _old
check(uploads.safe_name("../../etc/pas<s>wd.pdf") == "passwd.pdf", "nombre de archivo saneado (sin rutas ni caracteres raros)")
check(uploads.serve_type("viejo.html") == "application/octet-stream", "un archivo antiguo no permitido se sirve como binario genérico")
h = uploads.headers_for("Informe año.pdf")
check(h["Content-Disposition"].startswith("attachment;") and h["X-Content-Type-Options"] == "nosniff"
      and "sandbox" in h["Content-Security-Policy"], "descarga segura: adjunto + nosniff + CSP sandbox")

# ─────────────────────────────────────────────────────────────────────────────
print("2) Quién sube qué, por fase")
did = s.create_debate("Bancos a la sombra en las paradas", "Cuerpo", "Movilidad", "Ayuntamiento", autor)["debate_id"]
ds_lib = s.get_debate(did, u[0])["library"]
check(ds_lib["citizen_issue"] and not ds_lib["expert_issue"] and not ds_lib["read_only"], "Convocar: reglas de biblioteca (ciudadanía sí, expertos no)")
r = cd.add_doc(did, autor, "estudio", "Por qué importa", "Resumen", "", file_name="resumen.pdf", data_b64=b64(PDF))
check(r["ok"] and r["file"]["file_type"] == "PDF", "Convocar: quien convoca sube un PDF")
r2 = cd.add_doc(did, u[0], "dato", "Foto de la parada", "", "", file_name="parada.png", data_b64=b64(PNG))
check(r2["ok"], "Convocar: otra persona registrada sube una imagen")
cd.add_doc(did, u[1], "noticia", "Fuente oficial", "", "https://www.ine.es/")
expect_error(lambda: cd.add_doc(did, nover, "dato", "Sin verificar", "x"), 403, "Convocar: sin email verificado no", "Verifica")
expect_error(lambda: ds.create_document(did, admin, "informe", "Informe", "text", "x"), 409,
             "Convocar: los expertos aún no publican", "a partir de la fase Deliberar")
expect_error(lambda: cd.add_doc(did, u[0], "dato", "Archivo HTML", "", "", file_name="x.html", data_b64=b64(b"<html>")), 415,
             "Convocar: archivo HTML rechazado")
s.set_phase(did, "deliberar", admin)
import docs_service
docs_service.assign_expert(did, "bexperto@sfera.org", admin)
check(cd.add_doc(did, u[2], "estudio", "Estudio en Word", "", "", file_name="estudio.docx", data_b64=b64(DOCX))["ok"],
      "Deliberar: ciudadanía sube un Word")
rd = ds.create_document(did, experto, "datos", "Datos de uso", "file", None, "datos.xlsx", "text/html", b64(XLSX))
check(bool(rd["document_id"]), "Deliberar: experto asignado sube un Excel")
lst = ds.list_documents(did)
xl = next(d for d in lst if d["id"] == rd["document_id"])
check(xl["latest_version"]["file_url"] == f"/api/files/doc/{rd['document_id']}" and xl["latest_version"]["file_type"] == "Excel"
      and xl["latest_version"]["size"] == len(XLSX), "lista de expertos: enlace de descarga, tipo llano y tamaño (sin el contenido)")
check("data_b64" not in json.dumps(lst), "la lista nunca incluye el contenido del archivo")
expect_error(lambda: ds.create_document(did, u[0], "informe", "Yo no soy experto", "text", "x"), 403,
             "Deliberar: una persona sin rol de experto no publica documentos de expertos")
expect_error(lambda: ds.create_document(did, experto, "informe", "Malo", "file", None, "x.svg", "image/svg+xml",
                                        b64(b"<svg/>")), 415, "Deliberar: experto tampoco puede subir SVG")
raw, name, ctype = ds.file_content(rd["document_id"])
check(raw == XLSX and name == "datos.xlsx" and ctype == uploads.ALLOWED["xlsx"][0],
      "descarga de experto: bytes exactos y tipo decidido por el servidor (no el que mandó el navegador)")
ds.add_contribution(rd["document_id"], u[0], "comentario", "Gracias por los datos")
s.set_phase(did, "proponer", admin)
check(cd.add_doc(did, u[3], "dato", "Dato en Proponer", "Texto")["ok"], "Proponer: aún se aceptan documentos del asunto")

# ─────────────────────────────────────────────────────────────────────────────
print("3) Bibliotecas por propuesta (ciudadana)")
p1 = s.add_proposal(did, u[0]["id"], "Bancos con sombra en las 20 paradas más usadas")["id"]
p2 = s.add_proposal(did, u[1]["id"], "Marquesinas nuevas")["id"]
rp = cd.add_doc(did, u[0], "estudio", "Mi propuesta detallada", "", "", file_name="propuesta.pdf", data_b64=b64(PDF), proposal_id=p1)
check(rp["ok"] and rp["proposal_id"] == p1, "Proponer: su autor/a adjunta un PDF a su propuesta")
check(cd.add_doc(did, u[0], "enlace", "Fuente", "", "https://datos.gob.es/", proposal_id=p1)["ok"], "y un enlace")
expect_error(lambda: cd.add_doc(did, u[2], "dato", "No es mía", "x", proposal_id=p1), 403,
             "otra persona NO puede añadir documentos a una propuesta ajena", "Solo quien presentó")
expect_error(lambda: cd.add_doc(did, u[0], "dato", "Propuesta de otro asunto", "x", proposal_id=999999), 404,
             "propuesta inexistente")
lp = cd.list_proposal_docs(p1, u[0])
check(len(lp["items"]) == 2 and lp["can_add"] and lp["proposal"]["mine"], "biblioteca de la propuesta: 2 documentos, su autor/a puede añadir")
check(not cd.list_proposal_docs(p1, u[2])["can_add"] and not cd.list_proposal_docs(p1, None)["can_add"],
      "otra persona / anónimo: solo lectura")
check(cd.list_docs(did, scope="issue")["total"] == 5 and cd.list_docs(did)["total"] == 7,
      "biblioteca del asunto: 'issue' excluye los de propuestas (5 vs 7 en total)")
props = s.get_debate(did, u[0])["proposals"]
check(next(p for p in props if p["id"] == p1)["docs_count"] == 2 and next(p for p in props if p["id"] == p2)["docs_count"] == 0,
      "ficha: cada propuesta ciudadana trae su nº de documentos")

print("4) Propuesta experta con documento formal")
e1 = s.add_expert_proposal(did, experto, "Bancos con pérgola", "Resumen de la propuesta.", "Basada en p1",
                           formal_file_name="propuesta-formal.pdf", formal_data_b64=b64(PDF))
check(e1["formal_doc_id"] and not e1["formal_doc_missing"], "propuesta experta creada CON su documento formal (misma operación)")
e2 = s.add_expert_proposal(did, admin, "Marquesinas con techo verde", "Resumen B.")
check(e2["formal_doc_missing"], "sin documento formal (web anterior): se crea pero queda marcada «Falta el documento formal»")
expect_error(lambda: s.add_expert_proposal(did, experto, "Con archivo malo", "x", formal_file_name="x.html",
                                           formal_data_b64=b64(b"<html>")), 415, "documento formal HTML rechazado (y no se crea la propuesta)")
check(len(s.get_debate(did, None)["expert_proposals"]) == 2, "la propuesta con archivo rechazado no se creó")
eps = {e["id"]: e for e in s.get_debate(did, None)["expert_proposals"]}
check(eps[e1["id"]]["formal_doc"]["file_url"].startswith("/api/files/doc/") and eps[e1["id"]]["docs_count"] == 1,
      "ficha: propuesta experta con «Documento de la propuesta» (enlace de descarga)")
check(eps[e2["id"]]["formal_doc_missing"] is True and eps[e2["id"]]["formal_doc"] is None, "ficha: aviso de documento formal que falta")
rf = ds.create_document(did, admin, "anexo", "Documento formal B", "file", None, "b.odt", "", b64(ODT),
                        expert_proposal_id=e2["id"], formal=True)
check(rf["is_formal"], "se añade después el documento formal que faltaba (Proponer)")
expect_error(lambda: ds.create_document(did, admin, "anexo", "Otro formal", "file", None, "c.pdf", "", b64(PDF),
                                        expert_proposal_id=e2["id"], formal=True), 409, "no se duplica el documento formal")
ds.create_document(did, experto, "anexo", "Plano de las paradas", "file", None, "plano.png", "", b64(PNG),
                   expert_proposal_id=e1["id"])
lib = ds.list_expert_proposal_docs(e1["id"], experto)
check(lib["formal_doc"] and len(lib["items"]) == 1 and lib["can_add"], "biblioteca de la propuesta experta: formal + 1 anexo; el experto puede añadir")
check(not ds.list_expert_proposal_docs(e1["id"], u[0])["can_add"], "una persona sin rol de experto: solo lectura")
expect_error(lambda: ds.create_document(did, u[0], "anexo", "Intruso", "text", "x", expert_proposal_id=e1["id"]), 403,
             "la ciudadanía no puede añadir documentos a una propuesta experta")
idx = s.proposal_docs_index(did)
check(len(idx["expert"]) == 2 and all(not x["formal_doc_missing"] for x in idx["expert"])
      and [c["id"] for c in idx["citizen"]] == [p1], "vista «Por propuesta»: 2 expertas (con su formal) y 1 ciudadana con documentos")
iss = [d for d in ds.list_documents(did) if not d.get("expert_proposal_id")]
check(len(iss) == 1, "documentos de expertos del asunto separados de los de propuestas")

# ─────────────────────────────────────────────────────────────────────────────
print("5) Votar / Publicar: solo lectura, todo visible")


def votar(eid, user, chosen):
    pub = s.election_public(eid); H = int(pub["elgamal_pub"]["h"])
    bpub = cc.BlindPubKey(int(pub["blind_pub"]["open"]["n"]), int(pub["blind_pub"]["open"]["e"]))
    token = secrets.token_bytes(32); blinded, rr = cc.BlindSigner.blind(bpub, token)
    sig = cc.BlindSigner.unblind(bpub, int(s.issue_credential(eid, user, str(blinded), "open")["blind_sig"]), rr)
    ballot, ys, bps = [], [], []
    for i in range(len(pub["options"])):
        b = 1 if i == chosen else 0; y = secrets.randbelow(Q - 2) + 2
        c1, c2 = pow(G, y, P), (pow(G, b, P) * pow(H, y, P)) % P
        ballot.append({"c1": str(c1), "c2": str(c2)}); ys.append(y); bps.append(zk.prove_bit(H, c1, c2, y, b))
    C1, C2 = zk.combine_ballot([(int(b["c1"]), int(b["c2"])) for b in ballot])
    return s.cast_vote(eid, token.hex(), str(sig), ballot, bps, zk.prove_sum_one(H, C1, C2, sum(ys) % Q), "open")


s.set_phase(did, "votar", admin)
g = s.get_debate(did, u[0])
check(g["library"]["read_only"] and not g["library"]["citizen_issue"], "Votar: reglas = solo lectura")
expect_error(lambda: cd.add_doc(did, u[0], "dato", "Tarde", "x"), 409, "Votar: ciudadanía no añade al asunto", "votación ya ha empezado")
expect_error(lambda: cd.add_doc(did, u[0], "dato", "Tarde", "x", proposal_id=p1), 409, "Votar: ni a su propuesta", "fase Proponer")
expect_error(lambda: ds.create_document(did, experto, "informe", "Tarde", "text", "x"), 409, "Votar: expertos tampoco", "votación está abierta")
expect_error(lambda: ds.create_document(did, admin, "anexo", "Tarde", "text", "x", expert_proposal_id=e1["id"]), 409,
             "Votar: ni en una propuesta experta", "fase Proponer")
expect_error(lambda: ds.add_version(rd["document_id"], experto, "text", "v2"), 409, "Votar: no hay versiones nuevas")
expect_error(lambda: ds.add_contribution(rd["document_id"], u[1], "comentario", "tarde"), 409, "Votar: no se comenta")
eid = g["election"]["id"]
v1 = votar(eid, u[0], 0); v2 = votar(eid, u[1], 1)
check(len(v1["code"]) == 9 and v1["code"][4] == "-" and v1["code"].replace("-", "") == v1["entry_hash"][:8].upper(),
      f"comprobante legible al votar: {v1['code']}")
c = s.check_receipt(eid, v1["code"])
check(c["found"] and c["position"] == 1 and c["total"] == 2, "comprobar mi voto: «está en la urna (nº 1 de 2)»")
check(s.check_receipt(eid, v2["code"].lower().replace("-", ""))["position"] == 2, "acepta minúsculas y sin guion")
check(s.check_receipt(eid, v2["entry_hash"])["found"], "acepta la huella completa")
check(not s.check_receipt(eid, "0000-0000")["found"], "un comprobante que no existe: no encontrado")
expect_error(lambda: s.check_receipt(eid, "AB12"), 400, "comprobante incompleto", "8 letras")
expect_error(lambda: s.check_receipt(999999, "AB12-CD34"), 404, "votación inexistente")
a = s.audit(eid)
check(a["estado_recuento"] == "pendiente" and a["recuento_reproducible"] is None and a["estado_votacion"] == "abierta"
      and a["votos"] == 2 and a["cadena_integra"], "panel abierto: recuento «pendiente» (no «null»), 2 votos, urna íntegra")
s.close_election(eid, admin)
a = s.audit(eid)
check(a["estado_recuento"] == "coincide" and a["estado_votacion"] == "cerrada" and a["votos_por_via"]["open"] == 2,
      "panel cerrado: el recuento se ha repetido y coincide")
check(s.check_receipt(eid, v1["code"])["found"], "tras publicar, el comprobante sigue encontrándose")
g = s.get_debate(did, None)
check(g["phase"] == "publicar" and g["library"]["read_only"], "Publicar: solo lectura")
check(len(cd.list_proposal_docs(p1, None)["items"]) == 2 and ds.list_expert_proposal_docs(e1["id"])["formal_doc"],
      "Publicar: las bibliotecas de cada propuesta siguen visibles para siempre")
expect_error(lambda: cd.add_doc(did, u[0], "dato", "Tarde", "x"), 409, "Publicar: no se añade nada")

# ─────────────────────────────────────────────────────────────────────────────
print("6) Descargas y moderación de archivos")
raw, name, ctype = cd.file_content(r["id"])
check(raw == PDF and name == "resumen.pdf" and ctype == "application/pdf", "descarga ciudadana: bytes exactos y tipo PDF")
expect_error(lambda: cd.file_content(999999), 404, "archivo inexistente")
for rep_u in (u[1], u[2], u[3]):      # tres personas distintas (no su autor/a) → se oculta sola
    try: mod.report_content(rep_u, "citizen_doc", r2["id"], "ofensivo", "")
    except s.SferaError: pass
expect_error(lambda: cd.file_content(r2["id"]), 404, "archivo ocultado por denuncias: ya no se descarga")
check(all(x["id"] != r2["id"] for x in cd.list_docs(did)["items"]), "y desaparece de la lista")
mod.resolve(admin, "document", rd["document_id"], "hide")
expect_error(lambda: ds.file_content(rd["document_id"]), 404, "documento de experto ocultado por moderación: no se descarga")
check(all(x["id"] != rd["document_id"] for x in ds.list_documents(did)), "ni se lista")

print("7) Límite de archivos por persona y día")
d2 = s.create_debate("Otro asunto para el límite", "", "Movilidad", "Ayuntamiento", autor)["debate_id"]
_old = uploads.MAX_FILES_PER_DAY
uploads.MAX_FILES_PER_DAY = 2
cd.add_doc(d2, u[3], "dato", "Archivo 1", "", "", file_name="1.png", data_b64=b64(PNG))
cd.add_doc(d2, u[3], "dato", "Archivo 2", "", "", file_name="2.png", data_b64=b64(PNG))
expect_error(lambda: cd.add_doc(d2, u[3], "dato", "Archivo 3", "", "", file_name="3.png", data_b64=b64(PNG)), 429,
             "3er archivo del día: límite alcanzado", "Inténtalo mañana")
check(cd.add_doc(d2, u[3], "dato", "Solo texto", "Sin archivo")["ok"], "sin archivo sí puede seguir aportando")
uploads.MAX_FILES_PER_DAY = _old

print(f"\nRESULTADO biblioteca v55: {PASSED} OK · {FAILED} fallos")
raise SystemExit(1 if FAILED else 0)
