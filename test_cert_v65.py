"""v65 — certificado digital REAL: CAs oficiales fijadas por huella, piloto sin CAs = rechazo,
puente @firma (storage/retrieve) y autoscript.js fijado. Ejecutar: python test_cert_v65.py"""
import datetime, hashlib, io, os, sys, tempfile, zipfile
os.environ.setdefault("SFERA_DB", os.path.join(tempfile.mkdtemp(), "t.db"))
import cert_service as cs
import afirma_bridge as afb
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

OK = 0
def check(c, m):
    global OK
    if not c:
        print("  ✗", m); sys.exit(1)
    OK += 1; print("  ✓", m)

def mkcert(name):
    k = ec.generate_private_key(ec.SECP256R1()); n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(k, hashes.SHA256()))
    return c

print("1) Formatos oficiales: DER, PEM y ZIP")
c = mkcert("CA prueba"); der = c.public_bytes(serialization.Encoding.DER); pem = c.public_bytes(serialization.Encoding.PEM)
check(cs._der_candidates(der) == [der], "DER (.cer de la FNMT)")
check(cs._der_candidates(pem) == [der], "PEM (.cer G2 de la FNMT, que viene en PEM)")
buf = io.BytesIO(); z = zipfile.ZipFile(buf, "w"); z.writestr("ACDNIE00X.crt", der); z.close()
check(cs._der_candidates(buf.getvalue()) == [der], "ZIP (DNIe)")

print("2) Descarga con huella: solo se instala si coincide la huella oficial")
tdir = tempfile.mkdtemp(); cs.TRUSTDIR = tdir
good, bad = mkcert("Buena"), mkcert("Impostora")
sha_good = hashlib.sha1(good.public_bytes(serialization.Encoding.DER)).hexdigest()
cs.OFFICIAL_CAS = [("dnie_ac_dnie_004.pem", "https://x/ok.zip", sha_good),
                   ("fnmt_ac_fnmt_usuarios.pem", "https://x/bad.cer", sha_good)]
import urllib.request
class R:
    def __init__(s, b): s.b = b
    def read(s, n=-1): return s.b
    def __enter__(s): return s
    def __exit__(s, *a): pass
def fake(req, timeout=0):
    url = req.full_url
    if url.endswith("ok.zip"):
        b = io.BytesIO(); zz = zipfile.ZipFile(b, "w"); zz.writestr("a.crt", good.public_bytes(serialization.Encoding.DER)); zz.close()
        return R(b.getvalue())
    return R(bad.public_bytes(serialization.Encoding.PEM))
urllib.request.urlopen = fake
res = cs.ensure_trust_store(force=True)
check(res["dnie_ac_dnie_004.pem"] == "ok", "CA con huella oficial: instalada")
check(res["fnmt_ac_fnmt_usuarios.pem"].startswith("error"), "CA con huella distinta: rechazada")
check(not os.path.exists(os.path.join(tdir, "fnmt_ac_fnmt_usuarios.pem")), "y no se escribe en el almacén")
check(cs._trust_files_ok() and len(cs._load_trust_roots()) == 1, "el almacén de confianza tiene la CA buena")
check(cs.ensure_trust_store()["skipped"], "no reintenta en bucle (10 min)")

print("3) Piloto SIN CAs: nadie se verifica")
cs.TRUSTDIR, cs.MODE = tempfile.mkdtemp(), "pilot"
cs.OFFICIAL_CAS = []
leaf = mkcert("Persona")
try:
    cs._validate_certificate(leaf, []); check(False, "debía rechazar")
except cs.CertError as e:
    check(e.code == 503, "sin almacén de confianza → 503 (antes bastaba la vigencia)")
st = cs.status()
check(st["real_enabled"] is False and "trustdir" not in st, "status: no habilitado y sin rutas internas")

print("4) Servidor intermedio @firma (protocolo oficial)")
check(afb.storage({"op": "check"}) == "OK" and afb.retrieve({"op": "check"}) == "OK", "op=check → OK")
check(afb.storage({"op": "put", "id": "abc123"}).startswith("ERR-20"), "sin versión → ERR-20")
check(afb.storage({"op": "put", "v": "1_0", "id": "../etc"}).startswith("ERR-06"), "id con ruta → ERR-06")
check(afb.storage({"op": "put", "v": "1_0", "id": "abc123", "dat": "CIFRADO=="}) == "OK", "put → OK")
check(afb.retrieve({"op": "get", "v": "1_0", "id": "abc123"}) == "CIFRADO==", "get → datos")
check(afb.retrieve({"op": "get", "v": "1_0", "id": "abc123"}).startswith("ERR-06"), "un solo uso: segunda vez ERR-06")
afb.storage({"op": "put", "v": "1_0", "id": "viejo1", "dat": "x"}); afb._store["viejo1"] = (0, "x")
check(afb.retrieve({"op": "get", "v": "1_0", "id": "viejo1"}).startswith("ERR-06"), "caducado → ERR-06")
check(afb.storage({"op": "del", "v": "1_0", "id": "abc123"}).startswith("ERR-01"), "operación desconocida → ERR-01")

print("5) autoscript.js fijado por huella")
afb._autoscript = None
afb._AUTOSCRIPT_CACHE = os.path.join(tempfile.mkdtemp(), "a.js")
urllib.request.urlopen = lambda url, timeout=0: R(b"alert('codigo no fijado')")
try:
    afb.autoscript(); check(False, "debía rechazar")
except RuntimeError:
    check(True, "fichero que no coincide con la huella: NO se sirve")

src = open(os.path.join(os.path.dirname(__file__), "main.py"), encoding="utf-8").read()
check('"/api/afirma/storage"' in src and '"/api/afirma/retrieve"' in src and '"/api/afirma/autoscript.js"' in src,
      "rutas del puente publicadas en la API")
print(f"\nOK — {OK} comprobaciones v65")
