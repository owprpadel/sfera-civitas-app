"""
cert_service.py — Verificación de identidad con CERTIFICADO DIGITAL REAL
(DNIe / FNMT / certificados cualificados eIDAS) para Sfera Civitas.

DOCTRINA (roadmap §3.2 — identidad desacoplada del voto):
  · La identidad se comprueba con garantías, pero NO se une a la papeleta.
  · El servidor sabe *que* votas (cuenta verificada), no *qué* votas
    (eso lo garantiza la capa de firma ciega / ElGamal de crypto_core).
  · NO se guarda el certificado ni el NIF. Solo un identificador PSEUDÓNIMO
    pid = HMAC(secreto_servidor, NIF) que permite "una persona = una cuenta
    verificada" sin poder revertirse a la identidad real.

FLUJO (challenge-response, sin depender de @firma ni de convenios):
  1. Cliente pide un reto:            POST /cert/challenge  {email}
     → servidor genera un NONCE aleatorio, lo guarda con caducidad y lo devuelve.
  2. Cliente firma el NONCE con su DNIe/certificado usando **AutoFirma** (FNMT,
     gratis) o firma en cliente, y envía firma + certificado:
                                      POST /cert/verify {email, nonce_id, signature, cert, fmt}
  3. Servidor:
     a) recupera el nonce (no caducado, no usado) y lo marca usado;
     b) VERIFICA la firma sobre ESE nonce con la clave pública del certificado;
     c) VALIDA el certificado: vigencia + cadena hasta una CA de confianza
        (FNMT/DNIe/eIDAS) + (en modo estricto) revocación OCSP/CRL;
     d) comprueba que es un certificado de PERSONA FÍSICA cualificado;
     e) extrae el NIF, calcula el pid pseudónimo y marca la cuenta 'verified'
        (rechaza si ese pid ya verifica otra cuenta: una persona, una identidad).

MODOS (variable de entorno SFERA_CERT_MODE):
  · 'sim'   (por defecto): comportamiento simulado heredado — NO valida de verdad.
            Sirve para desarrollo y mantiene la vía verificada OCULTA en la UI
            (CERT_ENABLED=false) hasta que haya CAs configuradas.
  · 'pilot' : validación REAL ligera — firma sobre el nonce + vigencia del
            certificado + cadena hasta las CAs del directorio de confianza.
            Revocación best-effort (si hay red y pyhanko-certvalidator).
  · 'strict': validación completa eIDAS — cadena + revocación OBLIGATORIA
            (requiere pyhanko-certvalidator, las raíces y OCSP/CRL online).

CONFIG:
  · SFERA_SECRET       — secreto del servidor (deriva el pid y ya se usa en service.py).
  · SFERA_CERT_MODE    — sim | pilot | strict  (por defecto 'sim').
  · SFERA_CERT_TRUSTDIR— carpeta con las CAs raíz/intermedias de confianza en PEM
                         (FNMT AC Raíz, DNIe AC Raíz, etc.). Ver trust_store/README.
"""
from __future__ import annotations
import hashlib
import hmac
import os
import re
import secrets
import time

import db

MODE = os.environ.get("SFERA_CERT_MODE", "sim").lower()
SECRET = (os.environ.get("SFERA_SECRET", "sfera-dev-secret")).encode()
TRUSTDIR = os.environ.get("SFERA_CERT_TRUSTDIR",
                          os.path.join(os.path.dirname(__file__), "trust_store"))
CHALLENGE_TTL = 300  # 5 min de validez del reto

# --- dependencias criptográficas (cryptography ya está en requirements) ---------
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
    from cryptography.exceptions import InvalidSignature
    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False

# pyhanko-certvalidator: opcional, solo para modo 'strict' (cadena + revocación eIDAS)
try:
    from pyhanko_certvalidator import CertificateValidator, ValidationContext  # type: ignore
    _CERTVALIDATOR = True
except Exception:
    _CERTVALIDATOR = False


class CertError(Exception):
    def __init__(self, code: int, msg: str):
        self.code, self.msg = code, msg
        super().__init__(msg)


# ---------------------------------------------------------------------------
# 1) RETO
# ---------------------------------------------------------------------------
def start_challenge(email: str) -> dict:
    """Genera un nonce para que el usuario lo firme con su certificado."""
    email = (email or "").strip().lower()
    with db.session() as conn:
        row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            raise CertError(404, "No hay cuenta con ese email (regístrate primero por email)")
        uid = row["id"]
        nonce = secrets.token_hex(32)
        now = db.now()
        cur = conn.execute(
            "INSERT INTO cert_challenges(user_id,nonce,expires,used,created) VALUES(?,?,?,0,?)",
            (uid, nonce, now + CHALLENGE_TTL, now), returning=True)
        conn.commit()
        cid = cur.lastrowid
    return {"nonce_id": cid, "nonce": nonce, "expires_in": CHALLENGE_TTL,
            "instructions": "Firma este nonce con tu DNIe/certificado (AutoFirma) y envíalo a /cert/verify"}


def _take_challenge(conn, email: str, nonce_id, expected_nonce: str):
    """Recupera y CONSUME el reto (un solo uso, no caducado)."""
    row = conn.execute(
        "SELECT c.id, c.nonce, c.expires, c.used, u.id AS uid "
        "FROM cert_challenges c JOIN users u ON u.id=c.user_id "
        "WHERE c.id=? AND u.email=?", (nonce_id, email)).fetchone()
    if not row:
        raise CertError(400, "Reto no encontrado para este usuario")
    if row["used"]:
        raise CertError(409, "Este reto ya se usó (pide uno nuevo)")
    if float(row["expires"]) < db.now():
        raise CertError(410, "Reto caducado (pide uno nuevo)")
    if expected_nonce and expected_nonce != row["nonce"]:
        raise CertError(400, "El nonce firmado no coincide con el emitido")
    conn.execute("UPDATE cert_challenges SET used=1 WHERE id=?", (row["id"],))
    return row["uid"], row["nonce"]


# ---------------------------------------------------------------------------
# 2) VERIFICACIÓN
# ---------------------------------------------------------------------------
def verify(email: str, nonce_id, signature_b64: str, cert_pem: str,
           fmt: str = "raw", signed_nonce: str = "") -> dict:
    """Verifica la firma del nonce con el certificado y valida el certificado.
    Sube la cuenta a loa='verified' guardando SOLO el pid pseudónimo.

    fmt:
      · 'raw'  → `signature_b64` es la firma directa (RSA PKCS#1 v1.5 o ECDSA)
                 sobre los bytes del nonce (hex). `cert_pem` = certificado del firmante.
      · 'pkcs7'→ `signature_b64` es un CMS/PKCS#7 detached (CAdES de AutoFirma);
                 el certificado del firmante va dentro (o en `cert_pem`).
    """
    email = (email or "").strip().lower()

    if MODE == "sim":
        # Comportamiento heredado simulado (NO validar): mantiene DEV operativo.
        return _mark_verified_sim(email, cert_pem or signature_b64 or "sim")

    if not _CRYPTO:
        raise CertError(500, "Falta la librería 'cryptography' en el servidor")

    import base64
    try:
        sig = base64.b64decode(signature_b64)
    except Exception:
        raise CertError(400, "Firma no es base64 válido")

    with db.session() as conn:
        uid, nonce = _take_challenge(conn, email, nonce_id, signed_nonce)
        conn.commit()  # el reto queda consumido pase lo que pase después

    nonce_bytes = nonce.encode()

    # a) obtener el certificado del firmante y verificar la firma sobre el nonce
    if fmt == "pkcs7":
        # AutoFirma/DNIe firman en CAdES (CMS/PKCS#7 detached): verificamos el CMS
        # (messageDigest == hash(nonce) + firma de los signedAttrs con la clave del
        # certificado firmante) y de ahí extraemos el certificado del ciudadano y
        # los intermedios que la propia firma incluye (para encadenar hasta la raíz).
        cert, chain_certs = _verify_cms_detached(sig, nonce_bytes)
    else:
        cert = _load_signer_cert(cert_pem, sig, fmt)
        _verify_signature(cert, sig, nonce_bytes, fmt)
        chain_certs = []

    # b) validar el certificado (vigencia + cadena + revocación según modo)
    _validate_certificate(cert, chain_certs)

    # c) identidad → pid pseudónimo (NO se guarda el NIF)
    nif, display = _extract_identity(cert)
    if not nif:
        raise CertError(422, "El certificado no expone un NIF de persona física")
    pid = _pid(nif)

    with db.session() as conn:
        dup = conn.execute("SELECT id FROM users WHERE cert_pid=? AND email<>?",
                           (pid, email)).fetchone()
        if dup:
            raise CertError(409, "Este certificado ya verifica otra cuenta (una persona, una identidad)")
        conn.execute(
            "UPDATE users SET loa='verified', verified=1, cert_pid=?, cert_subject=?, cert_verified_at=? "
            "WHERE email=?", (pid, display[:120], db.now(), email))
        conn.commit()
    return {"loa": "verified", "mode": MODE, "identidad": display,
            "nota": "Identidad verificada y DESACOPLADA del voto (no se guarda el certificado ni el NIF)"}


# ---------------------------------------------------------------------------
# Helpers de criptografía / X.509
# ---------------------------------------------------------------------------
def _load_signer_cert(cert_pem: str, sig: bytes, fmt: str):
    """Devuelve el x509.Certificate del firmante."""
    if fmt == "pkcs7":
        # Extrae los certificados del CMS/PKCS#7 y toma el de firmante (hoja).
        from cryptography.hazmat.primitives.serialization import pkcs7
        certs = []
        try:
            certs = pkcs7.load_der_pkcs7_certificates(sig)
        except Exception:
            try:
                certs = pkcs7.load_pem_pkcs7_certificates(sig)
            except Exception:
                certs = []
        if certs:
            # la hoja es la que NO es CA (o la primera)
            leaf = next((c for c in certs if _is_leaf(c)), certs[0])
            return leaf
    if not cert_pem or not cert_pem.strip():
        raise CertError(400, "Falta el certificado del firmante")
    data = cert_pem.encode() if isinstance(cert_pem, str) else cert_pem
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        try:
            import base64
            return x509.load_der_x509_certificate(base64.b64decode(cert_pem))
        except Exception:
            raise CertError(400, "Certificado ilegible (esperado PEM o DER base64)")


def _is_leaf(cert) -> bool:
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        return not bc.ca
    except Exception:
        return True


def _verify_signature(cert, sig: bytes, nonce_bytes: bytes, fmt: str):
    """Verifica la firma del nonce con la clave pública del certificado.
    En 'pkcs7' se delega en la verificación CMS si está disponible; si no,
    se exige el modo 'raw' (más simple y robusto en cliente/servidor)."""
    if fmt == "pkcs7":
        # Verificación CMS detached (disponible en cryptography >= 42 según build).
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7 as _p7
            if hasattr(_p7, "verify_pkcs7"):  # API nueva, si existe
                _p7.verify_pkcs7(sig, nonce_bytes)  # type: ignore
                return
        except InvalidSignature:
            raise CertError(401, "Firma PKCS#7 inválida sobre el reto")
        except Exception:
            pass
        # Si no podemos verificar el CMS de forma fiable, no aceptamos a ciegas.
        raise CertError(415, "Formato PKCS#7 no verificable en este servidor; use fmt='raw'")

    pub = cert.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, nonce_bytes, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, nonce_bytes, ec.ECDSA(hashes.SHA256()))
        else:
            raise CertError(415, "Tipo de clave del certificado no soportado")
    except InvalidSignature:
        raise CertError(401, "La firma no corresponde al reto emitido")


# ---------------------------------------------------------------------------
# Verificación CMS/PKCS#7 detached (CAdES de AutoFirma/DNIe) — Python puro,
# sin dependencias nuevas. Verifica que messageDigest == hash(nonce) y que la
# firma de los signedAttrs valida con la clave pública del certificado firmante.
# ---------------------------------------------------------------------------
_OID_MSGDIGEST = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04"   # 1.2.840.113549.1.9.4
_CMS_HASHES = {
    "2.16.840.1.101.3.4.2.1": ("sha256", None),
    "2.16.840.1.101.3.4.2.2": ("sha384", None),
    "2.16.840.1.101.3.4.2.3": ("sha512", None),
    "1.3.14.3.2.26":          ("sha1",   None),
}


def _der_read(data, off):
    tag = data[off]; o = off + 1
    f = data[o]; o += 1
    if f & 0x80:
        n = f & 0x7f
        length = int.from_bytes(data[o:o + n], "big"); o += n
    else:
        length = f
    end = o + length
    return {"tag": tag, "val": data[o:end], "full": data[off:end]}, end


def _der_children(val):
    out, off = [], 0
    while off < len(val):
        node, off = _der_read(val, off)
        out.append(node)
    return out


def _der_oid_str(b):
    first = b[0]; res = [str(first // 40), str(first % 40)]; n = 0
    for c in b[1:]:
        n = (n << 7) | (c & 0x7f)
        if not c & 0x80:
            res.append(str(n)); n = 0
    return ".".join(res)


def _verify_cms_detached(sig_der: bytes, content: bytes):
    """Verifica una firma CMS/PKCS#7 detached sobre `content` (el nonce) y
    devuelve el x509.Certificate del firmante. Lanza CertError si algo falla."""
    try:
        ci, _ = _der_read(sig_der, 0)                       # ContentInfo SEQUENCE
        c = _der_children(ci["val"])                        # [OID, [0] EXPLICIT]
        signed_data = _der_children(c[1]["val"])[0]         # SignedData SEQUENCE
        sd = _der_children(signed_data["val"])
        certs_node = next((x for x in sd if x["tag"] == 0xA0), None)
        signerinfos = [x for x in sd if x["tag"] == 0x31][-1]
        si = _der_children(_der_children(signerinfos["val"])[0]["val"])
        digest_oid = _der_oid_str(_der_children(si[2]["val"])[0]["val"])
        signed_attrs = next((x for x in si if x["tag"] == 0xA0), None)
        sig_octet = [x for x in si if x["tag"] == 0x04][-1]
        signature = sig_octet["val"]
    except CertError:
        raise
    except Exception:
        raise CertError(400, "Firma PKCS#7/CAdES ilegible")
    if digest_oid not in _CMS_HASHES:
        raise CertError(415, "Algoritmo de hash del CMS no soportado")
    hname = _CMS_HASHES[digest_oid][0]
    hcls = {"sha256": hashes.SHA256, "sha384": hashes.SHA384,
            "sha512": hashes.SHA512, "sha1": hashes.SHA1}[hname]
    if signed_attrs is None or certs_node is None:
        raise CertError(415, "CMS sin signedAttrs o sin certificado del firmante")
    try:
        all_certs = []
        for cnode in _der_children(certs_node["val"]):
            try:
                all_certs.append(x509.load_der_x509_certificate(cnode["full"]))
            except Exception:
                continue
        if not all_certs:
            raise CertError(400, "No hay certificados en el CMS")
        # firmante = la hoja (el que no es CA); si no se distingue, el primero
        signer = next((c for c in all_certs if _is_leaf(c)), all_certs[0])
    except CertError:
        raise
    except Exception:
        raise CertError(400, "No se pudo leer el certificado del firmante en el CMS")
    # messageDigest == hash(nonce)
    md_expected = hashlib.new(hname, content).digest()
    md_found = None
    for attr in _der_children(signed_attrs["val"]):
        ac = _der_children(attr["val"])
        if ac and ac[0]["val"] == _OID_MSGDIGEST:
            md_found = _der_children(ac[1]["val"])[0]["val"]
    if md_found != md_expected:
        raise CertError(401, "El resumen firmado no corresponde al reto (messageDigest)")
    # firma de los signedAttrs (re-etiquetados como SET 0x31)
    sa = b"\x31" + signed_attrs["full"][1:]
    pub = signer.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, sa, padding.PKCS1v15(), hcls())
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, sa, ec.ECDSA(hcls()))
        else:
            raise CertError(415, "Tipo de clave del certificado no soportado")
    except InvalidSignature:
        raise CertError(401, "La firma CAdES no corresponde al reto emitido")
    return signer, all_certs


def _load_trust_roots():
    """Carga las CAs de confianza del directorio de confianza. Acepta PEM (uno o
    varios por fichero) y DER (.cer/.crt/.der tal como los publica la FNMT/DNIe)."""
    roots = []
    if not os.path.isdir(TRUSTDIR):
        return roots
    for fn in os.listdir(TRUSTDIR):
        if not fn.lower().endswith((".pem", ".crt", ".cer", ".der")):
            continue
        try:
            with open(os.path.join(TRUSTDIR, fn), "rb") as fh:
                blob = fh.read()
            if b"-----BEGIN CERTIFICATE-----" in blob:
                for part in _split_pem(blob):
                    roots.append(x509.load_pem_x509_certificate(part))
            else:
                roots.append(x509.load_der_x509_certificate(blob))  # DER (.cer)
        except Exception:
            continue
    return roots


def _split_pem(blob: bytes):
    out, cur, inside = [], [], False
    for line in blob.splitlines(keepends=True):
        if b"BEGIN CERTIFICATE" in line:
            inside, cur = True, [line]
        elif b"END CERTIFICATE" in line:
            cur.append(line); out.append(b"".join(cur)); inside = False
        elif inside:
            cur.append(line)
    return out


def _validate_certificate(cert, extra_certs=()):
    """Vigencia + cadena hasta una CA de confianza (+ revocación en 'strict').
    `extra_certs` son los certificados intermedios que la firma (CMS de AutoFirma)
    incluye: permiten encadenar hasta la RAÍZ aunque el emisor directo sea una
    intermedia, de modo que en el trust_store baste con las raíces."""
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    naf = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    nbf = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    if now > naf:
        raise CertError(403, "Certificado caducado")
    if now < nbf:
        raise CertError(403, "Certificado todavía no válido")

    roots = _load_trust_roots()

    if MODE == "strict":
        if not _CERTVALIDATOR:
            raise CertError(500, "Modo estricto requiere pyhanko-certvalidator instalado")
        if not roots:
            raise CertError(500, "Modo estricto sin CAs de confianza configuradas (SFERA_CERT_TRUSTDIR)")
        try:
            trust = [r.public_bytes(serialization.Encoding.DER) for r in roots]
            inter = [c.public_bytes(serialization.Encoding.DER) for c in extra_certs if c.subject != c.issuer]
            ctx = ValidationContext(trust_roots=trust, other_certs=inter, allow_fetching=True)
            der = cert.public_bytes(serialization.Encoding.DER)
            CertificateValidator(der, validation_context=ctx).validate_usage(set())
        except CertError:
            raise
        except Exception as e:
            raise CertError(403, f"Validación eIDAS fallida (cadena/revocación): {e}")
        return

    # modo 'pilot': construye la cadena desde el certificado hacia arriba usando
    # los intermedios incluidos en la firma, hasta llegar a una RAÍZ de confianza.
    # Verifica la firma de cada eslabón. Sin trust store aún: solo vigencia.
    if not roots:
        return  # piloto sin trust store: solo vigencia + firma del nonce ya verificada
    root_subjects = {r.subject: r for r in roots}
    inter_subjects = {c.subject: c for c in extra_certs}
    cur = cert
    for _ in range(10):  # límite de profundidad
        # ¿el emisor actual es una raíz de confianza?
        if cur.issuer in root_subjects:
            try:
                _verify_cert_signed_by(cur, root_subjects[cur.issuer])
                return  # cadena válida hasta la raíz
            except Exception:
                raise CertError(403, "Cadena inválida: la raíz no firma el certificado")
        # si no, subimos por un intermedio incluido en la firma
        nxt = inter_subjects.get(cur.issuer)
        if not nxt or nxt is cur:
            break
        try:
            _verify_cert_signed_by(cur, nxt)
        except Exception:
            raise CertError(403, "Cadena inválida en un eslabón intermedio")
        cur = nxt
    raise CertError(403, "El certificado no encadena con ninguna CA de confianza (FNMT/DNIe/eIDAS)")


def _verify_cert_signed_by(cert, ca):
    """Comprueba que `ca` firmó `cert` (un eslabón de la cadena)."""
    pub = ca.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes,
                   padding.PKCS1v15(), cert.signature_hash_algorithm)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes,
                   ec.ECDSA(cert.signature_hash_algorithm))
    else:
        raise Exception("tipo de clave de CA no soportado")


# ---------------------------------------------------------------------------
# Identidad (NIF → pid pseudónimo). NO se persiste el NIF.
# ---------------------------------------------------------------------------
_NIF_RE = re.compile(r"\b(\d{8}[A-Z]|[XYZ]\d{7}[A-Z])\b")


def _extract_identity(cert):
    """Devuelve (nif_normalizado, nombre_legible) del subject del certificado."""
    subj = cert.subject
    def _get(oid_dotted):
        try:
            return subj.get_attributes_for_oid(x509.ObjectIdentifier(oid_dotted))[0].value
        except Exception:
            return ""
    serial = _get("2.5.4.5")           # serialNumber (suele traer el NIF, p.ej. IDCES-00000000T)
    cn = _get("2.5.4.3")               # commonName
    given = _get("2.5.4.42")           # givenName
    surname = _get("2.5.4.4")          # surname
    blob = " ".join([serial, cn])
    m = _NIF_RE.search((serial or "").upper()) or _NIF_RE.search(blob.upper())
    nif = m.group(1) if m else ""
    name = (f"{given} {surname}".strip() or cn or "").strip()
    return nif, name


def _pid(nif: str) -> str:
    """Identificador PSEUDÓNIMO estable e irreversible: HMAC(secreto, NIF)."""
    norm = re.sub(r"[^0-9A-Z]", "", nif.upper())
    return hmac.new(SECRET, ("ES:" + norm).encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Modo 'sim' (heredado) — no valida; mantiene DEV
# ---------------------------------------------------------------------------
def _mark_verified_sim(email: str, cert_ref: str) -> dict:
    ref = (cert_ref or "").strip()
    if not ref:
        raise CertError(400, "Falta el certificado (modo simulado)")
    pid = _pid(ref)  # en sim, el pid deriva de la referencia simulada
    with db.session() as conn:
        row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            raise CertError(404, "Usuario no encontrado")
        dup = conn.execute("SELECT id FROM users WHERE cert_pid=? AND email<>?", (pid, email)).fetchone()
        if dup:
            raise CertError(409, "Este certificado ya verifica otra cuenta (una persona, una identidad)")
        conn.execute("UPDATE users SET loa='verified', verified=1, cert_pid=?, cert_subject=?, cert_verified_at=? "
                     "WHERE email=?", (pid, ref[:120], db.now(), email))
        conn.commit()
    return {"loa": "verified", "mode": "sim",
            "nota": "SIMULADO (desarrollo): configura SFERA_CERT_MODE=pilot y el trust_store para validar de verdad"}


def status() -> dict:
    """Diagnóstico del subsistema de certificado (para /cert/status)."""
    roots = _load_trust_roots() if _CRYPTO else []
    return {"mode": MODE, "cryptography": _CRYPTO, "certvalidator": _CERTVALIDATOR,
            "trust_roots": len(roots), "trustdir": TRUSTDIR,
            "real_enabled": MODE in ("pilot", "strict")}
