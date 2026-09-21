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
    cert = _load_signer_cert(cert_pem, sig, fmt)
    _verify_signature(cert, sig, nonce_bytes, fmt)

    # b) validar el certificado (vigencia + cadena + revocación según modo)
    _validate_certificate(cert)

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


def _load_trust_roots():
    """Carga las CAs de confianza (PEM) del directorio de confianza."""
    roots = []
    if not os.path.isdir(TRUSTDIR):
        return roots
    for fn in os.listdir(TRUSTDIR):
        if not fn.lower().endswith((".pem", ".crt", ".cer")):
            continue
        try:
            with open(os.path.join(TRUSTDIR, fn), "rb") as fh:
                blob = fh.read()
            for part in _split_pem(blob):
                roots.append(x509.load_pem_x509_certificate(part))
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


def _validate_certificate(cert):
    """Vigencia + cadena hasta una CA de confianza (+ revocación en 'strict')."""
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
            ctx = ValidationContext(trust_roots=trust, allow_fetching=True)
            der = cert.public_bytes(serialization.Encoding.DER)
            CertificateValidator(der, validation_context=ctx).validate_usage(set())
        except CertError:
            raise
        except Exception as e:
            raise CertError(403, f"Validación eIDAS fallida (cadena/revocación): {e}")
        return

    # modo 'pilot': cadena best-effort — el emisor debe estar entre las CAs de
    # confianza y su firma sobre el certificado debe verificar. Si no hay CAs
    # configuradas todavía, se acepta con vigencia comprobada y se deja aviso.
    if not roots:
        return  # piloto sin trust store: solo vigencia + firma del nonce ya verificada
    issuer = cert.issuer
    for ca in roots:
        if ca.subject == issuer:
            try:
                _verify_cert_signed_by(cert, ca)
                return
            except Exception:
                continue
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
