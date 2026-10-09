"""
uploads.py — Archivos adjuntos de la Biblioteca (oct-2026, v55).

Expertos y ciudadanía pueden adjuntar ARCHIVOS (además de texto y enlaces):
  · Tipos permitidos (por extensión Y por contenido real del archivo):
      PDF · imágenes JPG/PNG · Word (.docx) · Excel (.xlsx) · PowerPoint (.pptx)
      · OpenDocument (.odt, .ods, .odp).
  · Bloqueado todo lo demás (html, js, svg, exe, documentos con macros…).
  · Tamaño máximo: SFERA_MAX_FILE_MB (por defecto 10 MB).
  · El tipo con el que se SIRVE el archivo lo decide el servidor (según la
    extensión validada), nunca el navegador de quien lo subió. Se descarga siempre
    como adjunto (Content-Disposition: attachment) con nosniff y CSP 'sandbox':
    el navegador nunca lo ejecuta ni lo muestra como página.
  · Sin antivirus (no hay dependencias externas): por eso solo se admiten formatos
    de documento/imagen y se comprueba su firma interna.

Almacenamiento: en la base de datos, en base64 (como ya hacía docs_service), con su
huella sha256. Migrable a un almacenamiento de objetos sin cambiar la API.
"""
from __future__ import annotations
import base64
import hashlib
import io
import os
import re
import unicodedata
import zipfile

from service import SferaError

MAX_FILE_MB = max(1, int(os.environ.get("SFERA_MAX_FILE_MB", "10")))
MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024
MAX_FILES_PER_DAY = int(os.environ.get("SFERA_MAX_FILES_DAY", "20"))   # por persona (ciudadanía)

# extensión → (tipo MIME con el que se sirve, etiqueta llana)
ALLOWED = {
    "pdf": ("application/pdf", "PDF"),
    "jpg": ("image/jpeg", "Imagen"),
    "jpeg": ("image/jpeg", "Imagen"),
    "png": ("image/png", "Imagen"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Word"),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Excel"),
    "pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "PowerPoint"),
    "odt": ("application/vnd.oasis.opendocument.text", "Documento"),
    "ods": ("application/vnd.oasis.opendocument.spreadsheet", "Hoja de cálculo"),
    "odp": ("application/vnd.oasis.opendocument.presentation", "Presentación"),
}
ALLOWED_LIST = "PDF, JPG, PNG, Word (.docx), Excel (.xlsx), PowerPoint (.pptx) u OpenDocument (.odt, .ods, .odp)"
_OOXML_MAIN = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}


def ext_of(name: str) -> str:
    name = (name or "").strip().lower()
    return name.rsplit(".", 1)[-1] if "." in name else ""


def safe_name(name: str) -> str:
    """Nombre de archivo seguro para mostrar y descargar (sin rutas ni caracteres raros)."""
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFC", name)
    name = re.sub(r"[\x00-\x1f\x7f<>:\"|?*;`$]", "", name).strip().strip(".") or "documento"
    if len(name) > 120:
        base, _, ext = name.rpartition(".")
        name = (base[:110] if base else name[:110]) + ("." + ext if base and len(ext) <= 5 else "")
    return name


def _magic_ok(ext: str, raw: bytes) -> bool:
    if ext == "pdf":
        return raw[:1024].lstrip().startswith(b"%PDF-")
    if ext in ("jpg", "jpeg"):
        return raw[:3] == b"\xff\xd8\xff"
    if ext == "png":
        return raw[:8] == b"\x89PNG\r\n\x1a\n"
    if ext in _OOXML_MAIN or ext in ("odt", "ods", "odp"):
        if raw[:4] != b"PK\x03\x04":
            return False
        try:
            z = zipfile.ZipFile(io.BytesIO(raw))
            names = z.namelist()
        except Exception:
            return False
        low = [n.lower() for n in names]
        if any(n.endswith("vbaproject.bin") or n.endswith(".bin") and "vba" in n for n in low):
            return False            # documentos con macros: no
        if ext in _OOXML_MAIN:
            return "[content_types].xml" in low and any(n.startswith(_OOXML_MAIN[ext]) for n in low)
        try:
            mt = z.read("mimetype").decode("ascii", "replace").strip()
        except Exception:
            return False
        return mt == ALLOWED[ext][0]
    return False


def validate(file_name: str, data_b64: str) -> dict:
    """Valida un archivo subido (base64). Devuelve {file_name, mime_type, size, sha256, data_b64, label}.
    Lanza SferaError con un mensaje en lenguaje llano si no es válido."""
    name = safe_name(file_name)
    ext = ext_of(name)
    if ext not in ALLOWED:
        raise SferaError(415, f"Ese tipo de archivo no se admite. Puedes subir {ALLOWED_LIST}.")
    try:
        raw = base64.b64decode(data_b64 or "", validate=True)
    except Exception:
        raise SferaError(400, "El archivo no se ha podido leer. Prueba a subirlo de nuevo.")
    if not raw:
        raise SferaError(400, "El archivo está vacío.")
    if len(raw) > MAX_FILE_BYTES:
        raise SferaError(413, f"El archivo es demasiado grande: el máximo es {MAX_FILE_MB} MB.")
    if not _magic_ok(ext, raw):
        raise SferaError(415, "El archivo no es lo que dice ser (su contenido no coincide con su tipo) "
                              "o contiene macros. Guárdalo de nuevo como PDF y vuelve a intentarlo.")
    return {"file_name": name, "mime_type": ALLOWED[ext][0], "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "data_b64": base64.b64encode(raw).decode("ascii"),
            "label": ALLOWED[ext][1]}


def serve_type(file_name: str) -> str:
    """Tipo MIME con el que se SIRVE un archivo guardado: solo de la lista blanca;
    cualquier otro (archivos antiguos) se sirve como binario genérico."""
    ext = ext_of(file_name)
    return ALLOWED[ext][0] if ext in ALLOWED else "application/octet-stream"


def label_of(file_name: str) -> str:
    ext = ext_of(file_name)
    return ALLOWED[ext][1] if ext in ALLOWED else "Archivo"


def size_of_b64(data_b64: str) -> int:
    s = (data_b64 or "").strip()
    if not s:
        return 0
    pad = s.count("=", max(0, len(s) - 2))
    return max(0, len(s) * 3 // 4 - pad)


def file_meta(file_name, data_b64=None, size=None) -> dict:
    """Metadatos PÚBLICOS de un archivo (nunca el contenido)."""
    n = size if size is not None else size_of_b64(data_b64 or "")
    return {"file_name": file_name, "file_type": label_of(file_name), "size": int(n or 0)}


VIEWABLE = {"pdf", "png", "jpg", "jpeg"}   # se pueden VER en el navegador (?ver=1); el resto siempre se descarga


def headers_for(file_name: str, inline: bool = False) -> dict:
    """Cabeceras seguras. Por defecto, descarga. Con inline=True y solo para PDF e
    imágenes (contenido ya comprobado al subir), se abre para verlo en el navegador:
    en el móvil la app lo abre fuera (Safari / visor), con su botón para volver."""
    from urllib.parse import quote
    name = safe_name(file_name)
    ascii_name = name.encode("ascii", "ignore").decode("ascii").replace('"', "") or "documento"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    show = inline and ext in VIEWABLE
    h = {
        "Content-Disposition": f"{'inline' if show else 'attachment'}; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}",
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "private, max-age=300",
        "Referrer-Policy": "no-referrer",
    }
    # Imágenes y descargas: documento aislado (sin scripts). PDF visible: el visor del navegador
    # no admite «sandbox», así que se limita todo lo demás (sin red, sin formularios).
    h["Content-Security-Policy"] = ("default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; object-src 'self'; frame-ancestors 'self'"
                                    if (show and ext == "pdf") else "default-src 'none'; img-src 'self'; sandbox")
    return h
