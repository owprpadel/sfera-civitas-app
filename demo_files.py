"""
demo_files.py — Archivos REALES y pequeños para los casos de demostración (v55).

Sin dependencias externas:
  · pdf(title, paragraphs, footer) → bytes de un PDF de texto (Helvetica, A4, varias
    páginas si hace falta, acentos y eñes en WinAnsi).
  · bar_chart_png(values, colors) → bytes de un PNG con un gráfico de barras sencillo
    y los valores dibujados encima de cada barra (cifras con una fuente de píxeles).

Todo el contenido es ilustrativo y lleva la marca «Caso de demostración».
"""
from __future__ import annotations
import struct
import textwrap
import zlib

DEMO_FOOTER = "Caso de demostración — contenido ilustrativo para mostrar el método; personas y datos ficticios."


# ── PDF mínimo ───────────────────────────────────────────────────────────────
def _pdf_str(s: str) -> str:
    b = s.encode("cp1252", "replace").decode("latin-1")
    return b.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def pdf(title: str, paragraphs, footer: str = DEMO_FOOTER, subtitle: str = "") -> bytes:
    """PDF A4 de texto. `paragraphs`: lista de str (líneas en blanco separan párrafos;
    las que empiezan por «- » se muestran como viñetas)."""
    W, H, M = 595, 842, 56
    lines = []                                  # (fuente, tamaño, texto, espacio_antes)
    for t in textwrap.wrap(title, 60) or [""]:
        lines.append(("F2", 16, t, 0))
    if subtitle:
        for t in textwrap.wrap(subtitle, 85):
            lines.append(("F1", 10, t, 4))
    lines.append(("F1", 10, "", 6))
    for p in paragraphs:
        p = (p or "").strip()
        if not p:
            lines.append(("F1", 11, "", 4)); continue
        bullet = p.startswith("- ")
        body = p[2:] if bullet else p
        wrapped = textwrap.wrap(body, 84 if not bullet else 80) or [""]
        for i, t in enumerate(wrapped):
            lines.append(("F1", 11, ("•  " if (bullet and i == 0) else ("   " if bullet else "")) + t, 6 if i == 0 else 0))
    pages, cur, y = [], [], H - M
    for f, sz, t, sp in lines:
        lh = sz + 5 + sp
        if y - lh < M + 30:
            pages.append(cur); cur, y = [], H - M
        y -= lh
        cur.append((f, sz, t, y))
    pages.append(cur)
    objs = []                                   # contenido de cada objeto (índice = nº - 1)

    def add(o):
        objs.append(o); return len(objs)
    cat = add(None); pgs = add(None)
    f1 = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    f2 = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    kids = []
    for n, pg in enumerate(pages, 1):
        ops = ["BT"]
        for f, sz, t, yy in pg:
            ops.append(f"/{f} {sz} Tf 1 0 0 1 {M} {yy} Tm ({_pdf_str(t)}) Tj")
        ops.append(f"/F1 8 Tf 1 0 0 1 {M} {M - 20} Tm ({_pdf_str(footer + f'   ·   Página {n} de {len(pages)}')}) Tj")
        ops.append("ET")
        stream = "\n".join(ops).encode("latin-1")
        cs = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        kids.append(add(f"<< /Type /Page /Parent {pgs} 0 R /MediaBox [0 0 {W} {H}] "
                        f"/Resources << /Font << /F1 {f1} 0 R /F2 {f2} 0 R >> >> /Contents {cs} 0 R >>"))
    objs[cat - 1] = f"<< /Type /Catalog /Pages {pgs} 0 R >>"
    objs[pgs - 1] = f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>"
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        body = o if isinstance(o, bytes) else o.encode("latin-1")
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for o in offs:
        out += f"{o:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root {cat} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


# ── PNG: gráfico de barras ───────────────────────────────────────────────────
_DIG = {  # fuente 3x5
    "0": ["111", "101", "101", "101", "111"], "1": ["010", "110", "010", "010", "111"],
    "2": ["111", "001", "111", "100", "111"], "3": ["111", "001", "111", "001", "111"],
    "4": ["101", "101", "111", "001", "001"], "5": ["111", "100", "111", "001", "111"],
    "6": ["111", "100", "111", "101", "111"], "7": ["111", "001", "010", "010", "010"],
    "8": ["111", "101", "111", "101", "111"], "9": ["111", "101", "111", "001", "111"],
    "%": ["101", "001", "010", "100", "101"], ".": ["000", "000", "000", "000", "010"],
    " ": ["000", "000", "000", "000", "000"],
}
PALETTE = [(47, 158, 143), (46, 80, 144), (239, 159, 39), (178, 56, 56), (90, 120, 60), (120, 90, 160)]


def bar_chart_png(values, colors=None, w=640, h=360, suffix="") -> bytes:
    """PNG RGB con barras verticales; encima de cada barra, su valor (y `suffix`, p. ej. «%»)."""
    colors = colors or PALETTE
    img = [[(255, 255, 255)] * w for _ in range(h)]

    def rect(x0, y0, x1, y1, c):
        for yy in range(max(0, y0), min(h, y1)):
            row = img[yy]
            for xx in range(max(0, x0), min(w, x1)):
                row[xx] = c

    def text(x, y, s, c, sc=4):
        for ch in s:
            g = _DIG.get(ch, _DIG[" "])
            for gy, line in enumerate(g):
                for gx, bit in enumerate(line):
                    if bit == "1":
                        rect(x + gx * sc, y + gy * sc, x + (gx + 1) * sc, y + (gy + 1) * sc, c)
            x += 4 * sc
    base, top, left, right = h - 30, 50, 40, w - 30
    rect(left, base, right, base + 2, (120, 130, 150))                 # eje
    n = max(1, len(values)); mx = max([float(v) for v in values] + [1.0])
    slot = (right - left) // n; bw = int(slot * 0.6)
    for i, v in enumerate(values):
        x0 = left + i * slot + (slot - bw) // 2
        bh = int((base - top) * float(v) / mx)
        rect(x0, base - bh, x0 + bw, base, colors[i % len(colors)])
        lab = (str(int(v)) if float(v).is_integer() else f"{float(v):.1f}") + suffix
        text(x0 + max(0, (bw - len(lab) * 16) // 2), base - bh - 28, lab, (30, 40, 60))
    raw = b"".join(b"\x00" + bytes(c for px in row for c in px) for row in img)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))
