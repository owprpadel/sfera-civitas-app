"""
export_pdf.py — v65 · «Descargar mis datos» en PDF legible (RGPD art. 15, derecho de acceso).
Convierte la exportación de service.export_account() en un PDF con tablas en lenguaje llano.
La copia en formato de datos (JSON, art. 20 portabilidad) sigue disponible en /api/account/export.
"""
from __future__ import annotations

import datetime
import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

AZUL = colors.HexColor("#1F3864")
GRIS = colors.HexColor("#5b6b80")
LINEA = colors.HexColor("#d9e0ea")
FONDO = colors.HexColor("#f4f7fb")

ETQ = {
    "email": "Email", "email_verificado": "Email verificado", "nivel_garantia": "Nivel de acceso",
    "administracion": "Administración", "experto": "Experto/a", "creada": "Cuenta creada",
    "verificada_con_certificado": "Verificada con certificado digital",
    "certificado_verificado_en": "Fecha de verificación con certificado", "nota_certificado": "Sobre el certificado",
    "version_aceptada": "Versión de las condiciones aceptadas", "privacidad_aceptada_en": "Privacidad aceptada el",
    "declara_14_anos_o_mas": "Declara tener 14 años o más", "titulo": "Título", "texto": "Texto", "fecha": "Fecha",
    "creado": "Fecha", "postura": "Postura", "via": "Vía", "nombre": "Nombre", "rol": "Papel", "estado": "Estado",
    "desde": "Desde", "ambito": "Ámbito", "valor": "Valor", "tipo": "Tipo", "leida": "Leída", "usada": "Usada",
    "motivo": "Motivo", "asunto": "Asunto", "pregunta": "Pregunta", "dia": "Día", "archivo": "Archivo", "url": "Enlace",
    "especialidad": "Especialidad", "credenciales": "Credenciales", "organizacion": "Organización",
    "proveedor": "Proveedor", "importe_centimos": "Importe", "moneda": "Moneda", "unidades": "Unidades",
}
SECC = [
    ("organizaciones", "Organizaciones a las que perteneces"), ("roles", "Papeles asignados"),
    ("asuntos_convocados", "Asuntos que has convocado"), ("apoyos_a_asuntos", "Asuntos que has apoyado"),
    ("apoyos_a_propuestas", "Propuestas que has apoyado"), ("argumentos", "Tus argumentos"),
    ("propuestas", "Tus propuestas"), ("marcas_util_argumentos", "Argumentos que marcaste como útiles"),
    ("marcas_util_propuestas", "Propuestas que marcaste como útiles"),
    ("documentos_aportados", "Documentos que has aportado"), ("aportaciones_a_documentos", "Aportaciones a documentos"),
    ("perfil_de_experto", "Tu perfil de experto/a"), ("documentos_de_experto", "Documentos de experto/a"),
    ("propuestas_de_experto", "Propuestas de experto/a"),
    ("votaciones_con_papeleta_emitida", "Votaciones en las que has votado"), ("notificaciones", "Avisos recibidos"),
    ("invitaciones_recibidas", "Invitaciones recibidas"), ("invitaciones_enviadas", "Invitaciones enviadas"),
    ("pagos", "Pagos"), ("denuncias_realizadas", "Denuncias que has hecho"),
    ("usuarios_bloqueados", "Personas que has bloqueado"), ("soporte", "Mensajes a soporte"),
]
OCULTAS = {"id", "debate_id", "proposal_id", "argument_id", "document_id", "org_id", "election_id",
           "target_id", "blocked_id"}
_MADRID = datetime.timezone(datetime.timedelta(hours=1))   # aproximación suficiente para el informe


def _fecha(v) -> str:
    if v in (None, ""):
        return "—"
    try:
        n = float(v)
        if n > 1e11:
            n /= 1000
        dt = datetime.datetime.fromtimestamp(n, tz=datetime.timezone.utc)
    except (TypeError, ValueError):
        try:
            dt = datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        except ValueError:
            return str(v)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    try:
        from zoneinfo import ZoneInfo
        dt = dt.astimezone(ZoneInfo("Europe/Madrid"))
    except Exception:
        dt = dt.astimezone(_MADRID)
    return dt.strftime("%d/%m/%Y %H:%M")


def _val(k: str, v) -> str:
    if isinstance(v, bool):
        return "Sí" if v else "No"
    if v in (None, ""):
        return "—"
    if k in ("fecha", "creado", "creada", "desde", "dia", "generado") or k.endswith("_en"):
        return _fecha(v)
    if k == "importe_centimos":
        try:
            return f"{int(v) / 100:.2f}".replace(".", ",")
        except Exception:
            return str(v)
    if k in ("nivel_garantia", "via"):
        return {"verified": "Con certificado digital", "open": "Con email"}.get(v, str(v))
    if k == "postura":
        return {"favor": "A favor", "contra": "En contra", "matiz": "Con matices"}.get(v, str(v))
    if k in ("leida", "usada") and v in (0, 1):
        return "Sí" if v else "No"
    return str(v)


def build_pdf(d: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title="Mis datos · Sfera Civitas", author="Sfera Civitas")
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("h1", parent=ss["Title"], textColor=AZUL, alignment=0, fontSize=20, spaceAfter=4)
    H2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=AZUL, fontSize=13, spaceBefore=12, spaceAfter=5)
    P = ParagraphStyle("p", parent=ss["Normal"], fontSize=9.5, leading=12.5)
    META = ParagraphStyle("m", parent=P, textColor=GRIS, fontSize=9)
    CELL = ParagraphStyle("c", parent=P, fontSize=8.5, leading=11)
    CELLB = ParagraphStyle("cb", parent=CELL, fontName="Helvetica-Bold")

    def para(t, st=CELL):
        return Paragraph(escape(str(t)).replace("\n", "<br/>"), st)

    def tstyle(header: bool):
        st = [("GRID", (0, 0), (-1, -1), 0.4, LINEA), ("VALIGN", (0, 0), (-1, -1), "TOP"),
              ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
              ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
        st.append(("BACKGROUND", (0, 0), (-1, 0) if header else (0, -1), FONDO))
        return TableStyle(st)

    def ficha(o: dict):
        rows = [[para(ETQ.get(k, k), CELLB), para(_val(k, v))] for k, v in (o or {}).items() if k not in OCULTAS]
        if not rows:
            return para("Nada.", P)
        t = Table(rows, colWidths=[62 * mm, None])
        t.setStyle(tstyle(False))
        return t

    def tabla(rows: list):
        cols = [c for c in rows[0].keys() if c not in OCULTAS]
        if not cols:
            return para(f"{len(rows)} en total.", P)
        data = [[para(ETQ.get(c, c), CELLB) for c in cols]]
        data += [[para(_val(c, r.get(c))) for c in cols] for r in rows]
        peso = {"texto": 4, "titulo": 3, "pregunta": 3, "url": 3, "credenciales": 3, "asunto": 3,
                "fecha": 1.3, "creado": 1.3, "desde": 1.3, "dia": 1.3}
        total = sum(peso.get(c, 1) for c in cols)
        ancho = A4[0] - 32 * mm
        t = Table(data, repeatRows=1, colWidths=[ancho * peso.get(c, 1) / total for c in cols])
        t.setStyle(tstyle(True))
        return t

    s = [Paragraph("Mis datos en Sfera Civitas", H1),
         para(f"Generado el {_fecha(d.get('generado'))} · {d.get('responsable', '')}", META),
         Paragraph("Tu cuenta", H2), ficha(d.get("perfil")),
         Paragraph("Consentimientos", H2), ficha(d.get("consentimientos"))]
    vacias = []
    for k, titulo in SECC:
        rows = d.get(k) or []
        if rows:
            s += [Paragraph(escape(titulo), H2), tabla(rows)]
        else:
            vacias.append(titulo)
    s += [Paragraph("Tu voto", H2), para(d.get("nota_voto", ""), P)]
    if vacias:
        s += [Paragraph("Sin datos", H2), para(" · ".join(vacias), META)]
    s += [Spacer(1, 10),
          para("Si quieres llevarte tus datos a otro servicio, en la app tienes también la copia en formato de "
               "datos (JSON). Para cualquier duda sobre tus datos: hola@sferacivitas.org (asunto «Protección de datos»).", META)]

    def pie(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(GRIS)
        canvas.drawString(16 * mm, 9 * mm, "Sfera Civitas · Documento personal: no lo compartas")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Página {doc_.page}")
        canvas.restoreState()

    doc.build(s, onFirstPage=pie, onLaterPages=pie)
    return buf.getvalue()
