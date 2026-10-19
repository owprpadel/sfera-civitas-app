"""
clasificacion.py — CLASIFICACIÓN AUTOMÁTICA Y CORRECCIÓN de asuntos (v60, oct-2026).

Al convocar, quien propone escribe materia, administración, nivel y territorio. Esos
campos eran texto libre: llegaban con erratas («Centeal»), espacios sobrantes
(«Ayuntamiento ») o vacíos, y eso rompía el filtrado por territorio y el aviso a los
administradores de cada ámbito (que se busca por coincidencia exacta).

Este módulo los NORMALIZA sin pedir nada más al usuario:
  · materia      → una de MATERIAS (corrige erratas; si falta o no se reconoce, la
                   deduce del título y la descripción por palabras clave; si no, «Otros»).
  · nivel        → estado | ccaa | provincia | municipio (del propio nivel, de la
                   administración escrita o del territorio).
  · administración → la que corresponde al nivel (Ayuntamiento, Diputación provincial,
                   Comunidad Autónoma, Administración General del Estado).
  · territorio   → nombre oficial si es una comunidad autónoma o una provincia (corrige
                   mayúsculas, tildes y erratas leves); «España» en el nivel estatal; en
                   municipios, limpieza de espacios y mayúsculas.
Devuelve también la lista de cambios hechos, para avisar al usuario y a hola@.
Solo stdlib (difflib, unicodedata).
"""
from __future__ import annotations

import difflib
import unicodedata

MATERIAS = [
    "Medio ambiente", "Movilidad y transporte", "Urbanismo y vivienda", "Educación", "Sanidad",
    "Servicios sociales", "Cultura", "Deporte", "Economía y empleo", "Hacienda y tributos",
    "Seguridad y convivencia", "Participación y buen gobierno", "Medio rural y agricultura",
    "Tecnología y digitalización", "Igualdad", "Bienestar animal", "Turismo", "Otros",
]

# Palabras clave (sin tildes, minúsculas) → materia. Se usan para corregir lo escrito y
# para deducir la materia del título/descripción cuando falta.
KEYWORDS = {
    "Medio ambiente": ["medio ambiente", "ambiental", "residuo", "basura", "reciclaj", "compost", "contaminacion", "clima",
                       "arbol", "zona verde", "parque", "agua potable", "fuente", "ruido", "energia", "alumbrado", "emisiones",
                       "sostenib", "led"],
    "Movilidad y transporte": ["movilidad", "transporte", "autobus", "bus ", "metro", "tren", "trafico", "aparcamiento",
                               "patinete", "bicicleta", "carril bici", "parada", "peaton", "circulacion", "taxi"],
    "Urbanismo y vivienda": ["urbanismo", "vivienda", "alquiler", "piso", "solar", "obra", "calle", "plaza", "barrio",
                             "licencia", "edific", "acera", "turistic"],
    "Educación": ["educacion", "colegio", "escuela", "instituto", "alumn", "profesor", "ampa", "biblioteca", "universidad",
                  "estudiante", "comedor escolar", "patio"],
    "Sanidad": ["sanidad", "salud", "hospital", "centro de salud", "medic", "sanitari", "farmacia", "vacun", "cribado"],
    "Servicios sociales": ["servicios sociales", "social", "mayores", "dependencia", "soledad", "pobreza", "beca", "ayuda",
                           "discapacidad", "cuidados", "infancia"],
    "Cultura": ["cultura", "museo", "teatro", "fiesta", "patrimonio", "concierto", "festival", "arte"],
    "Deporte": ["deporte", "deportiv", "polideportivo", "pista", "piscina", "gimnasio", "futbol"],
    "Economía y empleo": ["economia", "empleo", "trabajo", "comercio", "empresa", "industria", "paro", "autonom"],
    "Hacienda y tributos": ["hacienda", "impuesto", "tasa", "tributo", "ibi", "presupuesto", "fiscal"],
    "Seguridad y convivencia": ["seguridad", "policia", "convivencia", "vandalismo", "robo", "incivism", "perro", "ordenanza"],
    "Participación y buen gobierno": ["participacion", "democracia", "transparencia", "gobierno", "politica", "consulta",
                                      "referendum", "voto", "ciudadania", "corrupcion", "administracion"],
    "Medio rural y agricultura": ["rural", "agricult", "ganader", "pueblo", "campo", "despoblacion", "concejo"],
    "Tecnología y digitalización": ["tecnologia", "digital", "internet", "wifi", "fibra", "aplicacion", "datos abiertos"],
    "Igualdad": ["igualdad", "genero", "mujer", "lgtb", "discriminacion"],
    "Bienestar animal": ["animal", "mascota", "perro", "gato", "colonia felina", "protectora"],
    "Turismo": ["turismo", "turista", "hotel"],
}

# Equivalencias de materias antiguas / habituales → canónica
ALIAS = {
    "movilidad": "Movilidad y transporte", "transporte": "Movilidad y transporte",
    "urbanismo": "Urbanismo y vivienda", "vivienda": "Urbanismo y vivienda",
    "cultura y educacion": "Educación", "salud": "Sanidad", "politica": "Participación y buen gobierno",
    "hacienda local": "Hacienda y tributos",
    "economia": "Economía y empleo", "empleo": "Economía y empleo", "seguridad": "Seguridad y convivencia",
    "medioambiente": "Medio ambiente", "agricultura": "Medio rural y agricultura", "tecnologia": "Tecnología y digitalización",
}

NIVELES = ("estado", "ccaa", "provincia", "municipio")
ADMIN_POR_NIVEL = {
    "estado": "Administración General del Estado",
    "ccaa": "Comunidad Autónoma",
    "provincia": "Diputación provincial",
    "municipio": "Ayuntamiento",
}

CCAA = ["Andalucía", "Aragón", "Principado de Asturias", "Illes Balears", "Canarias", "Cantabria", "Castilla y León",
        "Castilla-La Mancha", "Cataluña", "Comunitat Valenciana", "Extremadura", "Galicia", "Comunidad de Madrid",
        "Región de Murcia", "Comunidad Foral de Navarra", "País Vasco", "La Rioja", "Ceuta", "Melilla"]
CCAA_ALIAS = {"asturias": "Principado de Asturias", "baleares": "Illes Balears", "islas baleares": "Illes Balears",
              "comunidad valenciana": "Comunitat Valenciana", "valenciana": "Comunitat Valenciana",
              "madrid (comunidad)": "Comunidad de Madrid", "murcia (region)": "Región de Murcia",
              "navarra": "Comunidad Foral de Navarra", "euskadi": "País Vasco", "castilla la mancha": "Castilla-La Mancha",
              "catalunya": "Cataluña"}
PROVINCIAS = ["Álava", "Albacete", "Alicante", "Almería", "Asturias", "Ávila", "Badajoz", "Barcelona", "Burgos", "Cáceres",
              "Cádiz", "Cantabria", "Castellón", "Ciudad Real", "Córdoba", "A Coruña", "Cuenca", "Girona", "Granada",
              "Guadalajara", "Gipuzkoa", "Huelva", "Huesca", "Illes Balears", "Jaén", "León", "Lleida", "Lugo", "Madrid",
              "Málaga", "Murcia", "Navarra", "Ourense", "Palencia", "Las Palmas", "Pontevedra", "La Rioja", "Salamanca",
              "Santa Cruz de Tenerife", "Segovia", "Sevilla", "Soria", "Tarragona", "Teruel", "Toledo", "Valencia",
              "Valladolid", "Bizkaia", "Zamora", "Zaragoza", "Ceuta", "Melilla"]
ESTADO_TXT = ("espana", "estado", "nacional", "central", "gobierno de espana", "ministerio", "general del estado")


def _k(s: str) -> str:
    """Clave de comparación: minúsculas, sin tildes, espacios simples."""
    s = unicodedata.normalize("NFD", (s or "").strip().lower())
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    return " ".join(s.split())


def _best(value: str, options, cutoff=0.78):
    """Opción canónica más parecida (tolera erratas leves) o None."""
    kv = _k(value)
    if not kv:
        return None
    keys = {_k(o): o for o in options}
    if kv in keys:
        return keys[kv]
    m = difflib.get_close_matches(kv, list(keys), n=1, cutoff=cutoff)
    return keys[m[0]] if m else None


def _materia_por_texto(text: str):
    t = " " + _k(text) + " "
    score = {}
    for mat, kws in KEYWORDS.items():
        n = sum(1 for w in kws if w in t)
        if n:
            score[mat] = n
    return max(score, key=score.get) if score else None


def materia(value: str, title: str = "", body: str = "") -> str:
    kv = _k(value)
    if kv and _nivel_de_admin(value):              # escribió una administración en vez de una materia
        kv, value = "", ""
    if kv in ALIAS:
        return ALIAS[kv]
    m = _best(value, MATERIAS)
    if m:
        return m
    partes = {}                                    # cada parte de una materia compuesta («Movilidad y transporte»)
    for mt in MATERIAS:
        for p in mt.split(" y "):
            partes[p] = mt
    m = _best(value, list(partes), 0.75)
    if m:
        return partes[m]
    if kv:                                         # lo escrito contiene una palabra clave
        m = _materia_por_texto(value)
        if m:
            return m
    return _materia_por_texto(f"{title} {body}") or "Otros"


def _nivel_de_admin(admin: str):
    a = _k(admin)
    if not a:
        return None
    if any(w in a for w in ("ayunt", "municip", "concejo", "local", "alcald")):
        return "municipio"
    if any(w in a for w in ("diputac", "provinc", "cabildo", "consell insular", "diputacion foral")):
        return "provincia"
    if any(w in a for w in ("comunidad", "autonom", "junta", "generalitat", "xunta", "gobierno vasco", "gobierno de",
                            "consejeria", "region", "principado")):
        return "ccaa"
    if any(w in a for w in ESTADO_TXT) or difflib.get_close_matches(a, ["central", "estado", "nacional"], n=1, cutoff=0.7):
        return "estado"
    return None


def _territorio_ccaa(t):
    kt = _k(t)
    if kt in CCAA_ALIAS:
        return CCAA_ALIAS[kt]
    return _best(t, CCAA, 0.8)


def clasificar(title: str, body: str, materia_in: str, admin_in: str, nivel_in: str, territorio_in: str,
               privado: bool = False) -> dict:
    """Devuelve {materia, administracion, nivel, territorio, cambios:[...]}."""
    cambios = []
    mat = materia(materia_in, title, body)
    if _k(mat) != _k(materia_in):
        cambios.append(("materia", (materia_in or "").strip(), mat))
    if privado:                                    # en lo privado la administración es la propia organización
        return {"materia": mat, "administracion": (admin_in or "Privado").strip() or "Privado",
                "nivel": (nivel_in or "").strip() or None, "territorio": " ".join((territorio_in or "").split()) or None,
                "cambios": cambios}
    terr_raw = " ".join((territorio_in or "").split())
    nivel = (nivel_in or "").strip().lower()
    if nivel not in NIVELES:
        nivel = _nivel_de_admin(admin_in) or ""
        if not nivel:
            if _k(terr_raw) in ("espana", ""):
                nivel = "estado" if _k(terr_raw) == "espana" else "municipio"
            elif _territorio_ccaa(terr_raw):
                nivel = "ccaa"
            elif _best(terr_raw, PROVINCIAS, 0.85):
                nivel = "municipio"            # una capital se escribe igual que su provincia: lo normal es el municipio
            else:
                nivel = "municipio"
    if nivel != (nivel_in or "").strip().lower():
        cambios.append(("nivel", (nivel_in or "").strip(), nivel))
    adm = ADMIN_POR_NIVEL[nivel]
    if _k(adm) != _k(admin_in):
        cambios.append(("administracion", (admin_in or "").strip(), adm))
    # Territorio
    if nivel == "estado":
        terr = "España"
    elif nivel == "ccaa":
        terr = _territorio_ccaa(terr_raw) or terr_raw.title()
    elif nivel == "provincia":
        terr = _best(terr_raw, PROVINCIAS, 0.8) or terr_raw.title()
    else:
        terr = _best(terr_raw, PROVINCIAS, 0.9) or (terr_raw if terr_raw != terr_raw.lower() else terr_raw.title())
    if terr != terr_raw:
        cambios.append(("territorio", terr_raw, terr))
    return {"materia": mat, "administracion": adm, "nivel": nivel, "territorio": terr or None, "cambios": cambios}


def texto_cambios(cambios) -> str:
    nombres = {"materia": "Materia", "administracion": "Administración", "nivel": "Nivel", "territorio": "Territorio"}
    return "; ".join(f"{nombres.get(c, c)}: «{a or '—'}» → «{b}»" for c, a, b in cambios)
