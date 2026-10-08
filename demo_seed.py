"""
demo_seed.py — CASOS DE DEMOSTRACIÓN (oct-2026) y ocultación reversible de ejemplos.

Crea, a petición del Super Admin y de forma IDEMPOTENTE, un conjunto coherente de
asuntos verosímiles, neutrales y no partidistas, uno por fase (más un segundo
asunto en Deliberar y en Proponer):

  · Marcador OCULTO: debates.is_demo=1 + debates.demo_key (no hay prefijo en el título).
    Si ya existe un asunto con esa demo_key, no se duplica.
  · Transparencia: la ficha de cada caso muestra, discreta, la marca «Caso de
    demostración» («Contenido ilustrativo para mostrar el método; personas y datos
    ficticios»). Las cifras son ilustrativas («aprox.»).
  · Expertos INVENTADOS: perfiles sin cuenta de acceso (expert_profiles, is_demo=1),
    con descripciones genéricas; nunca nombran personas ni instituciones reales.
    La administración publica sus documentos y propuestas ATRIBUIDOS a esos perfiles
    (author_profile_id) y queda registrado quién lo hizo (created_by / author_id).
  · Ciudadanía ficticia SIN acceso (users.is_demo=1, email *.invalid, contraseña
    inutilizable) solo para que apoyos, «útil» y aportaciones tengan volumen realista.
  · VOTO: el servidor NUNCA emite papeletas. El caso «publicar» queda en votación y
    la web del admin vota con la criptografía real del cliente y cierra el recuento.

Ocultar / mostrar (reversible, no borra nada):
  · scope 'legacy': ejemplos antiguos («Ejemplo · …» y los sembrados al arrancar).
  · scope 'demo'  : los casos de demostración nuevos.
  Nunca toca asuntos de usuarios reales.
"""
from __future__ import annotations
import base64
import secrets

import db
import demo_files
from service import SferaError

DAY = 86400
DEMO_VERSION = "v2"
N_CITIZENS = 130          # supera el quórum real de 100 apoyos en los casos que ya pasaron Convocar

# Títulos de los ejemplos ANTIGUOS (versiones previas del botón y siembra de arranque).
LEGACY_TITLES = (
    "Ampliar el horario de las bibliotecas públicas en época de exámenes",
    "Regulación de los patinetes eléctricos en el casco urbano",
    "Uso de un solar público en desuso del barrio",
    "Peatonalizar la calle mayor los domingos",
)
LEGACY_PREFIX = "Ejemplo · "

# ── Expertos ficticios (sin personas ni instituciones reales) ──────────────────
EXPERTS = {
    "agua": ("Dra. Irene Saldaña Bermejo", "Salud pública ambiental",
             "Médica especialista en medicina preventiva; 15 años en programas municipales de salud ambiental y calidad del agua.",
             "Servicio público de salud (ámbito autonómico)"),
    "hidra": ("Andrés Molins Requena", "Ingeniería hidráulica",
              "Ingeniero de caminos; 20 años en el diseño y mantenimiento de redes de abastecimiento urbano.",
              "Consultoría técnica independiente"),
    "biblio": ("Dra. Marta Ezquerra Lafuente", "Gestión de bibliotecas públicas",
               "Doctora en Documentación; ha dirigido la planificación de servicios en una red municipal de bibliotecas.",
               "Universidad pública (área de Biblioteconomía)"),
    "gestion": ("Javier Oñate Prieto", "Gestión económica municipal",
                "Economista; 12 años como técnico de presupuestos y costes de servicios públicos locales.",
                ""),
    "movil": ("Dra. Lucía Ferrán Ortiz", "Urbanismo y movilidad",
              "Profesora titular de Urbanismo; investiga la convivencia entre peatones, bicicletas y vehículos de movilidad personal.",
              "Universidad pública (Escuela de Arquitectura)"),
    "segvial": ("Rubén Castañar Gil", "Seguridad vial",
                "Ingeniero de tráfico; 15 años en análisis de siniestralidad urbana y ordenación del espacio público.",
                "Consultoría de movilidad independiente"),
    "juridico": ("Elena Barrachina Soto", "Derecho administrativo local",
                 "Abogada especialista en ordenanzas municipales y contratación pública.",
                 ""),
    "clima": ("Dr. Tomás Iriarte Navas", "Climatología urbana",
              "Físico; investiga islas de calor y confort térmico en espacios escolares y públicos.",
              "Centro público de investigación (área de clima urbano)"),
    "arqesc": ("Nuria Valcárcel Amat", "Arquitectura escolar",
               "Arquitecta; ha proyectado reformas de patios en centros educativos públicos durante más de 10 años.",
               "Estudio de arquitectura independiente"),
    "pedag": ("Dra. Carmen Lozano Ibars", "Pedagogía y salud infantil",
              "Doctora en Ciencias de la Educación; especialista en juego, actividad física y bienestar en la escuela.",
              "Universidad pública (Facultad de Educación)"),
    "residuos": ("Dr. Pablo Echarri Ugalde", "Gestión de residuos",
                 "Ingeniero químico; 18 años en diseño de sistemas de recogida selectiva y compostaje.",
                 "Centro tecnológico público"),
    "rural": ("Ana Belén Quirós Llano", "Servicios públicos en el medio rural",
              "Geógrafa; trabaja en la prestación de servicios mancomunados en concejos y municipios pequeños.",
              ""),
    "urban": ("Dr. Sergio Albarracín Peña", "Planeamiento urbanístico",
              "Arquitecto urbanista; profesor asociado de Planeamiento y redactor de planes especiales de barrio.",
              "Universidad pública (Escuela de Arquitectura)"),
    "verde": ("Laura Mendizábal Rey", "Paisajismo y zonas verdes",
              "Ingeniera agrónoma; especialista en diseño y mantenimiento de parques de bajo consumo de agua.",
              "Consultoría ambiental independiente"),
    "transp": ("Dr. Víctor Garcés Lambán", "Transporte público",
               "Ingeniero de transportes; ha planificado servicios de autobús urbano y metropolitano durante 20 años.",
               "Universidad pública (área de Transportes)"),
    "nocturna": ("Beatriz Olmedo Sanz", "Seguridad y vida nocturna",
                 "Socióloga; estudia la movilidad nocturna, la seguridad percibida y la convivencia vecinal.",
                 ""),
}

# ── Casos (en orden de fase). Cifras ilustrativas («aprox.»). ──────────────────
CASES = [
    {   # CONVOCAR
        "key": "convocar", "phase": "convocar",
        "title": "Fuentes de agua potable en parques y plazas",
        "body": "Propongo instalar fuentes de agua potable en los parques y plazas del municipio que no tienen ninguna, "
                "con al menos una por parque, accesibles para personas con movilidad reducida y con caño para mascotas. "
                "En verano muchas familias, personas mayores y deportistas no encuentran dónde beber agua.",
        "materia": "Medio ambiente", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Zaragoza",
        "created_ago": 5, "deadline_in": 9, "supports": 41,
        "cdocs": [
            ("dato", "Parques sin fuente: recuento vecinal",
             "Hemos recorrido 38 parques y plazas del municipio: aprox. 15 no tienen ninguna fuente y en otras 6 la fuente no funciona. "
             "Recuento hecho a pie por un grupo de vecinos; no es un dato oficial.", ""),
            ("estudio", "Recomendaciones generales sobre hidratación en olas de calor",
             "Las guías de salud pública recomiendan facilitar el acceso a agua potable en espacios públicos durante episodios de calor, "
             "sobre todo para personas mayores, niños y quienes hacen deporte al aire libre.", ""),
            ("enlace", "Portal de datos abiertos del Gobierno de España",
             "Catálogo general de datos abiertos; puede servir para buscar inventarios municipales de fuentes y zonas verdes.",
             "https://datos.gob.es"),
        ],
    },
    {   # DELIBERAR (A)
        "key": "deliberar-a", "phase": "deliberar",
        "title": "Ampliar el horario de las bibliotecas municipales en época de exámenes",
        "body": "¿Deberían las bibliotecas municipales abrir por la noche y los fines de semana durante los periodos de exámenes? "
                "Hay que valorar la demanda real, el coste de personal y vigilancia, y si conviene hacerlo en todas o solo en algunas.",
        "materia": "Cultura y Educación", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Valencia",
        "created_ago": 20, "delib_started_ago": 4, "deadline_in": 10, "supports": 118,
        "experts": ["biblio", "gestion"],
        "args": [
            ("favor", "En época de exámenes las salas se llenan antes de las diez de la mañana y mucha gente se queda sin sitio.", 9),
            ("favor", "No todo el mundo tiene en casa un espacio tranquilo para estudiar; la biblioteca es la única opción para muchos.", 7),
            ("contra", "Abrir de noche exige personal y vigilancia extra; ese dinero podría ir a ampliar fondos o actividades todo el año.", 5),
            ("matiz", "Quizá no hace falta abrir todas: bastaría con una o dos bibliotecas grandes y bien comunicadas.", 8),
            ("favor", "Las salas de estudio privadas cuestan dinero; un horario ampliado público es una medida de igualdad.", 4),
            ("contra", "En otros servicios con horario nocturno la ocupación después de medianoche ha sido baja; conviene medir antes.", 3),
            ("matiz", "Se podría probar en una convocatoria de exámenes y decidir con datos de ocupación por franja horaria.", 6),
            ("matiz", "Si se amplía el horario, hay que pensar en el transporte público de vuelta a casa por la noche.", 2),
            ("favor", "Los fines de semana son clave: muchas personas trabajan entre semana y solo pueden estudiar sábado y domingo.", 3),
            ("contra", "El personal actual ya cubre turnos ajustados; ampliar sin contratar puede empeorar el servicio de día.", 1),
        ],
        "cdocs": [
            ("dato", "Ocupación observada en la sala de estudio central",
             "Durante tres semanas de enero contamos la ocupación a distintas horas: aprox. 95 % de 10 a 14 h y 80 % de 17 a 21 h. "
             "Recuento informal de usuarios habituales.", ""),
            ("noticia", "Otras ciudades han probado horarios extendidos",
             "Varias ciudades españolas han abierto salas de estudio 24 horas en época de exámenes con resultados dispares: "
             "alta ocupación hasta la medianoche y baja de madrugada.", ""),
        ],
        "edocs": [
            ("informe", "biblio", "Informe técnico: demanda de puestos de estudio",
             "Resumen ilustrativo.\n\n1. La red cuenta con aprox. 1.400 puestos de lectura.\n2. En las seis semanas de exámenes la ocupación media supera el 85 % en horario de mañana.\n"
             "3. Fuera de esas semanas, la ocupación media ronda el 45 %.\n\nConclusión: la demanda es estacional y se concentra en pocas bibliotecas."),
            ("datos", "gestion", "Datos: coste estimado de ampliar el horario",
             "Estimación ilustrativa (aprox.) por biblioteca y semana de apertura extendida:\n- Personal adicional (2 turnos): 3.800 €\n"
             "- Vigilancia: 1.600 €\n- Suministros y limpieza: 700 €\nTotal aprox.: 6.100 € por biblioteca y semana."),
        ],
    },
    {   # DELIBERAR (B)
        "key": "deliberar-b", "phase": "deliberar",
        "title": "Ordenar el aparcamiento de patinetes y bicicletas de alquiler en las aceras",
        "body": "Los patinetes y bicicletas de alquiler aparcados en las aceras dificultan el paso, sobre todo a personas con movilidad "
                "reducida o con carritos. ¿Cómo lo ordenamos: zonas de aparcamiento obligatorias, sanciones, límites de flota o una combinación?",
        "materia": "Movilidad", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Bilbao",
        "created_ago": 18, "delib_started_ago": 2, "deadline_in": 12, "supports": 104,
        "experts": ["movil", "segvial", "juridico"],
        "args": [
            ("favor", "Con zonas de aparcamiento marcadas, las aceras quedan libres y el servicio sigue siendo útil.", 11),
            ("contra", "Si las zonas están lejos de donde la gente va, se dejará de usar el servicio y volverán los coches.", 6),
            ("matiz", "Las zonas deberían ocupar plazas de calzada, no más espacio de la acera.", 9),
            ("favor", "Las personas ciegas y quienes van en silla de ruedas tropiezan a diario con vehículos mal aparcados.", 8),
            ("contra", "Sancionar al usuario es difícil de controlar; la responsabilidad debería ser de la empresa operadora.", 5),
            ("matiz", "Las aplicaciones ya pueden impedir terminar el viaje fuera de una zona permitida; sería la forma más eficaz.", 7),
            ("favor", "Ordenar el aparcamiento no es prohibir: muchas ciudades han mejorado la convivencia así.", 3),
            ("matiz", "Habría que limitar el número de vehículos por operadora según la demanda real de cada barrio.", 4),
            ("contra", "Los barrios periféricos tienen menos alternativas de transporte; no deberían perder servicio.", 2),
            ("matiz", "Conviene medir durante unos meses cuántos vehículos bloquean el paso y dónde, antes de fijar sanciones.", 2),
            ("favor", "Las bicicletas compartidas ya funcionan con estaciones y apenas generan quejas.", 1),
        ],
        "cdocs": [
            ("dato", "Fotos y recuento en el eje comercial",
             "Durante una semana contamos aprox. 60 vehículos al día aparcados en mitad de la acera en un tramo de 800 metros.", ""),
            ("otro", "Testimonio de una asociación de personas con discapacidad visual",
             "Piden que cualquier solución garantice un itinerario peatonal libre de obstáculos junto a las fachadas.", ""),
            ("enlace", "Boletín Oficial del Estado (buscador de legislación)",
             "Útil para consultar la normativa estatal de tráfico aplicable a vehículos de movilidad personal.", "https://www.boe.es"),
        ],
        "edocs": [
            ("informe", "movil", "Informe técnico: ocupación del espacio peatonal",
             "Resumen ilustrativo. En las 12 calles más transitadas, el ancho libre de paso se reduce por debajo de 1,8 m en aprox. "
             "un 30 % de las observaciones por vehículos mal aparcados. Las zonas de aparcamiento en calzada reducen ese porcentaje "
             "por debajo del 5 % allí donde se han probado."),
            ("dictamen", "juridico", "Dictamen: qué puede regular el Ayuntamiento",
             "Síntesis ilustrativa: la ordenanza municipal puede fijar zonas de estacionamiento, exigir a las operadoras sistemas que "
             "impidan finalizar el viaje fuera de ellas y condicionar la licencia al cumplimiento. Las sanciones deben respetar el "
             "procedimiento sancionador y la proporcionalidad."),
        ],
    },
    {   # PROPONER (A)
        "key": "proponer-a", "phase": "proponer",
        "title": "Sombra y vegetación en los patios de los colegios públicos",
        "body": "Muchos patios escolares son pistas de cemento sin sombra y en junio y septiembre superan los 35 °C a mediodía. "
                "¿Cómo damos sombra a los patios de los colegios públicos, con qué soluciones y en qué plazo?",
        "materia": "Educación", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Málaga",
        "created_ago": 34, "delib_started_ago": 26, "prop_started_ago": 4, "deadline_in": 10, "supports": 131,
        "experts": ["clima", "arqesc", "pedag"],
        "args": [
            ("favor", "Con sombra, los recreos de junio y septiembre dejan de ser un riesgo para la salud de los niños.", 14),
            ("contra", "Las estructuras grandes necesitan licencias y mantenimiento; el coste puede retrasar otras obras escolares.", 6),
            ("matiz", "El arbolado tarda años en dar sombra: quizá haga falta combinar toldos ahora y árboles para el futuro.", 12),
            ("favor", "Las familias ya organizan ventiladores y botellas de agua; es una demanda real y repetida.", 5),
            ("matiz", "Quitar parte del cemento y poner tierra o vegetación baja también reduce la temperatura del patio.", 7),
            ("contra", "Algunos patios son pequeños y los árboles grandes pueden quitar espacio para jugar.", 3),
            ("favor", "Un patio con sombra y vegetación se puede abrir al barrio por las tardes como espacio de juego.", 4),
            ("matiz", "Hay que priorizar los colegios con más horas de sol y menos espacio verde alrededor.", 9),
            ("contra", "Los toldos textiles se deterioran con el viento y el sol; hay que prever su sustitución.", 2),
            ("favor", "Cuidar los árboles del patio puede ser parte del proyecto educativo del centro.", 3),
        ],
        "props": [
            ("Toldos retráctiles en todos los patios con más horas de sol antes del próximo verano.", 48, 11),
            ("Plantar árboles de sombra rápida en cada patio, con riego por goteo.", 41, 13),
            ("Sustituir parte del cemento por suelo natural y vegetación baja.", 22, 6),
            ("Pérgolas con placas solares que den sombra y electricidad al colegio.", 27, 8),
            ("Adelantar el recreo a primera hora en los días de más calor.", 9, 2),
            ("Fuentes y zonas de agua en los patios más expuestos.", 14, 3),
        ],
        "cdocs": [
            ("dato", "Temperatura medida por la AMPA en el patio",
             "Con un termómetro de bola negra medimos aprox. 38 °C en la pista central a las 13 h el 12 de junio, y 29 °C bajo los "
             "únicos dos árboles del patio. Medición casera, orientativa.", ""),
            ("estudio", "Guías de diseño de patios escolares",
             "Diversas guías de diseño de entornos escolares recomiendan combinar sombra, vegetación y suelos permeables para "
             "reducir el calor y diversificar el juego.", ""),
        ],
        "edocs": [
            ("informe", "clima", "Informe técnico: temperaturas en los patios",
             "Resumen ilustrativo. Mediciones en 12 patios durante junio: en 9 se superaron los 35 °C a mediodía en las zonas "
             "expuestas. En las zonas con arbolado maduro se registraron entre 4 y 7 °C menos (aprox.)."),
            ("datos", "arqesc", "Datos: coste orientativo por solución",
             "Estimación ilustrativa (aprox.):\n- Toldo retráctil por patio: 18.000–25.000 €\n- Árbol de sombra plantado con riego: "
             "600–900 € por unidad\n- Pérgola fotovoltaica (100 m²): 45.000–60.000 €, con ahorro anual de 4.000–6.000 € en electricidad\n"
             "- Sustitución de 200 m² de pavimento por suelo natural: 15.000–20.000 €"),
            ("dictamen", "pedag", "Dictamen: sombra, juego y bienestar",
             "Síntesis ilustrativa: la sombra y la vegetación reducen el estrés térmico y favorecen un juego más variado. Se "
             "recomienda que el diseño mantenga espacio libre para el juego activo y cuente con la comunidad educativa."),
        ],
        "eprops": [
            ("clima", "Toldos ahora y árboles a medio plazo",
             "Instalar toldos retráctiles en los patios con más horas de sol antes del verano y plantar al menos cuatro árboles de "
             "sombra por patio, con riego por goteo, para sustituir progresivamente los toldos.",
             "Recoge las dos propuestas ciudadanas más apoyadas (toldos y arbolado) y el argumento de que el arbolado tarda años en dar sombra."),
            ("arqesc", "Pérgolas solares y suelo natural",
             "Cubrir parte de cada patio con pérgolas fotovoltaicas y sustituir una parte del pavimento por suelo natural con vegetación "
             "baja. El ahorro eléctrico se destina al mantenimiento.",
             "Parte de las propuestas ciudadanas de pérgolas solares y de suelo natural, y del argumento sobre el coste de mantenimiento."),
        ],
    },
    {   # PROPONER (B)
        "key": "proponer-b", "phase": "proponer",
        "title": "Recogida de residuos orgánicos en los concejos pequeños",
        "body": "En muchos concejos pequeños no hay contenedor de residuos orgánicos y todo acaba en el contenedor de resto. "
                "¿Cómo implantamos la recogida de orgánico donde hay poca población y mucha distancia: compostaje doméstico, "
                "compostaje comunitario o recogida con contenedor?",
        "materia": "Medio ambiente", "administracion": "Comunidad Autónoma", "nivel": "ccaa", "territorio": "Principado de Asturias",
        "created_ago": 36, "delib_started_ago": 29, "prop_started_ago": 8, "deadline_in": 6, "supports": 109,
        "experts": ["residuos", "rural"],
        "args": [
            ("favor", "Separar el orgánico reduce mucho lo que va a vertedero y abarata la gestión a medio plazo.", 10),
            ("contra", "Con casas dispersas, un camión específico para orgánico puede costar más de lo que ahorra.", 8),
            ("matiz", "En zonas rurales el compostaje en casa o comunitario puede funcionar mejor que el contenedor.", 12),
            ("favor", "Mucha gente ya composta en su huerta; solo falta apoyo y formación.", 6),
            ("contra", "Sin seguimiento, el compost doméstico se abandona a los pocos meses.", 4),
            ("matiz", "Podría combinarse: compostaje en las aldeas y contenedor en las villas más pobladas.", 9),
            ("favor", "Las normas europeas obligan a recoger el orgánico por separado; mejor organizarlo bien que improvisar.", 5),
            ("matiz", "Hay que pensar en las personas mayores que viven solas y no pueden cargar con compostadores.", 3),
        ],
        "props": [
            ("Compostadores domésticos gratuitos con formación y seguimiento en las aldeas.", 37, 9),
            ("Compostaje comunitario en cada núcleo de más de 50 habitantes.", 29, 7),
            ("Contenedor marrón solo en las villas más pobladas.", 24, 4),
            ("Bonificación en la tasa de basuras a quien composte en casa.", 31, 6),
            ("Puntos de recogida móviles una vez por semana en las parroquias.", 12, 2),
        ],
        "cdocs": [
            ("dato", "Composición aproximada de la bolsa de basura",
             "Según caracterizaciones habituales de residuos domésticos, la fracción orgánica suele rondar un tercio del peso de la "
             "bolsa de resto (aprox.).", ""),
            ("enlace", "Instituto Nacional de Estadística",
             "Para consultar datos de población por municipio y núcleo, útiles para dimensionar la recogida.", "https://www.ine.es"),
        ],
        "edocs": [
            ("informe", "residuos", "Informe técnico: opciones de recogida en población dispersa",
             "Resumen ilustrativo. En núcleos de menos de 100 habitantes, el compostaje doméstico o comunitario tiene un coste por "
             "tonelada aprox. 40–60 % menor que la recogida con camión específico, siempre que haya seguimiento técnico."),
            ("datos", "rural", "Datos: población y núcleos",
             "Datos ilustrativos (aprox.): 78 concejos; 52 tienen menos de 5.000 habitantes; más de 4.000 núcleos de población, la "
             "mayoría con menos de 50 vecinos."),
        ],
        "eprops": [
            ("residuos", "Modelo mixto según el tamaño del núcleo",
             "Compostaje doméstico con seguimiento en núcleos de menos de 50 habitantes, compostaje comunitario entre 50 y 500 y "
             "contenedor marrón en las villas de más de 500.",
             "Combina las tres propuestas ciudadanas más apoyadas y el argumento de adaptar la solución a cada tipo de núcleo."),
            ("rural", "Compostaje comunitario con bonificación en la tasa",
             "Compostaje comunitario con apoyo técnico en todos los núcleos de más de 50 habitantes y bonificación en la tasa de "
             "basuras a quien composte en casa, sin contenedor marrón en el medio rural.",
             "Basada en las propuestas ciudadanas de compostaje comunitario y de bonificación, y en el argumento sobre las personas mayores."),
        ],
    },
    {   # VOTAR
        "key": "votar", "phase": "votar",
        "title": "Qué hacer con el solar municipal vacío junto al centro de salud",
        "body": "Un solar municipal de aprox. 2.500 m² junto al centro de salud lleva años vacío. ¿Qué uso le damos: zona verde, "
                "huerto urbano, pistas deportivas o aparcamiento? Se vota entre las propuestas que han redactado los expertos.",
        "materia": "Urbanismo", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Sevilla",
        "created_ago": 50, "delib_started_ago": 44, "prop_started_ago": 30, "vote_started_ago": 4, "deadline_in": 10,
        "supports": 126, "experts": ["urban", "verde"],
        "args": [
            ("favor", "El barrio tiene menos zonas verdes por habitante que la media de la ciudad.", 13),
            ("contra", "Un parque nuevo necesita presupuesto de mantenimiento cada año, no solo de obra.", 7),
            ("matiz", "Un uso mixto (zona verde y pistas) podría atender a más grupos de edad.", 11),
            ("favor", "Las asociaciones vecinales llevan años pidiendo un espacio para actividades al aire libre.", 5),
            ("contra", "Quienes acuden al centro de salud en coche tienen problemas para aparcar.", 6),
            ("matiz", "Cualquier opción debería incluir sombra y bancos: hay muchas personas mayores en la zona.", 9),
            ("favor", "Un huerto urbano crea comunidad y puede vincularse con los colegios cercanos.", 4),
            ("contra", "Las pistas pueden generar ruido por la noche si no se regula el horario.", 3),
            ("matiz", "Antes de decidir conviene saber cuánto cuesta mantener cada opción durante diez años.", 6),
        ],
        "props": [
            ("Parque con juegos infantiles, sombra y bancos.", 52, 12),
            ("Huerto urbano gestionado por las asociaciones del barrio.", 33, 9),
            ("Pistas deportivas de uso libre con horario.", 29, 5),
            ("Aparcamiento para el centro de salud con zona verde perimetral.", 21, 4),
            ("Zona de estancia con sombra para personas mayores.", 18, 6),
        ],
        "cdocs": [
            ("dato", "Encuesta vecinal informal",
             "Una asociación vecinal preguntó a aprox. 300 personas: 46 % prefería zona verde, 22 % pistas, 18 % huerto y 14 % aparcamiento. "
             "No es una muestra representativa.", ""),
            ("otro", "Plano del solar con orientación y accesos",
             "El solar tiene acceso por dos calles; la cara sur recibe sol todo el día y la norte queda en sombra por la tarde.", ""),
        ],
        "edocs": [
            ("informe", "urban", "Síntesis de la deliberación",
             "Síntesis ilustrativa: los argumentos más útiles destacan el déficit de zonas verdes, el coste de mantenimiento y el "
             "interés por un uso mixto. Las propuestas ciudadanas más apoyadas fueron el parque y el huerto."),
            ("datos", "verde", "Datos: coste de obra y mantenimiento por opción",
             "Estimación ilustrativa (aprox.):\n- Parque: obra 380.000 €; mantenimiento 22.000 €/año\n"
             "- Huerto + zona verde: obra 210.000 €; mantenimiento 9.000 €/año\n- Pistas: obra 290.000 €; mantenimiento 14.000 €/año"),
            ("dictamen", "urban", "Dictamen: usos compatibles con el planeamiento",
             "Síntesis ilustrativa: el solar está calificado como dotacional; son compatibles la zona verde, el huerto y las pistas. "
             "Un aparcamiento en superficie requeriría una modificación puntual del planeamiento."),
        ],
        "eprops": [
            ("verde", "Parque de barrio con juegos y sombra",
             "Zona verde con arbolado, juegos infantiles, bancos y fuente. Mantenimiento incluido en el contrato de parques del distrito.",
             "Recoge la propuesta ciudadana más apoyada y el argumento sobre el déficit de zonas verdes."),
            ("urban", "Huerto urbano y zona verde",
             "Mitad del solar como huerto urbano gestionado por asociaciones con convenio municipal; la otra mitad, zona verde abierta con sombra.",
             "Basada en la propuesta ciudadana del huerto y en el argumento del uso mixto."),
            ("urban", "Pistas deportivas y zona de estancia",
             "Dos pistas polideportivas de uso libre con horario, iluminación eficiente y una zona de estancia con sombra para mayores.",
             "Basada en las propuestas ciudadanas de pistas y de zona de estancia, y en el argumento sobre el ruido nocturno."),
        ],
    },
    {   # PUBLICAR
        "key": "publicar", "phase": "publicar",
        "title": "Autobuses nocturnos los fines de semana",
        "body": "Los viernes y sábados por la noche no hay transporte público después de las 23:30. ¿Creamos líneas nocturnas de "
                "autobús los fines de semana, con qué recorridos y frecuencia?",
        "materia": "Movilidad", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Valladolid",
        "created_ago": 75, "delib_started_ago": 70, "prop_started_ago": 56, "vote_started_ago": 42, "supports": 122,
        "experts": ["transp", "nocturna"],
        "args": [
            ("favor", "Mucha gente trabaja de noche en hostelería, limpieza o sanidad y no tiene cómo volver a casa.", 12),
            ("favor", "Un autobús nocturno reduce los trayectos en coche después de beber alcohol.", 9),
            ("contra", "Con pocos viajeros, el coste por persona será muy alto.", 6),
            ("matiz", "Empezar con dos líneas circulares que pasen por los barrios más poblados y medir la demanda.", 10),
            ("matiz", "Las paradas nocturnas deben estar bien iluminadas y cerca de zonas con actividad.", 5),
            ("contra", "El ruido de los autobuses de madrugada puede molestar en calles estrechas.", 2),
            ("favor", "Da autonomía a los jóvenes y tranquilidad a sus familias.", 4),
            ("matiz", "Coordinar los horarios con el último tren y con los taxis de la estación.", 3),
        ],
        "props": [
            ("Dos líneas circulares nocturnas viernes y sábados, cada 30 minutos.", 44, 10),
            ("Servicio a demanda con reserva por aplicación.", 21, 5),
            ("Prolongar las líneas actuales hasta las 2:00.", 30, 7),
            ("Parada a demanda para mujeres y menores entre paradas.", 26, 8),
            ("Llevar una línea hasta el polígono industrial para los turnos de noche.", 17, 4),
        ],
        "cdocs": [
            ("dato", "Horarios del último servicio por línea",
             "Hemos recopilado los horarios publicados: el último autobús sale entre las 22:45 y las 23:30 según la línea.", ""),
            ("noticia", "Experiencias de búhos en otras ciudades",
             "Varias ciudades medianas mantienen líneas nocturnas de fin de semana; la ocupación suele concentrarse entre la 1 y las 4 h.", ""),
        ],
        "edocs": [
            ("informe", "transp", "Informe técnico: demanda nocturna estimada",
             "Resumen ilustrativo: aprox. 2.300 desplazamientos por noche de viernes o sábado entre las 0 y las 6 h; un 60 % en coche "
             "privado o taxi."),
            ("datos", "transp", "Datos: coste por opción",
             "Estimación ilustrativa (aprox.) anual:\n- Dos líneas circulares: 310.000 €\n- Servicio a demanda: 260.000 € + aplicación\n"
             "- Prolongar las líneas actuales: 420.000 €"),
        ],
        "eprops": [
            ("transp", "Dos líneas nocturnas circulares",
             "Dos líneas circulares viernes, sábados y vísperas de festivo, de 23:30 a 5:30, cada 30 minutos, con parada a demanda "
             "entre paradas para quien viaje sola o solo.",
             "Recoge la propuesta ciudadana más apoyada y la de parada a demanda, y el argumento de empezar por los barrios más poblados."),
            ("nocturna", "Prolongar las líneas actuales hasta las 2:00",
             "Ampliar el horario de las líneas diurnas con más demanda hasta las 2:00 los viernes y sábados.",
             "Basada en la propuesta ciudadana de prolongar las líneas actuales."),
            ("transp", "Servicio nocturno a demanda",
             "Microbuses con reserva por aplicación o teléfono entre las 23:30 y las 5:30 los fines de semana.",
             "Basada en la propuesta ciudadana de servicio a demanda y en el argumento del coste por viajero."),
        ],
    },
]


# ── v55: ARCHIVOS reales en las bibliotecas (gráficos PNG y PDF generados aquí) ──
# Gráfico ciudadano por caso: (título, explicación de las barras, valores, sufijo)
CHARTS = {
    "convocar": ("Gráfico: parques y plazas según su fuente de agua",
                 "Recuento vecinal (aprox.) en 38 parques y plazas. Barra verde: con fuente que funciona (17). "
                 "Barra azul: sin ninguna fuente (15). Barra naranja: con la fuente estropeada (6).", [17, 15, 6], ""),
    "deliberar-a": ("Gráfico: ocupación de la sala de estudio por franja horaria",
                    "Ocupación media observada en época de exámenes (aprox., %). Verde: de 10 a 14 h. Azul: de 17 a 21 h. "
                    "Naranja: de 21 a 24 h (estimación).", [95, 80, 40], "%"),
    "deliberar-b": ("Gráfico: vehículos mal aparcados contados en un paseo",
                    "Recuento vecinal en un mismo recorrido (aprox.). Verde: bien aparcados (34). Azul: en mitad de la acera (21). "
                    "Naranja: bloqueando un paso de peatones (7).", [34, 21, 7], ""),
    "proponer-a": ("Gráfico: temperatura del suelo del patio a las 13 h",
                   "Medidas hechas por familias con termómetro de infrarrojos (aprox., grados). Verde: bajo un árbol (31). "
                   "Azul: asfalto al sol (52). Naranja: caucho de juegos al sol (58).", [31, 52, 58], ""),
    "proponer-b": ("Gráfico: hogares por tamaño de núcleo",
                   "Distribución ilustrativa (aprox., %) de los hogares del concejo. Verde: núcleo principal (45). "
                   "Azul: pueblos de 50 a 200 habitantes (35). Naranja: caseríos dispersos (20).", [45, 35, 20], "%"),
    "votar": ("Gráfico: qué uso preferían las aportaciones",
              "Reparto (aprox., %) de los argumentos y propuestas según el uso que defendían. Verde: zona verde (46). "
              "Azul: aparcamiento disuasorio (31). Naranja: equipamiento deportivo (23).", [46, 31, 23], "%"),
    "publicar": ("Gráfico: viajes nocturnos estimados por noche",
                 "Estimación ilustrativa (aprox.) de viajes en una noche de sábado. Verde: 23–1 h (1.200). Azul: 1–3 h (700). "
                 "Naranja: 3–6 h (300).", [1200, 700, 300], ""),
}
# Enlaces a fuentes OFICIALES, reales y estables (sin inventar noticias)
OFFICIAL_LINKS = [
    ("dato", "Cifras de población del INE", "Instituto Nacional de Estadística: padrón y cifras de población para dimensionar la propuesta.",
     "https://www.ine.es/"),
    ("enlace", "Catálogo de datos abiertos de las administraciones", "Portal oficial de datos abiertos (datos.gob.es).",
     "https://datos.gob.es/"),
]


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _insert_cdoc(conn, did, uid, kind, title, text, url, phase, created, proposal_id=None, file_name=None, raw=None):
    import hashlib
    conn.execute("INSERT INTO citizen_docs(debate_id,user_id,kind,title,text,url,phase,created,proposal_id,file_name,"
                 "mime_type,file_size,data_b64,sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (did, uid, kind, title, text or None, url or None, phase, created, proposal_id, file_name,
                  ("image/png" if (file_name or "").endswith(".png") else "application/pdf") if file_name else None,
                  len(raw) if raw else None, _b64(raw) if raw else None,
                  hashlib.sha256(raw).hexdigest() if raw else None))


def _formal_pdf(c, title, text, just, author):
    name, spec = (EXPERTS[author][0], EXPERTS[author][1]) if author in EXPERTS else ("", "")
    paras = ["Asunto: " + c["title"], "", "Qué se propone", text, ""]
    if just:
        paras += ["En qué se basa (deliberación y propuestas ciudadanas)", just, ""]
    paras += ["Cómo se pondría en marcha",
              "- Fase 1: estudio detallado y consulta a los servicios municipales afectados.",
              "- Fase 2: puesta en marcha y seguimiento con datos públicos durante el primer año.",
              "- Fase 3: evaluación y ajuste según los resultados.", "",
              "Las cifras de este documento son ilustrativas (aprox.)."]
    return demo_files.pdf("Documento de la propuesta: " + title, paras,
                          subtitle=f"Propuesta de expertos · {name}" + (f" · {spec}" if spec else ""))


def _slug(t: str) -> str:
    import re
    import unicodedata
    t = unicodedata.normalize("NFD", t or "").encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"[^a-z0-9]+", "-", t).strip("-")[:50] or "documento"


def _is_super(user) -> bool:
    return bool(user and user.get("is_admin"))


def _demo_citizens(conn) -> list:
    rows = [int(dict(r)["id"]) for r in conn.execute(
        "SELECT id FROM users WHERE COALESCE(is_demo,0)=1 AND email LIKE ? ORDER BY id", ("ciudadania-demo-%",)).fetchall()]
    now = db.now()
    for i in range(len(rows), N_CITIZENS):
        email = f"ciudadania-demo-{i + 1:03d}@demo.sferacivitas.invalid"
        ex = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if ex:
            conn.execute("UPDATE users SET is_demo=1 WHERE id=?", (dict(ex)["id"],))
            rows.append(int(dict(ex)["id"])); continue
        # Contraseña INUTILIZABLE (no es un hash válido): nadie puede entrar con estas cuentas.
        cur = conn.execute("INSERT INTO users(email,pass_hash,verified,loa,is_admin,is_expert,is_demo,created) "
                           "VALUES(?,?,0,'open',0,0,1,?)", (email, "demo-disabled$" + secrets.token_hex(16), now - 90 * DAY),
                           returning=True)
        rows.append(int(cur.lastrowid))
    conn.commit()
    return rows


def _profile(conn, admin, key) -> int:
    name, spec, cred, org = EXPERTS[key]
    r = conn.execute("SELECT id FROM expert_profiles WHERE display_name=? AND COALESCE(is_demo,0)=1", (name,)).fetchone()
    if r:
        return int(dict(r)["id"])
    now = db.now()
    cur = conn.execute("INSERT INTO expert_profiles(user_id,display_name,specialty,credentials,organization,is_demo,"
                       "created_by,created,updated) VALUES(NULL,?,?,?,?,1,?,?,?)",
                       (name, spec, cred, org or None, admin["id"], now, now), returning=True)
    conn.commit()
    return int(cur.lastrowid)


def _assign_profile(conn, did, pid, admin, at):
    if not conn.execute("SELECT 1 FROM debate_expert_profiles WHERE debate_id=? AND profile_id=?", (did, pid)).fetchone():
        conn.execute("INSERT INTO debate_expert_profiles(debate_id,profile_id,assigned_by,assigned_at) VALUES(?,?,?,?)",
                     (did, pid, admin["id"], at))


def _seed_case(admin, c, citizens) -> dict:
    """Crea un caso completo. Devuelve {did, pending_close}. Sin papeletas del servidor."""
    import service as s
    import docs_service as ds
    now = db.now()
    ph = c["phase"]
    key = f"demo-{DEMO_VERSION}-{c['key']}"
    created = now - c["created_ago"] * DAY
    creator = citizens[sum(map(ord, c["key"])) % 20]
    with db.session() as conn:
        cur = conn.execute(
            "INSERT INTO debates(title,body,materia,administracion,nivel,territorio,phase,visibility,created_by,conv_status,"
            "conv_deadline,created,hidden,is_demo,demo_key,plan) VALUES(?,?,?,?,?,?,'convocar','public',?,'recabando',?,?,0,1,?,'estandar')",
            (c["title"], c["body"], c["materia"], c["administracion"], c["nivel"], c["territorio"], creator,
             created + s.CONV_DIAS * DAY, created, key), returning=True)
        did = int(cur.lastrowid)
        # Apoyos de convocatoria (ciudadanía ficticia). Pasado Convocar: por encima del quórum real.
        n_sup = min(int(c.get("supports", 0)), len(citizens))
        for i, uid in enumerate(citizens[:n_sup]):
            conn.execute("INSERT INTO supports(debate_id,user_id,via,created) VALUES(?,?,'abierto',?)",
                         (did, uid, created + (i % 9) * DAY / 3))
        if ph == "convocar":
            conn.execute("UPDATE debates SET conv_deadline=? WHERE id=?", (now + c["deadline_in"] * DAY, did))
        else:
            delib_start = now - c["delib_started_ago"] * DAY
            conn.execute("UPDATE debates SET phase='deliberar', conv_status='avanzado', qualified_track='abierto', "
                         "phase_deadline=? WHERE id=?", (now + 30 * DAY, did))
            # Expertos del asunto (perfiles ficticios, sin cuenta)
            for k in c.get("experts", []):
                _assign_profile(conn, did, _profile(conn, admin, k), admin, delib_start)
            # Argumentos + «Útil»
            arg_ids = []
            for i, (st, txt, n_util) in enumerate(c.get("args", [])):
                uid = citizens[(i * 7 + 3) % len(citizens)]
                r = conn.execute("INSERT INTO arguments(debate_id,user_id,stance,text,created) VALUES(?,?,?,?,?)",
                                 (did, uid, st, txt, delib_start + (i + 1) * DAY / 2), returning=True)
                arg_ids.append(int(r.lastrowid))
                for j in range(n_util):
                    conn.execute("INSERT INTO argument_utiles(argument_id,user_id,created) VALUES(?,?,?)",
                                 (arg_ids[-1], citizens[(j * 5 + i + 11) % len(citizens)], delib_start + DAY))
        conn.commit()
    # Aportaciones documentales ciudadanas (en la fase en la que «llegaron»)
    with db.session() as conn:
        for i, (kind, title, text, url) in enumerate(c.get("cdocs", [])):
            uid = creator if i == 0 else citizens[(i * 13 + 21) % len(citizens)]   # quien convoca aporta el primero
            _insert_cdoc(conn, did, uid, kind, title, text, url,
                         "convocar" if (ph == "convocar" or i == 0) else "deliberar", created + (i + 1) * DAY)
        ch = CHARTS.get(c["key"])
        if ch:                                   # gráfico (PNG real) aportado por la ciudadanía
            _insert_cdoc(conn, did, citizens[(len(c["key"]) * 17 + 9) % len(citizens)], "dato", ch[0], ch[1], "",
                         "convocar" if ph == "convocar" else "deliberar", created + 2 * DAY + 3600,
                         file_name="grafico-" + c["key"] + ".png", raw=demo_files.bar_chart_png(ch[2], suffix=ch[3]))
        if ph == "convocar":                     # un resumen en PDF de quien convoca (para reunir apoyos)
            _insert_cdoc(conn, did, creator, "estudio", "Resumen de la propuesta en una página (PDF)",
                         "Por qué pedimos que se debata, en una página.", "", "convocar", created + 3600,
                         file_name="resumen-propuesta.pdf",
                         raw=demo_files.pdf(c["title"], [c["body"], "", "Por qué importa",
                                                         "- Afecta a mucha gente cada día, sobre todo en verano.",
                                                         "- Es una mejora concreta, medible y de coste moderado.", "",
                                                         "Si estás de acuerdo en que se debata, apoya el asunto en Sfera Civitas."],
                                            subtitle="Documento aportado por quien convoca el asunto"))
        conn.commit()
    # Documentación de expertos (atribuida a su perfil; created_by = admin, auditoría)
    for dtype, ek, title, text in c.get("edocs", []):
        with db.session() as conn:
            pid = _profile(conn, admin, ek)
            _assign_profile(conn, did, pid, admin, now); conn.commit()
        if dtype == "datos":                     # tablas de datos: como PDF (archivo real)
            raw = demo_files.pdf(title, text.split("\n"), subtitle=f"{EXPERTS[ek][0]} · {EXPERTS[ek][1]}")
            ds.create_document(did, admin, dtype, title, "file", None, _slug(title) + ".pdf", "application/pdf",
                               _b64(raw), author_profile_id=pid)
        else:
            ds.create_document(did, admin, dtype, title, "text", text, author_profile_id=pid)
    pending = None
    if ph in ("proponer", "votar", "publicar"):
        with db.session() as conn:
            prop_start = now - c["prop_started_ago"] * DAY
            conn.execute("UPDATE debates SET phase='proponer', phase_deadline=? WHERE id=?", (now + 30 * DAY, did))
            for i, (txt, n_sup, n_util) in enumerate(c.get("props", [])):
                uid = citizens[(i * 11 + 5) % len(citizens)]
                r = conn.execute("INSERT INTO proposals(debate_id,user_id,text,created) VALUES(?,?,?,?)",
                                 (did, uid, txt, prop_start + (i + 1) * DAY / 2), returning=True)
                pid_ = int(r.lastrowid)
                if i == 0:                       # la más apoyada: su autor/a adjunta su propuesta detallada (PDF)
                    _insert_cdoc(conn, did, uid, "estudio", "Mi propuesta explicada con más detalle (PDF)",
                                 "Desarrollo de la propuesta: qué, dónde, cuánto cuesta (aprox.) y cómo medir si funciona.", "",
                                 "proponer", prop_start + (i + 1) * DAY / 2 + 3600, proposal_id=pid_,
                                 file_name="propuesta-detallada.pdf",
                                 raw=demo_files.pdf("Propuesta ciudadana: " + c["title"],
                                                    [txt, "", "Cómo lo haría",
                                                     "- Empezar por donde más se necesita, con un plazo claro.",
                                                     "- Publicar el coste real y revisarlo al año.",
                                                     "- Preguntar a quienes lo usan si ha mejorado.", "",
                                                     "Cifras ilustrativas (aprox.)."],
                                                    subtitle="Documento aportado por quien presentó la propuesta"))
                elif i == 1:                     # otra: un enlace a una fuente oficial
                    k, t, tx, u = OFFICIAL_LINKS[(len(c["key"]) + i) % len(OFFICIAL_LINKS)]
                    _insert_cdoc(conn, did, uid, k, t, tx, u, "proponer", prop_start + (i + 1) * DAY / 2 + 3600,
                                 proposal_id=pid_)
                for j in range(n_sup):
                    conn.execute("INSERT INTO proposal_supports(proposal_id,user_id,created) VALUES(?,?,?)",
                                 (pid_, citizens[(j * 3 + i) % len(citizens)], prop_start + DAY))
                for j in range(n_util):
                    conn.execute("INSERT INTO proposal_utiles(proposal_id,user_id,created) VALUES(?,?,?)",
                                 (pid_, citizens[(j * 7 + i + 2) % len(citizens)], prop_start + DAY))
            conn.commit()
        for ek, title, text, just in c.get("eprops", []):
            with db.session() as conn:
                pid = _profile(conn, admin, ek)
                _assign_profile(conn, did, pid, admin, now); conn.commit()
            raw = _formal_pdf(c, title, text, just, ek)
            s.add_expert_proposal(did, admin, title, text, just, author_profile_id=pid,
                                  formal_file_name="propuesta-" + _slug(title) + ".pdf", formal_data_b64=_b64(raw))
        if ph in ("votar", "publicar"):
            s.set_phase(did, "votar", admin)        # papeleta = propuestas expertas + «Ninguna»
            with db.session() as conn:
                e = s._open_election_row(conn, did)
                if ph == "votar":
                    dl = now + c["deadline_in"] * DAY
                    conn.execute("UPDATE debates SET phase_deadline=?, cierre=? WHERE id=?", (dl, dl, did))
                else:
                    pending = int(e["id"])           # la web del admin vota (cripto real) y cierra
                    dl = now + 2 * DAY
                    conn.execute("UPDATE debates SET phase_deadline=?, cierre=? WHERE id=?", (dl, dl, did))
                conn.commit()
        else:
            with db.session() as conn:
                conn.execute("UPDATE debates SET phase_deadline=? WHERE id=?", (now + c["deadline_in"] * DAY, did))
                conn.commit()
    elif ph == "deliberar":
        with db.session() as conn:
            conn.execute("UPDATE debates SET phase_deadline=? WHERE id=?", (now + c["deadline_in"] * DAY, did))
            conn.commit()
    # Los avisos generados durante la siembra van a ciudadanía ficticia/expertos: se retiran.
    with db.session() as conn:
        conn.execute("DELETE FROM notifications WHERE debate_id=? AND user_id IN (SELECT id FROM users WHERE COALESCE(is_demo,0)=1)", (did,))
        conn.commit()
    return {"did": did, "pending_close": pending}


def seed(admin, max_new=None) -> dict:
    """Crea los casos de demostración que falten (idempotente por demo_key).
    max_new: como mucho N casos nuevos por llamada (la web llama en bucle para no
    superar el tiempo máximo del reenvío de Netlify). Devuelve `remaining`."""
    if not _is_super(admin):
        raise SferaError(403, "Solo la administración general puede crear casos de demostración")
    with db.session() as conn:
        citizens = _demo_citizens(conn)
    log, pending = [], []
    created_now, remaining = 0, 0
    for c in CASES:
        key = f"demo-{DEMO_VERSION}-{c['key']}"
        with db.session() as conn:
            ex = conn.execute("SELECT id, phase FROM debates WHERE demo_key=?", (key,)).fetchone()
            ex = dict(ex) if ex else None
            open_e = None
            if ex and c["phase"] == "publicar" and ex["phase"] == "votar":
                import service as s
                e = s._open_election_row(conn, ex["id"])
                open_e = int(e["id"]) if e else None
        if ex:
            log.append({"key": c["key"], "phase": c["phase"], "id": ex["id"], "status": "ya existía"})
            if open_e:
                pending.append({"debate_id": ex["id"], "election_id": open_e})
            continue
        if max_new is not None and created_now >= max_new:
            remaining += 1
            continue
        try:
            created_now += 1
            r = _seed_case(admin, c, citizens)
            log.append({"key": c["key"], "phase": c["phase"], "id": r["did"], "status": "creado"})
            if r["pending_close"]:
                pending.append({"debate_id": r["did"], "election_id": r["pending_close"]})
        except SferaError as e:
            log.append({"key": c["key"], "phase": c["phase"], "status": "error", "error": e.msg})
        except Exception as e:                   # fallo inesperado: se informa del caso y se sigue (detalle en el registro del servidor)
            import traceback; traceback.print_exc()
            log.append({"key": c["key"], "phase": c["phase"], "status": "error", "error": type(e).__name__})
    return {"ok": True, "items": log, "pending_close": pending, "remaining": remaining}


# ── Ocultar / mostrar (reversible) ─────────────────────────────────────────────
def _legacy_ids(conn) -> list:
    rows = conn.execute("SELECT id, title, COALESCE(is_demo,0) AS is_demo FROM debates WHERE org_id IS NULL").fetchall()
    out = []
    for r in rows:
        r = dict(r)
        t = r["title"] or ""
        if r["is_demo"]:
            continue
        if t.startswith(LEGACY_PREFIX) or t in LEGACY_TITLES:
            out.append(int(r["id"]))
    return out


def _demo_ids(conn) -> list:
    return [int(dict(r)["id"]) for r in conn.execute(
        "SELECT id FROM debates WHERE COALESCE(is_demo,0)=1").fetchall()]


def status(admin) -> dict:
    if not _is_super(admin):
        raise SferaError(403, "Solo la administración general puede ver esto")
    with db.session() as conn:
        def cnt(ids):
            if not ids:
                return {"total": 0, "hidden": 0}
            h = conn.execute(f"SELECT COUNT(*) AS n FROM debates WHERE id IN ({','.join('?' * len(ids))}) AND "
                             "(COALESCE(hidden,0)=1 OR id IN (SELECT target_id FROM content_moderation WHERE "
                             "target_type='debate' AND status IN ('hidden','removed','auto_hidden')))", tuple(ids)).fetchone()
            return {"total": len(ids), "hidden": int(dict(h)["n"])}
        return {"legacy": cnt(_legacy_ids(conn)), "demo": cnt(_demo_ids(conn)),
                "cases": len(CASES), "version": DEMO_VERSION}


def set_visibility(admin, scope: str, action: str) -> dict:
    """scope: 'legacy' (ejemplos antiguos) | 'demo' (casos de demostración); action: hide | show.
    Ocultar = archivar (hidden=1, demo_archived=1). Mostrar deshace SOLO lo archivado por
    este botón (y lo que el botón antiguo ocultó por moderación). No borra nada."""
    if not _is_super(admin):
        raise SferaError(403, "Solo la administración general puede ocultar o mostrar ejemplos")
    if scope not in ("legacy", "demo") or action not in ("hide", "show"):
        raise SferaError(400, "Parámetros no válidos")
    now = db.now()
    with db.session() as conn:
        ids = _legacy_ids(conn) if scope == "legacy" else _demo_ids(conn)
        done = []
        for did in ids:
            if action == "hide":
                conn.execute("UPDATE debates SET hidden=1, demo_archived=1 WHERE id=?", (did,))
                done.append(did)
            else:
                r = conn.execute("SELECT COALESCE(hidden,0) AS h, COALESCE(demo_archived,0) AS a FROM debates WHERE id=?",
                                 (did,)).fetchone()
                r = dict(r)
                mod = conn.execute("SELECT status, note FROM content_moderation WHERE target_type='debate' AND target_id=?",
                                   (did,)).fetchone()
                mod = dict(mod) if mod else None
                old_btn = bool(mod and mod["status"] == "hidden" and (mod.get("note") or "").startswith("Ejemplo antiguo"))
                if r["a"] or old_btn:
                    conn.execute("UPDATE debates SET hidden=0, demo_archived=0 WHERE id=? AND COALESCE(demo_archived,0)=1", (did,))
                    if old_btn:
                        conn.execute("UPDATE content_moderation SET status='kept', note=?, updated=?, updated_by=? "
                                     "WHERE target_type='debate' AND target_id=?",
                                     ("Ejemplo antiguo visible", now, admin["id"], did))
                    done.append(did)
        conn.commit()
    return {"ok": True, "scope": scope, "action": action, "ids": done}
