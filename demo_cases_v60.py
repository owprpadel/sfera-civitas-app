"""
demo_cases_v60.py — CASOS ILUSTRATIVOS adicionales (v60, oct-2026).

Objetivo (Carlos, 19-oct): que en la app haya SIEMPRE al menos 3 asuntos en cada fase
(Convocar, Deliberar, Proponer, Votar y Publicar). Se suman a los casos de demo_seed.CASES
con el mismo formato y las mismas reglas: neutrales, no partidistas, cifras ilustrativas
(«aprox.»), expertos y ciudadanía FICTICIOS (sin personas ni instituciones reales).
"""

EXTRA_EXPERTS = {
    "energia": ("Dra. Rocío Benavent Llorca", "Eficiencia energética municipal",
                "Ingeniera industrial; 14 años en auditorías energéticas de alumbrado y edificios públicos.",
                "Agencia pública de la energía (ámbito autonómico)"),
    "deporte": ("Iñaki Zubeldia Arana", "Gestión de instalaciones deportivas",
                "Licenciado en Ciencias de la Actividad Física; ha gestionado polideportivos municipales durante 16 años.",
                ""),
    "social": ("Dra. Pilar Escartín Lahoz", "Servicios sociales y envejecimiento",
               "Trabajadora social y doctora en Sociología; investiga la soledad no deseada en personas mayores.",
               "Universidad pública (área de Trabajo Social)"),
    "salud": ("Dr. Manuel Arrieta Ocón", "Salud escolar y pediatría preventiva",
              "Pediatra; coordina programas de cribado en atención primaria desde hace 12 años.",
              "Servicio público de salud (ámbito autonómico)"),
    "vivienda": ("Cristina Llamas Ferrer", "Políticas de vivienda",
                 "Economista urbana; analiza el mercado del alquiler y el uso turístico de viviendas.",
                 "Centro público de investigación (área de vivienda)"),
    "nutri": ("Dra. Elena Prats Montoliu", "Nutrición infantil",
              "Dietista-nutricionista; diseña menús escolares y programas de alimentación en verano.",
              ""),
}

EXTRA_CASES = [
    {   # CONVOCAR (B)
        "key": "convocar-b", "phase": "convocar",
        "title": "Bancos y sombra en las paradas de autobús",
        "body": "Muchas paradas de autobús no tienen marquesina ni banco. En verano se espera al sol y las personas mayores "
                "no tienen dónde sentarse. Propongo que todas las paradas con más uso tengan, como mínimo, sombra y un banco.",
        "materia": "Movilidad y transporte", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Murcia",
        "created_ago": 4, "deadline_in": 10, "supports": 27,
        "cdocs": [
            ("dato", "Paradas sin marquesina en mi barrio",
             "He recorrido 22 paradas de las líneas que uso: aprox. 9 no tienen ni sombra ni banco. Recuento personal, no oficial.", ""),
            ("otro", "Por qué importa",
             "Esperar 15 minutos al sol en julio es un problema real para personas mayores, embarazadas y familias con niños.", ""),
        ],
    },
    {   # CONVOCAR (C)
        "key": "convocar-c", "phase": "convocar",
        "title": "Comedores escolares abiertos en verano para el alumnado con beca",
        "body": "Durante el curso, el alumnado con beca de comedor tiene garantizada una comida completa al día. En julio y agosto "
                "esa comida desaparece. ¿Abrimos algunos comedores escolares en verano para quien lo necesite?",
        "materia": "Educación", "administracion": "Comunidad Autónoma", "nivel": "ccaa", "territorio": "Castilla-La Mancha",
        "created_ago": 6, "deadline_in": 8, "supports": 58,
        "cdocs": [
            ("estudio", "Alimentación infantil en vacaciones",
             "Diversos informes de entidades sociales señalan que en verano empeora la alimentación de los niños de familias con "
             "menos recursos. Resumen de lectura, sin cifras propias.", ""),
            ("enlace", "Portal de datos abiertos del Gobierno de España",
             "Para buscar datos de becas de comedor por comunidad autónoma.", "https://datos.gob.es"),
        ],
    },
    {   # DELIBERAR (C)
        "key": "deliberar-c", "phase": "deliberar",
        "title": "Limitar las nuevas licencias de pisos turísticos en el casco histórico",
        "body": "En el casco histórico han crecido mucho las viviendas de uso turístico. Unos piden limitar las nuevas licencias "
                "para que haya más vivienda para residentes; otros temen por el empleo y el comercio. ¿Qué hacemos?",
        "materia": "Urbanismo y vivienda", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Cádiz",
        "created_ago": 21, "delib_started_ago": 5, "deadline_in": 9, "supports": 112,
        "experts": ["vivienda", "juridico"],
        "args": [
            ("favor", "Cada piso turístico es una vivienda menos para quien vive y trabaja en la ciudad todo el año.", 12),
            ("contra", "Muchas familias complementan sus ingresos alquilando un piso heredado; limitar les perjudica.", 7),
            ("matiz", "Se podría limitar solo en las calles con más concentración, no en todo el casco.", 10),
            ("favor", "El comercio de barrio desaparece cuando no quedan vecinos que compren a diario.", 6),
            ("contra", "El turismo sostiene buena parte del empleo local; hay que medir el efecto antes de decidir.", 8),
            ("matiz", "Antes que limitar, conviene inspeccionar los pisos que funcionan sin licencia.", 9),
            ("favor", "Los precios del alquiler para residentes han subido mucho en los últimos años.", 4),
            ("matiz", "Cualquier límite debería revisarse con datos al cabo de dos años.", 3),
        ],
        "cdocs": [
            ("dato", "Recuento de anuncios en el casco histórico",
             "Contamos aprox. 640 anuncios activos de alquiler turístico en el casco en una semana de septiembre. Recuento vecinal.", ""),
            ("noticia", "Otras ciudades han regulado por zonas",
             "Algunas ciudades españolas han fijado zonas donde no se conceden nuevas licencias, con revisiones periódicas.", ""),
        ],
        "edocs": [
            ("informe", "vivienda", "Informe técnico: peso de la vivienda turística",
             "Resumen ilustrativo: en el casco histórico, aprox. 1 de cada 6 viviendas tiene uso turístico; en el resto de la "
             "ciudad, 1 de cada 40. El alquiler residencial disponible ha bajado aprox. un 20 % en cinco años."),
            ("dictamen", "juridico", "Dictamen: qué puede regular el Ayuntamiento",
             "Síntesis ilustrativa: el planeamiento urbanístico puede limitar usos por zonas de forma motivada y proporcionada. "
             "Las licencias ya concedidas se respetan; la limitación afecta a las nuevas."),
        ],
    },
    {   # PROPONER (C)
        "key": "proponer-c", "phase": "proponer",
        "title": "Revisión gratuita de vista y oído en los colegios de primaria",
        "body": "Muchos problemas de visión o audición se detectan tarde y afectan al rendimiento escolar. ¿Hacemos una revisión "
                "gratuita de vista y oído en los colegios públicos de primaria, en qué cursos y con qué seguimiento?",
        "materia": "Sanidad", "administracion": "Comunidad Autónoma", "nivel": "ccaa", "territorio": "Aragón",
        "created_ago": 36, "delib_started_ago": 28, "prop_started_ago": 5, "deadline_in": 9, "supports": 127,
        "experts": ["salud", "pedag"],
        "args": [
            ("favor", "Un niño que no ve bien la pizarra puede parecer distraído; detectarlo pronto cambia su curso escolar.", 13),
            ("contra", "Los centros de salud ya hacen revisiones; duplicarlas en el colegio puede ser un gasto innecesario.", 5),
            ("matiz", "Bastaría con hacerlo en 1.º y 4.º de primaria, que es cuando más se detectan problemas.", 9),
            ("favor", "No todas las familias pueden pagar una revisión privada en la óptica.", 7),
            ("matiz", "Lo importante es el seguimiento: si se detecta algo, que la familia tenga cita rápida.", 8),
            ("contra", "Organizarlo en horario lectivo quita tiempo de clase.", 2),
        ],
        "props": [
            ("Revisión de vista y oído en 1.º y 4.º de primaria en todos los colegios públicos.", 48, 11),
            ("Cita prioritaria en el centro de salud si la revisión detecta un problema.", 37, 9),
            ("Gafas gratuitas para las familias con menos ingresos.", 29, 6),
            ("Informar a las familias por escrito del resultado y de qué hacer.", 18, 4),
        ],
        "cdocs": [
            ("dato", "Lo que nos cuentan en la AMPA",
             "En nuestro colegio, de 50 familias de 4.º, aprox. 8 descubrieron en el último año que su hijo necesitaba gafas.", ""),
        ],
        "edocs": [
            ("informe", "salud", "Informe técnico: revisiones en edad escolar",
             "Resumen ilustrativo: aprox. 1 de cada 5 niños de primaria tiene algún defecto visual sin corregir. Los cribados en el "
             "propio centro aumentan la detección cuando van unidos a una cita de seguimiento."),
        ],
        "eprops": [
            ("salud", "Cribado en 1.º y 4.º con cita de seguimiento",
             "Revisión de vista y oído en 1.º y 4.º de primaria en el propio colegio, con cita prioritaria en el centro de salud "
             "cuando se detecte un problema.",
             "Recoge las dos propuestas ciudadanas más apoyadas y el argumento de que lo importante es el seguimiento."),
        ],
    },
    {   # VOTAR (B)
        "key": "votar-b", "phase": "votar",
        "title": "Cambiar el alumbrado público a LED y reducir su intensidad de madrugada",
        "body": "El alumbrado público es uno de los mayores gastos eléctricos del municipio. ¿Lo cambiamos a LED, reducimos su "
                "intensidad de madrugada o hacemos ambas cosas? Se vota entre las propuestas de los expertos.",
        "materia": "Medio ambiente", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Logroño",
        "created_ago": 48, "delib_started_ago": 42, "prop_started_ago": 26, "vote_started_ago": 3, "deadline_in": 11,
        "supports": 117, "experts": ["energia", "segvial"],
        "args": [
            ("favor", "El LED gasta mucho menos y se amortiza en pocos años.", 12),
            ("contra", "Bajar la luz de madrugada puede aumentar la sensación de inseguridad.", 8),
            ("matiz", "Se puede reducir la intensidad en calles residenciales y mantenerla en pasos de peatones y cruces.", 11),
            ("favor", "Menos contaminación lumínica: se vuelve a ver el cielo y molesta menos a la fauna.", 5),
            ("contra", "El cambio de luminarias tiene un coste inicial alto para el presupuesto de un año.", 4),
            ("matiz", "Conviene empezar por los barrios con luminarias más antiguas.", 6),
        ],
        "props": [
            ("Cambiar todas las luminarias a LED en cuatro años.", 41, 10),
            ("Reducir la intensidad de 1 a 6 h en calles residenciales.", 33, 8),
            ("Mantener la luz completa en pasos de peatones y paradas.", 28, 7),
            ("Sensores de presencia en parques y caminos.", 19, 4),
        ],
        "cdocs": [
            ("dato", "Factura eléctrica del alumbrado",
             "Según el presupuesto municipal publicado, el alumbrado supone aprox. el 40 % del gasto eléctrico del Ayuntamiento.", ""),
        ],
        "edocs": [
            ("informe", "energia", "Informe técnico: ahorro por opción",
             "Estimación ilustrativa (aprox.): el cambio a LED ahorra un 55 % de consumo; la reducción de intensidad de madrugada, "
             "un 15 % adicional. Inversión del cambio completo: aprox. 6 millones de euros, amortizable en 7 años."),
            ("dictamen", "segvial", "Dictamen: seguridad vial y peatonal",
             "Síntesis ilustrativa: la reducción de intensidad es compatible con la seguridad si se mantienen niveles completos en "
             "cruces, pasos de peatones y paradas de transporte."),
        ],
        "eprops": [
            ("energia", "LED en cuatro años y regulación de madrugada",
             "Cambio progresivo a LED en cuatro años, empezando por las luminarias más antiguas, y reducción del 30 % de la intensidad "
             "de 1 a 6 h en calles residenciales.",
             "Combina las dos propuestas ciudadanas más apoyadas y el argumento de empezar por los barrios más antiguos."),
            ("segvial", "LED con luz completa en puntos sensibles",
             "Cambio a LED sin reducción general de intensidad; regulación solo en parques y caminos con sensores de presencia.",
             "Basada en el argumento sobre la sensación de inseguridad y en la propuesta de sensores."),
            ("energia", "Solo cambio a LED",
             "Cambio completo a LED en cuatro años, sin modificar los niveles de iluminación actuales.",
             "Basada en la propuesta ciudadana más apoyada."),
        ],
    },
    {   # VOTAR (C)
        "key": "votar-c", "phase": "votar",
        "title": "Abrir las pistas deportivas municipales hasta las 23:00",
        "body": "Las pistas deportivas municipales al aire libre cierran a las 21:00. Mucha gente trabaja hasta tarde y no puede "
                "usarlas. ¿Ampliamos el horario, en qué pistas y con qué condiciones? Se vota entre las propuestas de los expertos.",
        "materia": "Deporte", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Salamanca",
        "created_ago": 45, "delib_started_ago": 39, "prop_started_ago": 24, "vote_started_ago": 2, "deadline_in": 12,
        "supports": 109, "experts": ["deporte", "gestion"],
        "args": [
            ("favor", "Quien trabaja hasta las 20:00 no tiene tiempo de usar las pistas.", 11),
            ("contra", "El ruido de noche molesta a los vecinos de las pistas que están junto a viviendas.", 9),
            ("matiz", "Ampliar solo en las pistas alejadas de viviendas.", 10),
            ("favor", "Hacer deporte es salud; facilitarlo ahorra gasto sanitario a largo plazo.", 4),
            ("contra", "La iluminación nocturna tiene un coste eléctrico y de mantenimiento.", 3),
            ("matiz", "Probar un verano y medir el uso real por franjas horarias.", 6),
        ],
        "props": [
            ("Abrir hasta las 23:00 de lunes a viernes.", 38, 9),
            ("Ampliar solo en las pistas sin viviendas cerca.", 35, 10),
            ("Reserva por aplicación para evitar conflictos.", 22, 5),
            ("Prueba de un verano con informe de uso.", 20, 6),
        ],
        "cdocs": [
            ("dato", "Ocupación a última hora",
             "Contamos el uso de cuatro pistas una semana de mayo: aprox. 85 % de ocupación entre las 19 y las 21 h.", ""),
        ],
        "edocs": [
            ("informe", "deporte", "Informe técnico: demanda y ubicación de las pistas",
             "Resumen ilustrativo: de 18 pistas al aire libre, 7 están a más de 50 metros de la vivienda más cercana. La demanda "
             "de 19 a 21 h supera la oferta en aprox. un 30 %."),
            ("datos", "gestion", "Datos: coste de ampliar el horario",
             "Estimación ilustrativa (aprox.) por pista y año:\n- Electricidad: 1.900 €\n- Mantenimiento y vigilancia: 3.200 €"),
        ],
        "eprops": [
            ("deporte", "Hasta las 23:00 en las pistas alejadas de viviendas",
             "Ampliar el horario hasta las 23:00 en las 7 pistas alejadas de viviendas, con reserva por aplicación.",
             "Combina la propuesta de ampliar solo donde no hay viviendas y la de reserva por aplicación."),
            ("gestion", "Prueba de un verano en todas las pistas",
             "Ampliar hasta las 23:00 en todas las pistas durante un verano y decidir después con el informe de uso y de quejas.",
             "Basada en la propuesta de prueba y en el argumento de medir antes de decidir."),
            ("deporte", "Hasta las 22:00 en todas las pistas",
             "Ampliar una hora el horario en todas las pistas, de lunes a viernes.",
             "Solución intermedia entre la demanda de horario y el descanso vecinal."),
        ],
    },
    {   # VOTAR (D)
        "key": "votar-d", "phase": "votar",
        "title": "Acompañamiento a personas mayores que viven solas en los pueblos",
        "body": "En los pueblos pequeños de la provincia muchas personas mayores viven solas y lejos de los servicios. ¿Cómo las "
                "acompañamos: visitas periódicas, teleasistencia, voluntariado o una combinación? Se vota entre las propuestas de los expertos.",
        "materia": "Servicios sociales", "administracion": "Diputación provincial", "nivel": "provincia", "territorio": "Teruel",
        "created_ago": 52, "delib_started_ago": 46, "prop_started_ago": 30, "vote_started_ago": 5, "deadline_in": 9,
        "supports": 104, "experts": ["social", "rural"],
        "args": [
            ("favor", "La soledad no deseada afecta a la salud tanto como otras enfermedades.", 14),
            ("matiz", "La teleasistencia ayuda, pero no sustituye a una visita en persona.", 12),
            ("contra", "Con la dispersión de los pueblos, las visitas frecuentes son muy caras.", 6),
            ("favor", "Muchos vecinos jóvenes estarían dispuestos a colaborar como voluntarios.", 5),
            ("matiz", "Hay que coordinarse con el centro de salud y la farmacia, que ya conocen a estas personas.", 8),
            ("contra", "El voluntariado sin formación ni seguimiento no es suficiente.", 3),
        ],
        "props": [
            ("Visita semanal de un profesional en los pueblos de menos de 200 habitantes.", 45, 11),
            ("Teleasistencia gratuita para mayores de 75 años que viven solos.", 39, 9),
            ("Red de voluntariado con formación y coordinación comarcal.", 27, 6),
            ("Transporte a demanda para ir al médico y a la compra.", 24, 5),
        ],
        "cdocs": [
            ("dato", "Personas mayores que viven solas en mi comarca",
             "El padrón muestra aprox. 1.100 personas de más de 75 años que viven solas en los municipios de la comarca.", ""),
        ],
        "edocs": [
            ("informe", "social", "Informe técnico: soledad no deseada en el medio rural",
             "Resumen ilustrativo: aprox. el 30 % de las personas mayores que viven solas en municipios pequeños declara sentirse "
             "sola con frecuencia. Las visitas presenciales periódicas reducen ese porcentaje de forma notable."),
            ("datos", "rural", "Datos: coste por modelo",
             "Estimación ilustrativa (aprox.) anual para la provincia:\n- Visitas semanales: 1,2 millones €\n"
             "- Teleasistencia: 380.000 €\n- Voluntariado coordinado: 150.000 €"),
        ],
        "eprops": [
            ("social", "Visitas semanales y teleasistencia",
             "Visita semanal de un profesional en los pueblos de menos de 200 habitantes y teleasistencia gratuita para mayores de 75 "
             "años que viven solos.",
             "Combina las dos propuestas ciudadanas más apoyadas y el argumento de que la tecnología no sustituye a la visita."),
            ("rural", "Teleasistencia y voluntariado coordinado",
             "Teleasistencia gratuita y una red comarcal de voluntariado formado, coordinada con centros de salud y farmacias.",
             "Basada en las propuestas de teleasistencia y voluntariado y en el argumento de coordinarse con quien ya los conoce."),
            ("social", "Visitas quincenales en todos los pueblos",
             "Visita quincenal de un profesional a todas las personas mayores que viven solas, sin distinguir tamaño de municipio.",
             "Solución de cobertura universal con menor frecuencia."),
        ],
    },
    {   # PUBLICAR (B)
        "key": "publicar-b", "phase": "publicar",
        "title": "Comedor de verano para el alumnado con beca en los colegios del barrio",
        "body": "¿Abrimos uno de los comedores escolares del distrito en julio para el alumnado con beca de comedor?",
        "materia": "Educación", "administracion": "Ayuntamiento", "nivel": "municipio", "territorio": "Zaragoza",
        "created_ago": 80, "delib_started_ago": 74, "prop_started_ago": 60, "vote_started_ago": 46, "supports": 115,
        "experts": ["nutri", "gestion"],
        "args": [
            ("favor", "La beca de comedor es la comida principal del día para muchos niños.", 13),
            ("contra", "Abrir en julio exige personal de cocina y monitores en vacaciones.", 5),
            ("matiz", "Basta con un comedor por distrito, combinado con actividades de verano.", 10),
            ("favor", "Las familias que más lo necesitan no pueden pagar campamentos con comida.", 6),
        ],
        "props": [
            ("Un comedor por distrito abierto en julio con actividades.", 40, 9),
            ("Vales de comida para las familias con beca.", 26, 5),
            ("Ampliar el servicio también a agosto.", 18, 3),
        ],
        "cdocs": [
            ("dato", "Alumnado con beca en el distrito",
             "La AMPA estima aprox. 320 alumnos con beca de comedor en los colegios del distrito.", ""),
        ],
        "edocs": [
            ("informe", "nutri", "Informe técnico: alimentación infantil en verano",
             "Resumen ilustrativo: la falta de comedor en verano reduce la calidad de la dieta de los niños de familias con menos "
             "recursos. Los programas con comida y actividades tienen mayor asistencia que los vales."),
        ],
        "eprops": [
            ("nutri", "Comedor de verano con actividades",
             "Un comedor por distrito abierto en julio, con menú supervisado y actividades de mañana para el alumnado con beca.",
             "Recoge la propuesta ciudadana más apoyada."),
            ("gestion", "Vales de comida en julio",
             "Vales de comida para las familias con beca de comedor durante julio, canjeables en comercios del barrio.",
             "Basada en la propuesta ciudadana de vales."),
        ],
    },
]


# ── Complementos para cumplir el estándar de calidad de los casos (≥8 argumentos, ≥5 propuestas
#    ciudadanas, ≥2 documentos de expertos y 3–5 documentos ciudadanos con algún archivo real) ──
_MORE = {
    "proponer-c": {
        "args": [("favor", "Detectar a tiempo una pérdida de audición evita problemas de lenguaje y de aprendizaje.", 6),
                 ("matiz", "Las familias deberían poder elegir hacer la revisión en el centro de salud si lo prefieren.", 3)],
        "props": [("Formar al profesorado para reconocer señales de problemas de vista u oído.", 15, 3)],
        "cdocs": [("enlace", "Cifras de población del INE", "Para estimar cuántos alumnos hay en 1.º y 4.º de primaria.",
                   "https://www.ine.es/")],
        "edocs": [("datos", "pedag", "Datos: tiempo y coste de la revisión",
                   "Estimación ilustrativa (aprox.):\n- Tiempo por alumno: 10 minutos\n- Coste por alumno revisado: 6 €\n"
                   "- Alumnado de 1.º y 4.º en la comunidad: 26.000")],
    },
    "votar-b": {
        "args": [("favor", "El ahorro en la factura se puede dedicar a otros servicios del barrio.", 3),
                 ("contra", "Algunas luminarias LED dan una luz muy blanca que molesta si no se elige bien el tono.", 2)],
        "props": [("Usar luz cálida en las calles residenciales.", 16, 4)],
        "cdocs": [("otro", "Calles demasiado oscuras",
                   "Vecinos de dos calles señalan tramos donde la luz actual ya es escasa; piden revisarlos antes de reducir.", "")],
    },
    "votar-c": {
        "args": [("favor", "Los jóvenes necesitan espacios para quedar que no sean bares ni centros comerciales.", 5),
                 ("matiz", "Los fines de semana podría bastar con ampliar en verano.", 2)],
        "props": [("Iluminación con temporizador que se apague si la pista está vacía.", 14, 3)],
        "cdocs": [("otro", "Quejas por ruido en una pista",
                   "La asociación vecinal de una de las pistas pide que no se amplíe allí el horario por el ruido.", "")],
    },
    "votar-d": {
        "args": [("favor", "Muchos mayores prefieren seguir en su pueblo si tienen un mínimo de apoyo.", 6),
                 ("matiz", "Las visitas deberían incluir también apoyo con trámites y medicación.", 4)],
        "props": [("Formación en el uso del móvil para videollamadas con la familia.", 15, 3)],
        "cdocs": [("otro", "Testimonio de una farmacéutica rural",
                   "Cuenta que a menudo es la única persona que ve a algunos vecinos mayores en toda la semana.", "")],
    },
    "publicar-b": {
        "args": [("contra", "Los vales llegan a más familias que un único comedor por distrito.", 4),
                 ("matiz", "Coordinar el comedor con los campamentos urbanos que ya existen.", 7),
                 ("favor", "El comedor permite supervisar que la comida es equilibrada.", 5),
                 ("matiz", "El transporte hasta el comedor puede ser un problema para algunas familias.", 2)],
        "props": [("Coordinar el comedor con los campamentos urbanos municipales.", 22, 4),
                  ("Menú adaptado a alergias e intolerancias.", 12, 2)],
        "cdocs": [("otro", "Lo que piden las familias",
                   "En una reunión de la AMPA, la mayoría de familias con beca prefería un comedor con actividades a los vales.", "")],
        "edocs": [("datos", "gestion", "Datos: coste del comedor de verano",
                   "Estimación ilustrativa (aprox.) para julio:\n- Comida y personal de cocina: 4,5 € por menú\n"
                   "- Monitores: 18.000 € por comedor\n- Coste total por comedor: aprox. 45.000 €")],
    },
}
for _c in EXTRA_CASES:
    for _k, _v in _MORE.get(_c["key"], {}).items():
        _c.setdefault(_k, []).extend(_v)

# Gráficos ciudadanos (PNG real) de los casos nuevos
EXTRA_CHARTS = {
    "deliberar-c": ("Gráfico: viviendas turísticas por cada 100 viviendas",
                    "Estimación ilustrativa (aprox.). Verde: casco histórico (16). Azul: ensanche (6). Naranja: resto de la ciudad (2).",
                    [16, 6, 2], ""),
    "proponer-c": ("Gráfico: niños de 4.º con gafas nuevas este curso",
                   "Encuesta de la AMPA (aprox., niños). Verde: ya usaban gafas (9). Azul: las necesitaron este curso (8). "
                   "Naranja: sin revisión todavía (14).", [9, 8, 14], ""),
    "votar-b": ("Gráfico: consumo eléctrico municipal por uso",
                "Reparto ilustrativo (aprox., %). Verde: alumbrado público (40). Azul: edificios (35). Naranja: bombeo de agua (25).",
                [40, 35, 25], "%"),
    "votar-c": ("Gráfico: ocupación de las pistas por franja",
                "Recuento vecinal (aprox., %). Verde: de 17 a 19 h (60). Azul: de 19 a 21 h (85). Naranja: cerradas a partir de las 21 h (0).",
                [60, 85, 0], "%"),
    "votar-d": ("Gráfico: mayores que viven solos por tamaño de municipio",
                "Estimación ilustrativa (aprox., personas). Verde: menos de 200 habitantes (520). Azul: de 200 a 1.000 (380). "
                "Naranja: más de 1.000 (200).", [520, 380, 200], ""),
    "publicar-b": ("Gráfico: alumnado con beca por colegio del distrito",
                   "Estimación de la AMPA (aprox., alumnos). Verde: colegio A (120). Azul: colegio B (110). Naranja: colegio C (90).",
                   [120, 110, 90], ""),
}
