# Prueba: «Crear casos de demostración» por tandas (un caso por llamada, como hace la web).
import os
os.environ.setdefault("SFERA_CERT_SIM_ALLOWED", "1")
os.environ["SFERA_DB"] = "/tmp/sfera_test_seed_tandas.db"
os.environ.setdefault("SFERA_ADMIN_EMAILS", "tadmin@sfera.org")
if os.path.exists("/tmp/sfera_test_seed_tandas.db"):
    os.remove("/tmp/sfera_test_seed_tandas.db")
import db; db.init_db()
import service as s, demo_seed
OK = FAIL = 0
def check(c, l):
    global OK, FAIL
    if c: OK += 1; print("  ok  ·", l)
    else: FAIL += 1; print("  FALLO ·", l)
r = s.register("tadmin@sfera.org", "clave-test-123"); s.verify("tadmin@sfera.org", r.get("codigo_piloto"))
admin = s.get_user(s.login("tadmin@sfera.org", "clave-test-123")["user_id"])
items, pend, vueltas, rem_prev = {}, {}, 0, None
while True:
    vueltas += 1
    r = demo_seed.seed(admin, max_new=1)
    nuevos = [x for x in r["items"] if x["status"] == "creado"]
    check(len(nuevos) <= 1, f"vuelta {vueltas}: como mucho 1 caso nuevo ({len(nuevos)})")
    for x in r["items"]:
        if x["status"] != "ya existía" or x["key"] not in items: items[x["key"]] = x
    for p in r["pending_close"]: pend[p["election_id"]] = p
    if rem_prev is not None: check(r["remaining"] < rem_prev or r["remaining"] == 0, f"quedan {r['remaining']}")
    rem_prev = r["remaining"]
    if not r["remaining"] or vueltas > 12: break
check(vueltas == 7, f"7 vueltas ({vueltas})")
check(len(items) == 7 and all(x["status"] == "creado" for x in items.values()), "7 casos creados en total")
check(not any(x["status"] == "error" for x in items.values()), "sin errores")
check(len(pend) == 1, "el caso Publicar queda pendiente de cierre")
r = demo_seed.seed(admin, max_new=1)
check(r["remaining"] == 0 and all(x["status"] == "ya existía" for x in r["items"]), "otra pulsación: no duplica")
for x in items.values():
    check("ejemplo" not in s.get_debate(x["id"], None)["title"].lower(), "sin «ejemplo» en el título: " + x["key"])
print(f"RESULTADO tandas: {OK} OK · {FAIL} fallos")
