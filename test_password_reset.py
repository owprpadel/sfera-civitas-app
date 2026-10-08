# Prueba: recuperar contraseña con código por email.
import os
os.environ.setdefault("SFERA_CERT_SIM_ALLOWED", "1")
os.environ["SFERA_DB"] = "/tmp/sfera_test_pwreset.db"
if os.path.exists("/tmp/sfera_test_pwreset.db"):
    os.remove("/tmp/sfera_test_pwreset.db")
import db; db.init_db()
import service as s
OK = FAIL = 0
def check(c, l):
    global OK, FAIL
    if c: OK += 1; print("  ok  ·", l)
    else: FAIL += 1; print("  FALLO ·", l)
def err(fn, status, contains, l):
    try: fn()
    except s.SferaError as e:
        check(e.status == status and contains in e.msg, f"{l} ({e.status}: {e.msg})"); return
    check(False, l + " (no dio error)")
s.register("ana@sfera.org", "clave-vieja-1")              # sin verificar a propósito
r = s.forgot_password("ANA@sfera.org ")
check(r["ok"] and r.get("codigo_piloto"), "pide código (mayúsculas/espacios da igual)")
code = r["codigo_piloto"]
with db.session() as c:
    row = dict(c.execute("SELECT reset_code_hash FROM users WHERE email='ana@sfera.org'").fetchone())
check(row["reset_code_hash"] and code not in row["reset_code_hash"], "se guarda la huella, no el código")
n = s.forgot_password("nadie@sfera.org")
check(n == {"ok": True}, "email inexistente: misma respuesta, sin revelar nada")
err(lambda: s.forgot_password("no-es-email"), 400, "email válido", "email mal escrito")
err(lambda: s.reset_password("ana@sfera.org", code, "corta"), 400, "8 caracteres", "contraseña corta")
wrong = "000000" if code != "000000" else "111111"
err(lambda: s.reset_password("ana@sfera.org", wrong, "clave-nueva-1"), 400, "Código incorrecto", "código incorrecto")
check(s.reset_password("ana@sfera.org", code, "clave-nueva-1")["ok"], "código correcto: contraseña cambiada")
err(lambda: s.login("ana@sfera.org", "clave-vieja-1"), 401, "incorrectos", "la vieja ya no entra")
lg = s.login("ana@sfera.org", "clave-nueva-1")
check(lg["token"] and lg["verified"], "entra con la nueva y el email queda verificado")
err(lambda: s.reset_password("ana@sfera.org", code, "otra-clave-2"), 400, "caducado", "el código no se puede reutilizar")
# intentos
code2 = s.forgot_password("ana@sfera.org")["codigo_piloto"]
bad = "000000" if code2 != "000000" else "111111"
for _ in range(5):
    try: s.reset_password("ana@sfera.org", bad, "otra-clave-2")
    except s.SferaError: pass
err(lambda: s.reset_password("ana@sfera.org", code2, "otra-clave-2"), 400, "Demasiados intentos", "tras 5 fallos se bloquea aunque acierte")
code3 = s.forgot_password("ana@sfera.org")["codigo_piloto"]
check(s.reset_password("ana@sfera.org", code3, "otra-clave-2")["ok"], "pedir un código nuevo desbloquea")
# caducidad
code4 = s.forgot_password("ana@sfera.org")["codigo_piloto"]
with db.session() as c:
    c.execute("UPDATE users SET reset_expires=? WHERE email='ana@sfera.org'", (db.now() - 1,)); c.commit()
err(lambda: s.reset_password("ana@sfera.org", code4, "clave-3-xxx"), 400, "caducado", "código caducado (15 min)")
# código de una cuenta no sirve para otra
s.register("beto@sfera.org", "clave-beto-1")
cb = s.forgot_password("beto@sfera.org")["codigo_piloto"]
ca = s.forgot_password("ana@sfera.org")["codigo_piloto"]
if ca != cb:
    err(lambda: s.reset_password("ana@sfera.org", cb, "clave-3-xxx"), 400, "Código incorrecto", "el código de otra cuenta no vale")
# cuenta borrada
uid = s.login("beto@sfera.org", "clave-beto-1")["user_id"]
s.delete_account(uid, "clave-beto-1")
check(s.forgot_password("beto@sfera.org") == {"ok": True}, "cuenta borrada: no se envía código")
print(f"RESULTADO recuperar contraseña: {OK} OK · {FAIL} fallos")
