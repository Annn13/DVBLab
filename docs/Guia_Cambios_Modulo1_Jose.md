# Guía de cambios — Módulo 1: Autenticación (Jose Arrieta)

Mapa de los parches para el video: **dónde está cada cambio** (archivo : línea),
qué era el problema y cómo quedó. Seguí este orden al grabar. PR de los parches: **#9**.

---

### 1. Contraseñas: MD5 → PBKDF2  ·  OWASP A02
- **Archivo:** `backend/models.py` · **líneas 29–42**
- **Antes:** `self.password_hash = hashlib.md5(password.encode()).hexdigest()` (sin sal).
- **Después (línea 31):** `generate_password_hash(password)` (PBKDF2 con sal) y
  `check_password_hash` en tiempo constante (línea 42); migra los MD5 viejos (línea 38).

### 2. JWT: se elimina `alg:none`  ·  OWASP A07 / A01
- **Archivo:** `backend/auth.py` · **líneas 7–19**
- **Antes:** si fallaba, re-decodificaba con `verify_signature: False` y `'none'`.
- **Después (líneas 16–19):** una sola `jwt.decode(..., algorithms=['HS256'])` que
  verifica firma y expiración; secreto desde config (línea 18).

### 3. Inyección SQL en el login → ORM  ·  OWASP A03
- **Archivo:** `backend/routes/auth_routes.py` · **función `login` (línea 76)**
- **Antes:** `query = f"SELECT * FROM user WHERE username = '{username}'"`.
- **Después (línea 85):** `User.query.filter_by(username=username).first()` (parametrizado).

### 4. IDOR en el cambio de contraseña  ·  OWASP A01
- **Archivo:** `backend/routes/auth_routes.py` · **líneas 183–189**
- **Antes:** tomaba `user_id` del cuerpo → cambiaba la clave de cualquiera.
- **Después (línea 189):** usa `current_user` (sesión) y exige `current_password`.
- **Frontend:** `frontend/src/components/PasswordUpdate.js` · **línea 22** (manda `current_password`, no `user_id`).

### 5. Token de recuperación predecible  ·  OWASP A07
- **Archivo:** `backend/routes/auth_routes.py` · **líneas 203–212 y 226–255**
- **Antes:** `token = hashlib.md5(username...)` devuelto en la respuesta (`debug_token`), sin expiración.
- **Después:** `secrets.token_urlsafe(32)` (210), se guarda solo su `sha256` (211) con
  expiración (212); se valida con `hmac.compare_digest` (244); respuesta genérica.

### 6. Cookie de sesión segura  ·  OWASP A05
- **Archivo:** `backend/routes/auth_routes.py` · **líneas 34–41 y 116**
- **Antes:** `set_cookie(..., httponly=False, secure=False)`.
- **Después:** `_set_session_cookie` con `httponly=True` (39), `secure`, `samesite='Strict'` (41).

### 7. Deserialización YAML (RCE) → `safe_load`  ·  OWASP A08
- **Archivo:** `backend/routes/auth_routes.py` · **línea 266**
- **Antes:** `yaml.load(profile_yaml, Loader=yaml.Loader)` (ejecuta código).
- **Después:** `yaml.safe_load(profile_yaml)` + lista blanca de campos.

### 8. Refuerzos: rate limiting y secreto por entorno  ·  OWASP A07 / A05
- **Archivo:** `backend/routes/auth_routes.py` · `@limiter.limit(...)` en **líneas 48, 75, 202**.
- **Archivo:** `backend/config.py` · **línea 14** → `os.environ.get("SECRET_KEY")` (secreto fuera del código).

---

> **Para el video:** abrí cada archivo en VS Code o en el PR #9 de GitHub, andá a la línea
> indicada (`Ctrl+G`), y explicá *qué era el problema (antes) → qué cambiaste (después) → por qué*.
> Verificación: en `docs/evidencia/` están las pruebas de que los ataques ya dan 401/403.
