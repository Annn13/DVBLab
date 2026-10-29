# Fase 3 — Reporte Técnico de Parches

**Proyecto Final IC-8071 Seguridad del Software · DVBank Lab**

Repositorio con trazabilidad por commits y ramas. Estrategia: una rama por módulo
fusionada a `master` mediante merge sin fast-forward (equivalente a un Pull Request).

> **Nota de trazabilidad individual:** los commits de cada módulo llevan como *autor* el
> nombre de su responsable. Al publicar el repositorio en GitHub, cada integrante debería
> abrir/firmar su propio Pull Request desde su cuenta para cumplir al 100 % la trazabilidad
> individual exigida. Complete la columna «Enlace al PR» con la URL real tras el push:
> `https://github.com/<org>/DVBLab-Seguridad/pull/<n>`.

Repositorio: **https://github.com/Annn13/DVBLab**

| Commit base | SHA |
|---|---|
| Baseline vulnerable (main del equipo) | `9969a44` |
| Base de hardening compartida (`seguridad/base`) | `fa9a80d` |

---

## 1. Ficha de integrantes y trazabilidad de Git

Flujo de PRs apilados (cada PR se fusiona sobre el anterior; su diff muestra solo su módulo):
`main → seguridad/base → modulo1 → modulo2 → modulo3 → modulo4`.

| Integrante | Módulo | Rama | Commit | Enlace al PR |
|---|---|---|---|---|
| Jose Arrieta | 1 · Autenticación | `seguridad/modulo1-autenticacion` | `9f10f22` | _(completar nº de PR)_ |
| Angie Aguilar | 2 · Gestión de Usuarios | `seguridad/modulo2-gestion-usuarios` | `4a6bf55` | _(completar nº de PR)_ |
| Laura Alpízar | 3 · Operaciones | `seguridad/modulo3-operaciones` | `b45f723` | _(completar nº de PR)_ |
| Melany Bustos | 4 · Auditoría y Logs | `seguridad/modulo4-auditoria-logs` | `d95e9dd` | _(completar nº de PR)_ |

Base compartida (`seguridad/base`, commit `fa9a80d`): `security.py`, `config.py`,
`extensions.py`, `app.py`, `requirements.txt`.

> **Trazabilidad individual:** los commits llevan como autor el nombre de cada responsable.
> Para cumplir al 100 % la autoría individual, cada integrante debería **abrir su propio PR
> desde su cuenta de GitHub** con el enlace correspondiente y, si la profesora lo exige,
> re-firmar su commit desde su usuario. Complete el nº de PR una vez creados.

Controles transversales (política de contraseñas, `require_role`, `safe_path`, guardia
anti-SSRF, saneamiento de logs, config por entorno, CORS, CSP, logging) viven en
`backend/security.py`, `backend/config.py`, `backend/extensions.py` y `backend/app.py`
(commit `84c7f55`).

---

## 2. Mapeo de vulnerabilidad y parche (por módulo)

### Módulo 1 — Autenticación (Jose Arrieta)

| # | Vulnerabilidad | OWASP | NIST CSF 2.0 | Archivo (antes → después) |
|---|---|---|---|---|
| 1 | SQLi en login/register | A03 | PR.DS-01, PR.PS-06 | `routes/auth_routes.py` |
| 2 | JWT `alg:none` / sin verificar firma | A02/A07 | PR.AA-03 | `auth.py` |
| 3 | Contraseñas MD5 sin sal | A02 | PR.DS-01, PR.AA-01 | `models.py` |
| 4 | IDOR en update-password | A01 | PR.AA-05 | `routes/auth_routes.py` |
| 5 | Reset token predecible/expuesto | A01/A07 | PR.AA-01/02 | `routes/auth_routes.py`, `models.py` |
| 6 | Cookie sin HttpOnly/SameSite | A05 | PR.AA-01, PR.DS-02 | `routes/auth_routes.py` |
| 7 | Deserialización YAML (RCE) | A08 | PR.PS-06 | `routes/auth_routes.py` |
| 8 | Sin rate limiting en login | A07 | PR.AA-03, PR.IR-04 | `routes/auth_routes.py` |

### Módulo 2 — Gestión de Usuarios (Angie Aguilar)

| # | Vulnerabilidad | OWASP | NIST CSF 2.0 | Archivo |
|---|---|---|---|---|
| 1 | Mass assignment (role/balance) | A08/A01 | PR.AA-05 | `routes/admin_routes.py` |
| 2 | Broken access control admin | A01 | PR.AA-05, GV.RR-02 | `routes/admin_routes.py` |
| 3 | Fuga de `password_hash` | A01/A02 | PR.DS-01 | `routes/admin_routes.py` |
| 4 | ReDoS en search-users | A05 | PR.IR-04 | `routes/admin_routes.py` |
| 5 | SSRF en fetch-avatar | A10 | PR.IR-01 | `routes/admin_routes.py` |
| 6 | SSTI en preview-email | A03 | PR.PS-06 | `routes/admin_routes.py` |
| 7 | RCE (eval/exec/pickle), backdoors | A08/A01 | PR.PS-06, PR.AA-05 | `routes/admin_routes.py` |
| 8 | Subida de archivos insegura | A05/A08 | PR.PS-05 | `routes/upload_routes.py` |
| 9 | XSS en AdminPanel | A03 | PR.DS-10 | `frontend/.../AdminPanel.js` |

### Módulo 3 — Operaciones (Laura Alpízar)

| # | Vulnerabilidad | OWASP | NIST CSF 2.0 | Archivo |
|---|---|---|---|---|
| 1 | SQLi historial/búsqueda | A03 | PR.DS-01 | `routes/transaction_routes.py` |
| 2 | IDOR en historial | A01 | PR.AA-05 | `routes/transaction_routes.py` |
| 3 | Monto negativo / sin saldo | A04 | ID.RA-01 | `routes/transaction_routes.py` |
| 4 | Débito de cuenta ajena (split-bill) | A01 | PR.AA-05 | `routes/transaction_routes.py` |
| 5 | XSS almacenado en recibo | A03 | PR.DS-10 | `routes/transaction_routes.py` |
| 6 | Command injection | A03 | PR.PS-06 | `routes/admin_routes.py` |
| 7 | XXE en import-data | A05 | PR.PS-06 | `routes/admin_routes.py` |
| 8 | Path traversal download-statement | A01 | PR.DS-01 | `routes/admin_routes.py` |
| 9 | Integridad SHA-1 sin clave | A02/A08 | PR.DS-02 | `routes/admin_routes.py` |

### Módulo 4 — Auditoría y Logs (Melany Bustos)

| # | Vulnerabilidad | OWASP | NIST CSF 2.0 | Archivo |
|---|---|---|---|---|
| 1 | Audit poisoning / log injection | A09 | PR.PS-04, DE.AE-02 | `routes/admin_routes.py` |
| 2 | Path traversal en view-log | A01/A05 | PR.DS-01 | `routes/admin_routes.py` |
| 3 | Fuga de secretos (dashboard/código) | A05 | PR.PS-01, ID.AM-05 | `routes/admin_routes.py`, `app.py` |
| 4 | Logging ausente + debug activo | A09/A05 | PR.PS-04, DE.CM-01 | `app.py` |
| 5 | Secretos en docker-compose | A05 | ID.AM-05 | `docker-compose.yml` |

---

## 3. Comparativa de código (Diff de remediación) — extractos representativos

### M1 · SQLi + JWT

```diff
# backend/routes/auth_routes.py — login
- query = f"SELECT * FROM user WHERE username = '{username}'"
- user = db.session.execute(query).fetchone()
+ user = User.query.filter_by(username=username).first()   # ORM parametrizado
```
```diff
# backend/auth.py — _decode_token
- try:
-     return jwt.decode(token, 'secret', algorithms=['HS256'])
- except Exception:
-     return jwt.decode(token, options={'verify_signature': False, 'verify_exp': False},
-                       algorithms=['HS256', 'none'])
+ return jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
```
```diff
# backend/models.py — contraseñas
- self.password_hash = hashlib.md5(password.encode()).hexdigest()
+ self.password_hash = generate_password_hash(password)   # PBKDF2-SHA256 con sal
```

### M2 · Mass assignment + fuga de hashes

```diff
# backend/routes/admin_routes.py — update_user
- for key, value in data.items():
-     setattr(user, key, value)
+ if 'email' in data:
+     if not valid_email(data['email']): return jsonify({'error':'Correo invalido'}),400
+     user.email = data['email']
+ if 'role' in data and data['role'] in ('user','admin','auditor'):
+     user.role = data['role']
```
```diff
# backend/routes/admin_routes.py — list_all_users
- 'password_hash': u.password_hash,   # fuga de credenciales
+ # _user_public(u): solo campos públicos, sin hash ni reset_token
```

### M3 · SQLi + lógica de dinero + XSS recibo

```diff
# backend/routes/transaction_routes.py — transferencia
- transaction = Transaction(...); 
- if current_user.balance < amount: return 'Insufficient', 400   # tarde
+ amount, err = _parse_amount(data.get('amount', 0))   # > 0, 2 decimales
+ if current_user.balance < amount: return jsonify({'error':'Insufficient balance'}),400
+ current_user.balance -= amount; receiver.balance += amount      # atómico
```
```diff
# backend/routes/transaction_routes.py — recibo
- <p><b>Memo:</b> {transaction.description or ''}</p>
+ <p><b>Memo:</b> {escape(transaction.description or '')}</p>   # markupsafe + @token_required
```

### M4 · Audit poisoning

```diff
# backend/routes/admin_routes.py — create_audit_entry
- logger.info(f"AUDIT: User {current_user.username} ... Details: {details}")
- audit = AuditLog(..., details=details, ...)
+ if action not in _AUDIT_ACTIONS: return jsonify({'error':'Accion no permitida'}),400
+ safe_details = sanitize_log_value(details, max_len=512)   # sin CR/LF ni control
+ audit_logger.info(f'user=... action={action} ip=... details={safe_details}')
```

---

## 4. Verificación de no-reincidencia (prueba de regresión)

Para cada PoC de la Fase 2, se re-ejecuta contra la versión remediada (`master`) y se
documenta el nuevo comportamiento. Resultado esperado: la PoC original ya **no** es
ejecutable.

| PoC original | Resultado tras el parche |
|---|---|
| SQLi login `' OR '1'='1' -- ` | 401 Invalid username or password (ORM parametrizado) |
| JWT `alg:none` / token forjado | 401 Invalid token (firma HS256 obligatoria) |
| IDOR update-password con `user_id` ajeno | 403; se exige `current_password` del propio usuario |
| Reset token `md5(username)` | 403 Invalid or expired reset token (token aleatorio + hash + expiración) |
| YAML `!!python/object/apply` | Perfil no se importa; `safe_load` no instancia objetos |
| Mass assignment `role=admin` | role ignorado salvo valor de lista blanca; endpoint exige admin |
| `GET /admin/users` expone hashes | 403 sin rol admin; respuesta sin `password_hash` |
| SSRF `169.254.169.254` | 400 URL no permitida (IP de metadatos bloqueada) |
| SSTI `{{7*7}}` | No se evalúa; plantilla fija del servidor |
| `eval`/`exec`/`pickle` RCE | Endpoints eliminados o parser aritmético seguro |
| SQLi `UNION` en /transactions | ORM parametrizado; `user_id` del cliente ignorado |
| Monto negativo / split-bill ajeno | 400 monto inválido; el pagador es el usuario de sesión |
| XSS en recibo | Datos escapados; endpoint con auth + CSP + nosniff |
| Command injection generate-report | 400 parámetros inválidos; sin shell |
| XXE import-data | Entidades externas deshabilitadas (defusedxml) |
| Path traversal view-log/download | 400/404; `safe_path` + lista blanca |
| Audit poisoning con `\n` | CR/LF eliminados; acción validada contra lista cerrada |
| Fuga de secretos dashboard-data | Respuesta sin claves; secretos solo en entorno |

> **Cómo reproducir la regresión:** instalar dependencias
> (`pip install -r backend/requirements.txt`), definir `SECRET_KEY` (ver `.env.example`),
> `python backend/app.py`, y repetir cada `curl` de la Fase 2 sobre `master`.
> Adjuntar capturas por cada caso como evidencia.
