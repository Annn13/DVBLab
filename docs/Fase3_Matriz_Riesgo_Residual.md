# Fase 3 — Matriz de Riesgos NIST CSF Consolidada (Riesgo Residual)

**Proyecto Final IC-8071 Seguridad del Software · DVBank Lab**

Escala de riesgo residual (según el enunciado):
- **Alto/Crítico — No aceptable:** el parche no resuelve la causa raíz o es evadible.
- **Medio — Tolerable:** el vector principal se eliminó, pero quedan configuraciones laxas.
- **Bajo — Aceptado:** el vector fue neutralizado en el código, la PoC ya no es ejecutable y
  el control cumple la subcategoría NIST correspondiente.

---

## Módulo 1 — Autenticación (Jose Arrieta)

| Hallazgo | Riesgo inherente | Control aplicado | Subcat. NIST | Riesgo residual | Justificación |
|---|---|---|---|---|---|
| SQLi login/register | Crítico | ORM parametrizado + validación | PR.DS-01 | **Bajo** | Sin concatenación; PoC no ejecutable |
| JWT alg:none / secreto hardcoded | Crítico | HS256 obligatorio, secreto por entorno | PR.AA-03 | **Bajo** | Firma y expiración verificadas; fallback eliminado |
| Contraseñas MD5 | Alto | PBKDF2-SHA256 + política 12c | PR.DS-01 | **Bajo** | Hash con sal y migración transparente |
| IDOR update-password | Alto | Usuario de sesión + contraseña actual | PR.AA-05 | **Bajo** | No se acepta `user_id` del cuerpo |
| Reset token predecible | Alto | Token aleatorio, hash, expiración 30 min | PR.AA-01 | **Bajo** | No se revela; comparación en tiempo constante |
| Cookie insegura | Medio | HttpOnly+Secure+SameSite=Strict | PR.DS-02 | **Medio** | El token también sigue en `localStorage` por compat. del cliente; `Secure` solo activo en producción |
| YAML RCE | Crítico | `safe_load` + lista blanca | PR.PS-06 | **Bajo** | No instancia objetos Python |
| Sin rate limiting | Medio | Flask-Limiter en login/reset | PR.IR-04 | **Medio** | Límite en memoria por instancia; en despliegue multi-nodo requiere backend compartido (Redis) y falta MFA |

## Módulo 2 — Gestión de Usuarios (Angie Aguilar)

| Hallazgo | Riesgo inherente | Control aplicado | Subcat. NIST | Riesgo residual | Justificación |
|---|---|---|---|---|---|
| Mass assignment | Crítico | Lista blanca de campos + rol admin | PR.AA-05 | **Bajo** | `setattr` sobre el cuerpo eliminado |
| Broken access control | Crítico | `require_role('admin')` denegación por defecto | GV.RR-02 | **Bajo** | Todos los endpoints admin protegidos |
| Fuga de password_hash | Alto | Serializador `_user_public` | PR.DS-01 | **Bajo** | No se devuelven credenciales |
| ReDoS search-users | Medio | Búsqueda `ilike` + paginación | PR.IR-04 | **Bajo** | Sin regex del cliente |
| SSRF fetch-avatar | Alto | Guardia https + bloqueo IP interna/metadatos | PR.IR-01 | **Bajo** | Destinos internos rechazados |
| SSTI preview-email | Crítico | Plantilla fija del servidor | PR.PS-06 | **Bajo** | No se renderiza plantilla del cliente |
| RCE eval/exec/pickle + backdoors | Crítico | Parser aritmético; endpoints eliminados; JSON | PR.PS-06 | **Bajo** | Ejecución de código arbitrario eliminada |
| Subida insegura | Alto | Nombre aleatorio, tipo real, límite, `safe_path` | PR.PS-05 | **Bajo** | Sin traversal ni ejecutables; nosniff |
| XSS AdminPanel | Alto | Render como texto (React), sin `dangerouslySetInnerHTML` | PR.DS-10 | **Bajo** | Sinks de DOM eliminados + CSP |

## Módulo 3 — Operaciones (Laura Alpízar)

| Hallazgo | Riesgo inherente | Control aplicado | Subcat. NIST | Riesgo residual | Justificación |
|---|---|---|---|---|---|
| SQLi historial/búsqueda | Crítico | ORM parametrizado | PR.DS-01 | **Bajo** | PoC `UNION` no ejecutable |
| IDOR historial | Alto | Alcance al usuario de sesión | PR.AA-05 | **Bajo** | `user_id` del cliente ignorado |
| Monto negativo / sin saldo | Alto | Validación `>0`, 2 dec., saldo previo, atómico | ID.RA-01 | **Bajo** | Lógica de dinero consistente |
| Débito de cuenta ajena | Crítico | Pagador = usuario de sesión | PR.AA-05 | **Bajo** | No se acepta `from_user_id` |
| XSS recibo | Alto | `escape()` + auth + CSP/nosniff | PR.DS-10 | **Bajo** | Datos escapados; endpoint autenticado |
| Command injection | Crítico | Sin shell, args en lista, lista blanca | PR.PS-06 | **Bajo** | Metacaracteres sin efecto |
| XXE import-data | Alto | `defusedxml` | PR.PS-06 | **Bajo** | Entidades externas deshabilitadas |
| Path traversal download | Alto | `safe_path` + rol admin | PR.DS-01 | **Bajo** | Fuera del directorio rechazado |
| Integridad SHA-1 sin clave | Medio | HMAC-SHA256 con clave | PR.DS-02 | **Bajo** | Autenticidad verificable |

## Módulo 4 — Auditoría y Logs (Melany Bustos)

| Hallazgo | Riesgo inherente | Control aplicado | Subcat. NIST | Riesgo residual | Justificación |
|---|---|---|---|---|---|
| Audit poisoning | Crítico | Lista cerrada de acciones + saneo CR/LF + campos | DE.AE-02 | **Bajo** | Inyección de líneas falsas eliminada |
| Path traversal view-log | Alto | Lista blanca de logs + `safe_path` + rol auditor | PR.DS-01 | **Bajo** | Nombre libre eliminado |
| Fuga de secretos | Crítico | Secretos fuera del código; dashboard sin claves | ID.AM-05 | **Medio** | Las claves que estuvieron en el repositorio deben **rotarse**; el histórico de git aún las contiene hasta reescribirlo |
| Logging ausente + debug | Alto | Logging JSON con rotación; debug off; errores genéricos | PR.PS-04 | **Bajo** | Eventos persistidos; sin consola Werkzeug |
| Secretos en docker-compose | Alto | Variables de entorno + `.env.example` | ID.AM-05 | **Bajo** | `SECRET_KEY` ya no versionado |
| Integridad de la bitácora | Medio | (Pendiente) tabla append-only + encadenado por hash | PR.DS-11 | **Medio** | Control propuesto en la matriz de gobernanza; no implementado en esta fase |

---

### Resumen consolidado

- **Bajo (aceptado):** la gran mayoría de los vectores quedan neutralizados en código y sus
  PoC originales no son ejecutables.
- **Medio (tolerable) — acciones recomendadas:**
  1. **Rotar** todas las claves que estuvieron hardcoded (AWS/Stripe/GitHub/SendGrid/BD) y,
     opcionalmente, reescribir el histórico de git para purgarlas.
  2. Migrar el token de sesión a **solo cookie HttpOnly** (retirarlo de `localStorage`) para
     cerrar la exfiltración por XSS.
  3. Backend de rate limiting compartido (Redis) y **MFA** para administradores.
  4. Implementar la **bitácora append-only encadenada por hash** (PR.DS-11).
- **Alto/Crítico residual:** ninguno.
