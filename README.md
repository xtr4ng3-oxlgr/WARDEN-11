# WARDEN-11

<img width="1672" height="941" alt="warden-11" src="https://github.com/user-attachments/assets/d429e50c-55a8-4d14-9177-0cddbd297f44" />

**WARDEN-11** es una mesa de trabajo de ciberpatrullaje autorizado para revisión defensiva de superficie web, detección local de secretos, higiene de contraseñas, inventario de hashes y generación de reportes estructurados.

---

## Propósito

WARDEN-11 está diseñado para revisiones de seguridad autorizadas.

Reúne varios flujos defensivos dentro de un espacio de trabajo local:

- revisión pasiva de postura web,
- escaneo local de secretos,
- análisis de higiene de contraseñas,
- inventario de formatos hash,
- almacenamiento basado en casos,
- reportes HTML / JSON / SARIF,
- dashboard estático.

No explota sistemas.  
No realiza fuerza bruta contra credenciales.  
No roba secretos.  
No ataca objetivos de terceros.

---

## Módulos principales

### Web Patrol

Revisa objetivos autorizados para detectar:

- uso de HTTPS,
- headers de seguridad,
- flags de cookies,
- formularios de contraseña,
- rutas comunes expuestas,
- problemas básicos de postura pública.

El módulo web requiere confirmación explícita de autorización:

```bash
warden11 web-audit cases/audit --yes-authorized
```

### Secrets Patrol

Escanea carpetas locales controladas por el usuario en busca de:

- API keys,
- tokens,
- webhooks,
- claves privadas,
- asignaciones de contraseña,
- filtraciones riesgosas en archivos de configuración.

Los secretos se guardan enmascarados en la base de datos y en los reportes.

### Password Hygiene

Revisa una lista de contraseñas proporcionada por el usuario para detectar problemas de higiene:

- contraseñas cortas,
- ausencia de clases de caracteres,
- patrones comunes,
- repetición,
- reutilización dentro del archivo revisado.

WARDEN-11 no crackea contraseñas.

### Hash Inventory

Clasifica valores con apariencia de hash:

- MD5,
- SHA1,
- SHA256,
- bcrypt,
- Argon2,
- valores tipo NTLM.

No crackea hashes.

---

## Comandos

Crear un caso:

```bash
warden11 new cases/audit --title "Authorized patrol"
```

Agregar un objetivo autorizado al scope:

```bash
warden11 scope-add cases/audit https://example.com
```

Mostrar el scope actual:

```bash
warden11 scope cases/audit
```

Ejecutar Web Patrol:

```bash
warden11 web-audit cases/audit --yes-authorized
```

Escanear secretos locales:

```bash
warden11 secrets cases/audit ./my-project
```

Revisar higiene de contraseñas:

```bash
warden11 passwords cases/audit passwords.txt
```

Clasificar hashes:

```bash
warden11 hashes cases/audit hashes.txt
```

Generar reportes:

```bash
warden11 report cases/audit
```

Mostrar estado del caso:

```bash
warden11 status cases/audit
```

---

## Arquitectura

```text
Rust CLI
  -> espacio de trabajo por caso
  -> base de datos SQLite
  -> módulos de patrullaje
  -> motor de reportes
  -> dashboard estático
```

Lenguajes y tecnologías usadas:

- Rust para el motor principal,
- SQLite / SQL para almacenamiento local,
- HTML / CSS / JavaScript para el dashboard,
- Python para el helper de empaquetado de reportes,
- texto de reglas estilo TOML para configuración,
- BAT / SH para scripts de build,
- YAML para GitHub Actions.

---

## Estructura de un caso

```text
audit/
├─ CASE.md
├─ scope.json
├─ warden11.db
├─ exports/
└─ reports/
   ├─ warden11_<timestamp>.html
   ├─ warden11_<timestamp>.json
   └─ warden11_<timestamp>.sarif
```

---

## Compilación

Requiere Rust.

```bash
cargo build --release
```

Helper para Windows:

```bat
build_windows\BUILD_RELEASE.bat
```

---

## Dashboard

Abrir:

```text
dashboard/index.html
```

Después cargar un reporte JSON generado desde la carpeta `reports/` del caso.

---

## Seguridad

WARDEN-11 es defensivo y basado en autorización.

No incluye:

- fuerza bruta,
- explotación,
- generación de payloads,
- robo de credenciales,
- escaneo oculto,
- persistencia,
- acciones destructivas.

---

# Licencia

<img width="300" height="159" alt="xtr4ng3" src="https://github.com/user-attachments/assets/f2a8ea90-7721-42cc-b9cc-651696536d55" />


**xtr4ng3**

MIT.

