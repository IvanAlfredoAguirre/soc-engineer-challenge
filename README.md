# SOC Engineer Challenge

## Acme Fintech | Triage, ajuste y detección de alertas SOC

Este repositorio reúne el trabajo realizado para el challenge de Acme Fintech. La idea es mostrar cómo abordaría el análisis de una cola de alertas durante un turno: revisar cada caso con criterio, separar las detecciones reales de los falsos positivos, ajustar las reglas que generan ruido y proponer nuevas detecciones cuando encuentro puntos sin cobertura.

También incluye la correlación de eventos para reconstruir una posible intrusión, definir cuándo corresponde escalar a Tier 2/IR y contar con una herramienta propia que facilite las tareas de análisis e investigación.

## Estructura del repositorio

```text
soc-engineer-challenge/
├── README.md               # Este archivo
├── triage.csv              # Clasificación, severidad, justificación y acción por alerta
├── whitelist.yaml          # Excepciones configurables por rol, con responsable y fecha de revisión
├── data/
│   ├── raw/                # Alertas SIEM y logs originales de autenticación, VPC Flow y EDR
│   └── output/             # Resultados exportados por el script
├── src/
│   └── soc_tool.py         # Herramienta CLI e interactiva
└── docs/
    ├── uso_script.md       # Manual de uso de soc_tool.py
    ├── reglas_actuales.md  # Lógica actual del SIEM (entrada del challenge)
    ├── ajuste_reglas.md    # Ajuste de 3 reglas ruidosas y análisis del riesgo de falsos negativos
    ├── regla_nueva.md      # 3 reglas nuevas: persistencia, staging y exfiltración
    ├── correlacion.md      # Criterio de correlación y cadena escalada a Tier 2/IR
    └── metricas_turno.md   # Métricas del turno y pendientes de inventario
```

## Herramienta de apoyo: `soc_tool.py`

El repositorio incluye una herramienta propia para consultar y correlacionar información de las distintas fuentes sin tener que revisar cada archivo por separado.

**Requisitos:** Python 3.11 o superior. No requiere dependencias externas: utiliza únicamente la biblioteca estándar de Python. Puede trabajar con los archivos tal como se entregan, incluidos JSON, JSONL y ZIP sin descomprimir.

### Ejemplos de uso

```powershell
# Ver un resumen del volumen de alertas
python .\src\soc_tool.py summary

# Buscar un IOC en las cuatro fuentes y mostrar el detalle completo
python .\src\soc_tool.py search-ioc "185.220.101.47" --detail

## Buscar interactive y exportacion de datos filtrados 
python .\src\soc_tool.py interactive

# Extraer IOCs para una revisión de reputación
python .\src\soc_tool.py extract-iocs --type ip --output iocs.csv
```

El manual completo está en `docs/uso_script.md`.

## Criterios de clasificación

### Severidad

La severidad se asigna a partir del análisis del caso y de su impacto. No se toma automáticamente el nivel que informa el SIEM.

| Nivel        | Criterio                                       | Alertas                                                             |
|--------------|------------------------------------------------|---------------------------------------------------------------------|
| **CRITICAL** | Compromiso confirmado con exposición de datos. | SIEM-1001 (credencial robada e inicio de sesión sin MFA)            |
| **HIGH**     | True Positive con impacto en curso.            | SIEM-1004 (C2), SIEM-1006 (transferencia de herramienta)            |
| **LOW**      | Falso positivo o actividad benigna que la regla| SIEM-1002, SIEM-1003, SIEM-1005                                     |
|              | está clasificando incorrectamente.             |                                                                     |

### Clasificación de las alertas

- **True Positive (escalar):** hay evidencia que se sostiene al cruzar los logs, una línea de tiempo consistente, IOCs presentes en más de una fuente y un impacto real o en curso.
- **Falso positivo benigno por una regla mal ajustada (afinar regla):** la actividad es legítima, pero la regla no contempla el contexto del entorno, por ejemplo, un scanner, una salida por VPN o una herramienta de monitoreo. La detección puede estar funcionando como fue diseñada, pero necesita distinguir mejor la actividad corporativa esperada.

## Metodología de trabajo

1. **Carga y parsing:** se procesan las cuatro fuentes con `soc_tool.py`, manteniendo intactos los archivos originales.
2. **Triage:** se revisa cada alerta y se deja registrada su clasificación junto con la evidencia relevante de los logs.
3. **Correlación:** se relacionan eventos por entidad compartida, continuidad temporal y secuencia lógica. No alcanza con que dos eventos tengan un texto parecido.
4. **Ajuste de reglas:** se intervienen únicamente las tres reglas para las que se encontró evidencia de ruido. Las exclusiones se definen por rol y se administran mediante una whitelist, dejando explícito qué riesgo de falso negativo puede introducir cada excepción.
5. **Nuevas detecciones:** se proponen tres reglas para patrones que aparecen en los logs y no cuentan con cobertura suficiente: persistencia mediante `schtasks` y payload encubierto, staging con un archivo comprimido protegido por contraseña en `Temp`, y exfiltración a partir del volumen de tráfico saliente.
6. **Gestión de la whitelist:** las excepciones se organizan en YAML por rol, con justificación, responsable y fecha de revisión. Las entradas se mantienen como **PROVISORIAS** hasta validarlas contra el inventario.

## IOCs principales

| IOC                 | Rol dentro del caso                           | Fuentes donde aparece                     |
|---------------------|-----------------------------------------------|-------------------------------------------|
| `185.220.101.47`    | Origen del brute force                        | `auth_logs`, SIEM-1001                    |
| `194.36.191.55`     | Descarga del payload                          | `edr_events`, `vpc_flow_logs`, SIEM-1006  |
| `45.146.164.110`    | C2 y exfiltración de 187 MB                   | `vpc_flow_logs`, SIEM-1004                |
| `cdn-edge-sync.net` | SNI del C2, con dominio que simula ser un CDN | `vpc_flow_logs` (nota)                    |
| `10.20.5.44`        | Equipo comprometido: `WKS-FMARTINEZ-01`       | `edr_events`, `vpc_flow_logs`             |
| `fmartinez`         | Cuenta comprometida                           | `auth_logs`, `edr_events`                 |

**Artefactos identificados:** `Factura_0815.docm` (macro), `upd.dat` (payload), `bkp_0815.7z` (staging protegido con contraseña) y la tarea `OneDriveSyncHelper` (persistencia).

## Técnicas MITRE ATT&CK relacionadas

- T1110.001 — Password Guessing
- T1204.002 — Malicious File
- T1059.001 — PowerShell
- T1053.005 — Scheduled Task
- T1033 / T1087 / T1016 — Discovery
- T1105 — Ingress Tool Transfer
- T1218 — certutil
- T1560.001 — Archive via Utility
- T1071.001 — Web C2
- T1041 — Exfiltration Over C2 Channel

## Archivos generados y documentación

| Archivo                  | Contenido                                                  | Destinatario principal      |
|--------------------------|------------------------------------------------------------|-----------------------------|
| `triage.csv`             | Clasificación estructurada de cada alerta                  | Análisis automatizado       |
| `docs/ajuste_reglas.md`  | Reglas ajustadas y análisis del riesgo de falsos negativos | SOC / Detección             |
| `docs/regla_nueva.md`    | Tres reglas nuevas propuestas                              | SOC / Detección             |
| `docs/correlacion.md`    | Cadena de eventos, IOCs y acciones sugeridas               | SOC / Tier 2 / IR           |
| `docs/metricas_turno.md` | Métricas y resultados del turno                            | SOC Lead                    |
| `whitelist.yaml`         | Excepciones organizadas y justificadas por rol             | Detección / Infraestructura |
| `src/soc_tool.py`        | Herramienta de apoyo para triage e investigación           | Operaciones SOC             |

## Cómo usar el repositorio

### Para analistas SOC

```powershell
python .\src\soc_tool.py summary
python .\src\soc_tool.py search-ioc "45.146.164.110" --detail
type docs\correlacion.md
```

### Para Tier 2 / IR

Revisar `docs/correlacion.md`, donde se detalla la secuencia de eventos, los IOCs y las acciones propuestas. Para consultar los puntos de cobertura faltantes, ver también `docs/regla_nueva.md`.

### Para el equipo de Detección

Consultar `docs/ajuste_reglas.md`, `docs/regla_nueva.md` y `whitelist.yaml` para revisar los cambios propuestos, las nuevas detecciones y las excepciones configuradas.

## Notas técnicas

- El script utiliza únicamente la biblioteca estándar de Python (`argparse`, `csv`, `json`, `zipfile`, entre otras); no requiere dependencias externas.
- Los archivos originales se abren en modo de solo lectura y no se modifican. La integridad se verifica mediante hash.
- Los timestamps se manejan en formato ISO 8601 UTC. Los valores inválidos se conservan y se reportan.
- Las exportaciones se guardan en `data/output/` en una vista plana, con una estructura equivalente a la que muestra la consola. El registro original completo puede consultarse con `--detail` o con la opción `D`.
- **Códigos de salida:** `0` = se encontraron resultados; `1` = no hubo coincidencias; `2` = error.

## Hallazgo principal

Se reconstruyó una cadena de actividad sobre la cuenta `fmartinez` y el equipo `WKS-FMARTINEZ-01`, entre las **03:12 y las 05:36 UTC**:

**Brute force exitoso sin MFA → ejecución de macro → persistencia → discovery → uso de certutil → compresión de información de Finanzas con 7z → comunicación con C2 → exfiltración de 187 MB.**

Las alertas SIEM-1001, SIEM-1004 y SIEM-1006 corresponden a distintas etapas de una misma intrusión, por lo que se correlacionan y se escalan a Tier 2/IR como un único caso.

## Próximos pasos

1. **Análisis forense:** obtener una imagen de `WKS-FMARTINEZ-01` y realizar la limpieza de los mecanismos de persistencia.
2. **Validación de whitelist:** revisar las entradas **PROVISORIAS** de `whitelist.yaml` contra la CMDB y el equipo de Redes.
3. **Implementación de reglas:** poner en producción las tres reglas nuevas y monitorear su comportamiento durante las primeras semanas.
4. **Threat Intelligence:** consultar la reputación de los IOCs, por ejemplo, mediante `extract-iocs --type ip`.
5. **Hardening:** revocar las app passwords legacy, revisar la política de macros y reforzar el uso de MFA.
