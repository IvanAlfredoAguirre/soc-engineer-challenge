# Manual de uso - `soc_tool.py` v3.1.0

Herramienta de apoyo para analistas SOC sobre los JSON del challenge.
**Python 3.11+ | Solo biblioteca estandar | Sin dependencias externas.**
Compatible con Windows/PowerShell y Linux/bash. **No modifica los archivos de entrada.**

---

## 1. Datos esperados

```javascript
soc-engineer-challenge/
├── data/
│   ├── raw/                    <-- el script lee de aca por defecto
│   │   ├── alertas_dataset_v2.json    (fuente: siem)
│   │   ├── auth_logs.json             (fuente: auth)
│   │   ├── vpc_flow_logs.json         (fuente: vpc)
│   │   └── edr_events.json            (fuente: edr)
│   └── output/                 <-- exportaciones por defecto
└── src/
    └── soc_tool.py
```

**Tolerante a formatos:** JSON array, JSONL (una linea por evento), JSON envuelto
en dict (`{"records": [...]}`), archivos con BOM (`utf-8-sig`), y `.zip` sin
descomprimir (busca dentro del zip los JSON que correspondan a cada fuente).
Tambien acepta como fuente cualquier `.json` cuyo nombre contenga la pista de
la fuente (`alerta`, `auth`, `vpc`/`flow`, `edr`).

**Importante:** el directorio de datos por defecto se resuelve **relativo a la
ubicacion del script** (`data/raw` junto a `src/`), no al directorio desde donde
se ejecuta. Por eso funciona igual estando en la raiz del repo o dentro de `src/`.

---

## 2. Sintaxis general

```javascript
python src/soc_tool.py [--data-dir RUTA] <COMANDO> [OPCIONES DEL COMANDO]
```

- `--data-dir RUTA`: carpeta con los JSON/zip. Se acepta **antes o despues**
del subcomando. Default: `data/raw` junto al repo.
- Comandos: `summary`, `search-ioc`, `group`, `timeline`, `correlate`, `interactive`.
- Alias: `resumen` = summary, `buscar` = search-ioc, `agrupar` = group, `i` = interactive.
- `--version`: muestra version.

### Opciones de salida (comandos de busqueda y summary)

| Opcion | Descripcion |
| --- | --- |
| `--format table\\|json\\|csv` | Formato de visualizacion (default: `table`). La tabla es **vista resumida**: nunca altera el registro original. |
| `--detail` | Tras la tabla, imprime el/los registro(s) original(es) completo(s), JSON indentado, **sin truncar** `command_line`, hashes ni campos de red. |
| `--output NOMBRE` | Exporta el resultado. Nombre simple -> `data/output/`; con extension se infiere el formato; ruta explicita se respeta. |
| `--export-format csv\\|json` | Fuerza el formato de exportacion (default: segun extension, o json). |
| `--limit N` | Maximo de resultados mostrados/exportados. |
| `--sort asc\\|desc` | Orden temporal (default: `asc`). |

**Estructura del exportado:** las busquedas exportan la **misma vista plana
de la consola** (`timestamp, timestamp_valid, source, severity, user, host,
event, src_ip, dst_ip, dst_port, detail`) **mas `record_json`**: el registro
original completo serializado en JSON. Cada fila tiene exactamente la misma
estructura sin importar la fuente (auth, edr, siem o vpc mezcladas), y nada se
pierde: todo campo original esta disponible parseando `record_json`.
Las agrupaciones exportan `value,count` y los resumenes sus columnas propias.

**Nomenclatura de archivos exportados:** si el nombre no tiene extension, se
agrega la del formato: escribir `TEST` y elegir csv -> `data/output/TEST.csv`.
La consola informa la **ruta absoluta** y la cantidad de registros exportados.
CSV se escribe con `utf-8-sig` (abre bien en Excel).

### Codigos de salida

| Codigo | Significado |
| --- | --- |
| `0` | Ejecucion correcta (con coincidencias, en busquedas) |
| `1` | Busqueda/correlacion/timeline **sin coincidencias** (no es un fallo) |
| `2` | Error: ruta inexistente, JSON invalido, fuente desconocida, etc. |

Una fuente individual faltante se reporta como **warning** y el analisis
continua con las demas. Solo un directorio de datos inexistente detiene la
ejecucion.

---

## 3. Comandos CLI

### 3.1 `summary` - dimensionar el lote

```powershell
python .\src\soc_tool.py summary                          # alertas SIEM (default)
python .\src\soc_tool.py summary --source all             # estado de las 4 fuentes
python .\src\soc_tool.py summary --source edr             # frecuencia de campos EDR
python .\src\soc_tool.py summary --format json --output resumen_siem
```

- Fuente `siem`: totales, conteo por severidad (ordenada critical->info),
conteo por regla y listado de alertas ordenado cronologicamente.
- Otras fuentes: total de registros y **frecuencia de campos** (util para
descubrir el esquema de un log desconocido).
- `--source` acepta aliases: `alerts`->siem, `network`->vpc, `authentication`->auth.

### 3.2 `search-ioc` - buscar un IOC o texto

```powershell
python .\src\soc_tool.py search-ioc "185.220.101.47"
python .\src\soc_tool.py search-ioc "fmartinez" --source edr
python .\src\soc_tool.py search-ioc "cdn-edge-sync.net" --format json --output c2_hits
python .\src\soc_tool.py search-ioc "certutil" --detail
```

- Coincidencia de **subcadena insensible a mayusculas sobre los valores** de
los eventos (no sobre los nombres de los campos).
- `--source all` (default) cruza las cuatro fuentes en una corrida: ideal para
ver en que logs aparece una IP/usuario.
- `query` es un argumento posicional: **ningun IOC esta prefijado en el codigo**.

### 3.3 `group` - agrupar por campo configurable

```powershell
python .\src\soc_tool.py group --source vpc --field src_ip
python .\src\soc_tool.py group --source siem --field entity.user   # campo anidado
python .\src\soc_tool.py group --source edr --field process_name --limit 10 --output procs.csv
```

- Soporta campos anidados con punto (`entity.user`).
- Los valores sin dato van a `(sin valor)`. Ordenado por cantidad descendente.

### 3.4 `timeline` - linea de tiempo

```powershell
python .\src\soc_tool.py timeline "fmartinez"
python .\src\soc_tool.py timeline "10.20.5.44" --source vpc --sort desc
```

- Acepta `--source` para restringir a una fuente (default: todas).
- Orden cronologico (UTC internamente; se muestra el timestamp original).
- Los registros con timestamp ausente o **invalido se muestran al final y se
cuentan aparte** — nunca se descartan ni se les inventa un orden.
- El registro original nunca se altera.

### 3.5 `correlate` - busqueda exploratoria cruzada

```powershell
python .\src\soc_tool.py correlate "10.20.5.44"
python .\src\soc_tool.py correlate "upd.dat" --source edr --detail
```

- Acepta `--source` para restringir a una fuente (default: todas).
- Busca el valor en **todas** las fuentes y muestra el desglose por fuente.
- **ADVERTENCIA:** es una coincidencia textual. No demuestra causalidad por si
sola; la correlacion analitica requiere evidencia, contexto y proximidad
temporal (ver `docs/correlacion.md`).

### 3.6 `interactive` - consola interactiva

```powershell
python .\src\soc_tool.py interactive
```

| Tecla | Accion |
| --- | --- |
| `1` | Resumen SIEM |
| `2` | Buscar (pide valor y, opcionalmente, fuente) |
| `3` | Timeline del valor |
| `4` | Correlate cruzado (con nota de no-causalidad) |
| `5` | Agrupar por campo (resultado exportable) |
| `6` | **Perfil de usuario**: todos sus datos cruzados (auth+edr+vpc+siem) + resumen de autenticaciones (exitos/fallos, MFA, paises, agentes) |
| `7` | **Autenticaciones de un usuario**: analitico de login (tipos, MFA, geografia, UA top) |
| `E` | Exportar el **ultimo resultado** a CSV/JSON (`data/output/` por defecto) |
| `D` | Ver registro original completo: numero de indice o `A` para todos |
| `R` | Recargar fuentes desde disco |
| `H` | Ayuda |
| `Q` | Salir |

**Ciclo post-consulta:** tras cada busqueda (2-7) el menu ofrece
`[E]xportar resultado / [D]etalle / [N]ueva consulta / [Q]salir`, asi se filtra,
exporta y vuelve a buscar sin salir del modo interactivo.

Flujo tipico: opcion `6` -> usuario `fmartinez` -> revisar perfil -> `E` ->
`perfil_fmartinez` -> `csv` -> `N` -> nueva consulta.

### Tablas sin recortes

Las tablas **envuelven el texto largo en varias lineas fisicas** (estilo Excel):
ningun campo se trunca. Si un token muy largo supera el ancho de columna
(p. ej. una IP de 16 caracteres en una columna angosta), se divide visualmente;
el valor original intacto siempre esta en `--detail`, la opcion `D` o
`--format json`. El ancho se adapta al terminal (minimo 10 por columna).

---

## 4. Ejemplos de un turno de triage (con los datos reales del challenge)

```powershell
# 1. Dimensionar el lote
python .\src\soc_tool.py summary

# 2. Investigar la alerta SIEM-1001 (brute force + login exitoso sin MFA)
python .\src\soc_tool.py search-ioc "185.220.101.47" --detail

# 3. Reconstruir la cadena del usuario comprometido
python .\src\soc_tool.py timeline "fmartinez" --output cadena_fmartinez.csv

# 4. Verificar el C2 en logs de red
python .\src\soc_tool.py search-ioc "cdn-edge-sync.net" --source vpc
python .\src\soc_tool.py correlate "10.20.5.44" --detail

# 5. Contrastar los FP candidatos
python .\src\soc_tool.py search-ioc "qualys-scan-0815"
python .\src\soc_tool.py search-ioc "nrpe health check"
python .\src\soc_tool.py group --source vpc --field src_ip
```

---

## 5. Errores frecuentes

| Sintoma | Causa y solucion |
| --- | --- |
| `[ERROR] Directorio de datos no existe` | `--data-dir` erroneo, o falta copiar los JSON a `data/raw`. Verificar con `summary --source all`. |
| `Sin resultados.` + exit 1 | La busqueda no tuvo coincidencias. Probar con un termino mas corto (la busqueda es de subcadena). |
| `Fuente desconocida` | Revisar ortografia; aliases validos: `siem/alerts/alertas`, `auth/authentication`, `vpc/network/flow`, `edr/endpoint`. |
| `[!] Fuentes no disponibles: ...` | Falta algun JSON. El analisis continua con las fuentes cargadas. |
| Columnas cortadas en la tabla | Es la **vista resumida**: usar `--detail`, `--format json` o la opcion `D`. |
| `python` no se reconoce (Windows) | Usar `py` o `python3`, o verificar el PATH. Version requerida: 3.11+. |

---

## 6. Limitaciones conocidas

- La busqueda es de subcadena sobre valores: no soporta regex ni rangos de IP
(una IP buscada matchea solo esa cadena exacta).
- `correlate`/`timeline` son exploratorios: ayudan a priorizar, la conclusion
de relacion causal es del analista.
- Tokens mas largos que el ancho de columna se dividen visualmente en la
tabla (el valor original esta intacto en JSON/detalle/export).
- En modo interactivo las fuentes se cargan al inicio; usar `R` tras agregar
o modificar archivos en `data/raw`.
- Archivos muy grandes (>100 MB) cargan en memoria; el dataset del challenge
es pequeno y no presenta problema.

---

## 7. Notas de implementacion

- Solo biblioteca estandar: `argparse, csv, json, zipfile, pathlib, datetime`.
No requiere `pip install` ni entorno virtual.
- Los archivos de entrada se abren en modo lectura; la integridad de los
originales esta garantizada.
- Timestamps: ISO-8601 con soporte de sufijo `Z`; los invalidos se preservan
y reportan, nunca se reescriben.
- Exportacion CSV: `utf-8-sig` (compatible con Excel en Windows).