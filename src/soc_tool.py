#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soc_tool.py - Herramienta SOC para triage e investigacion (CLI + interactiva).

Python 3.11+ | Solo biblioteca estandar | Windows/PowerShell compatible.

Fuentes esperadas en data/raw (o --data-dir):
  - alertas_dataset_v2.json (siem)   - auth_logs.json (auth)
  - vpc_flow_logs.json (vpc)         - edr_events.json (edr)
Tambien acepta logs_soporte.zip sin descomprimir, JSONL y JSON envuelto en dict.

SALIDA SIN RECORTES: las tablas envuelven el texto largo en varias lineas
(nunca lo truncan). El registro original completo esta disponible con
--detail, la opcion D, o --format json. Una coincidencia textual NO demuestra
causalidad. Los archivos de entrada nunca se modifican.
"""

import argparse
import csv
import json
import shutil
import sys
import textwrap
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

VERSION = "3.1.0"

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = BASE_DIR / "data" / "raw"
DEFAULT_OUTPUT_DIR = BASE_DIR / "data" / "output"

SOURCES = {
    "siem": ("alertas_dataset_v2.json", ("alerta",)),
    "auth": ("auth_logs.json", ("auth",)),
    "vpc": ("vpc_flow_logs.json", ("vpc", "flow")),
    "edr": ("edr_events.json", ("edr", "endpoint")),
}
SOURCE_ALIASES = {
    "siem": "siem", "alerts": "siem", "alertas": "siem",
    "auth": "auth", "authentication": "auth",
    "vpc": "vpc", "network": "vpc", "flow": "vpc",
    "edr": "edr", "endpoint": "edr",
}
SEVERITY_ORDER = {"critical": 0, "critica": 0, "high": 1, "alta": 1,
                  "medium": 2, "media": 2, "low": 3, "baja": 3,
                  "informational": 4, "info": 4, "unknown": 5}

# --------------------------------------------------------------------------
# Carga de fuentes
# --------------------------------------------------------------------------

def parse_json_text(texto, fname):
    """JSON array, JSONL o dict envuelto. Lineas malformadas se reportan."""
    texto = texto.strip()
    if not texto:
        return []
    try:
        data = json.loads(texto)
    except json.JSONDecodeError:
        items, malas = [], 0
        for linea in texto.splitlines():
            linea = linea.strip()
            if not linea:
                continue
            try:
                items.append(json.loads(linea))
            except json.JSONDecodeError:
                malas += 1
        if malas:
            print(f"[!] {fname}: {malas} linea(s) ignorada(s) por JSON invalido",
                  file=sys.stderr)
        data = items
    if isinstance(data, dict):  # JSON envuelto: {"records": [...]}, etc.
        data = next((data[k] for k in ("records", "events", "alerts",
                                       "data", "results", "items")
                     if isinstance(data.get(k), list)), [data])
    if not isinstance(data, list):
        raise ValueError(f"{fname}: se esperaba lista u objeto JSON.")
    ignorados = sum(not isinstance(x, dict) for x in data)
    if ignorados:
        print(f"[!] {fname}: se omitieron {ignorados} elemento(s) no-objeto.",
              file=sys.stderr)
    return [x for x in data if isinstance(x, dict)]

def _leer_zip(path_zip, pistas):
    """Extrae del zip los .json cuyo nombre coincida con las pistas."""
    registros = []
    with zipfile.ZipFile(path_zip) as z:
        for nombre in z.namelist():
            if nombre.lower().endswith(".json") and \
               any(p in nombre.lower() for p in pistas):
                registros.extend(parse_json_text(
                    z.read(nombre).decode("utf-8-sig"), f"{path_zip.name}:{nombre}"))
    return registros

def normalize_source(source):
    key = str(source).lower().strip()
    if key not in SOURCE_ALIASES:
        raise ValueError(f"Fuente desconocida: {source}. "
                         f"Opciones: {', '.join(SOURCES)}")
    return SOURCE_ALIASES[key]

def load_source(source, data_dir):
    """Carga una fuente: archivo esperado, cualquier .json con la pista, o .zip."""
    source = normalize_source(source)
    fname, pistas = SOURCES[source]
    data_dir = Path(data_dir)
    if not data_dir.exists():
        raise FileNotFoundError(f"Directorio de datos no existe: {data_dir}")
    ruta = data_dir / fname
    if ruta.exists():
        return parse_json_text(ruta.read_text(encoding="utf-8-sig"), fname)
    for suelto in sorted(data_dir.glob("*.json")):
        if any(p in suelto.name.lower() for p in pistas):
            return parse_json_text(suelto.read_text(encoding="utf-8-sig"),
                                   suelto.name)
    for zip_path in sorted(data_dir.glob("*.zip")):
        try:
            registros = _leer_zip(zip_path, pistas)
        except zipfile.BadZipFile:
            print(f"[!] {zip_path.name}: zip invalido, se omite", file=sys.stderr)
            continue
        if registros:
            return registros
    raise FileNotFoundError(
        f"Fuente '{source}' no encontrada en {data_dir} "
        f"(se busco {fname}, .json con '{pistas[0]}' y .zip)")

def load_all_sources(data_dir):
    if not Path(data_dir).exists():
        raise FileNotFoundError(f"Directorio de datos no existe: {data_dir}")
    datasets, errors = {}, {}
    for source in SOURCES:
        try:
            datasets[source] = load_source(source, data_dir)
        except (FileNotFoundError, ValueError) as exc:
            errors[source] = str(exc)
    return datasets, errors

# --------------------------------------------------------------------------
# Acceso a campos y busqueda
# --------------------------------------------------------------------------

def get_nested_value(record, field):
    """Campo simple o anidado ('entity.user'). Serializa dict/list como JSON."""
    actual = record
    for parte in str(field).split("."):
        if not isinstance(actual, dict):
            return None
        actual = actual.get(parte)
        if actual is None:
            return None
    if isinstance(actual, (dict, list)):
        return json.dumps(actual, ensure_ascii=False, sort_keys=True)
    return str(actual)

def get_any(record, *fields):
    for field in fields:
        valor = get_nested_value(record, field)
        if valor not in (None, "", "None"):
            return valor
    return ""

def flatten_values(value):
    """Solo VALORES (no claves) para que la busqueda no matchee por nombre
    de campo. Conserva la estructura recorriendo dicts y listas."""
    if isinstance(value, dict):
        salida = []
        for v in value.values():
            salida.extend(flatten_values(v))
        return salida
    if isinstance(value, list):
        salida = []
        for v in value:
            salida.extend(flatten_values(v))
        return salida
    return [str(value)]

def search_records(records, query):
    """Subcadena case-insensitive sobre los VALORES. Vacio -> sin resultados."""
    aguja = str(query).casefold().strip()
    if not aguja:
        return []
    return [r for r in records
            if aguja in " ".join(flatten_values(r)).casefold()]

def search_all_sources(datasets, query, selected=None):
    resultados = {}
    for source in selected or list(SOURCES):
        coincidencias = search_records(datasets.get(source, []), query)
        if coincidencias:
            resultados[source] = coincidencias
    return resultados

# --------------------------------------------------------------------------
# Timestamps y filas
# --------------------------------------------------------------------------

def timestamp_value(record):
    for field in ("timestamp", "timestamp_first_seen", "timestamp_last_seen",
                  "first_seen", "last_seen", "@timestamp", "time"):
        valor = record.get(field)
        if valor not in (None, ""):
            return str(valor)
    return None

def parse_timestamp_value(value):
    """ISO-8601 (acepta 'Z') a UTC. None si falta/invalido. No altera nada."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None

def event_row(source, record):
    """Vista plana. 'record' conserva la evidencia original intacta."""
    ts = timestamp_value(record)
    proceso = get_any(record, "process_name")
    detalle = get_any(record, "description", "command_line", "failure_reason",
                      "note", "app", "dst_port")
    if source == "edr":
        detalle = get_any(record, "command_line") or proceso or detalle
    return {
        "timestamp": ts or "N/D",
        "timestamp_valid": parse_timestamp_value(ts) is not None,
        "source": source.upper(),
        "severity": get_any(record, "siem_severity", "severity", "level"),
        "user": get_any(record, "user", "username", "account", "entity.user"),
        "host": get_any(record, "host", "hostname", "computer", "entity.host"),
        "event": get_any(record, "event_type", "rule_name", "process_name",
                         "alert_id", "action", "name") or "(sin tipo)",
        "src_ip": get_any(record, "src_ip", "source_ip", "entity.src_ip"),
        "dst_ip": get_any(record, "dst_ip", "destination_ip"),
        "dst_port": get_any(record, "dst_port"),
        "detail": detalle,
        "record": record,
    }

def build_rows(records_by_source):
    filas = []
    for source, records in records_by_source.items():
        filas.extend(event_row(source, r) for r in records)
    return filas

def sort_rows(rows, order="asc"):
    """Cronologico. Invalidos al final SIEMPRE (no se descartan)."""
    validas = [f for f in rows if f["timestamp_valid"]]
    invalidas = [f for f in rows if not f["timestamp_valid"]]
    validas.sort(key=lambda f: (parse_timestamp_value(f["timestamp"]),
                                f["source"], f["event"]),
                 reverse=(order == "desc"))
    invalidas.sort(key=lambda f: (f["source"], f["event"]))
    return validas + invalidas

# --------------------------------------------------------------------------
# Tabla SIN RECORTES (wrap multilinea estilo Excel)
# --------------------------------------------------------------------------

COLUMNAS_TABLA = ["timestamp", "source", "severity", "user", "host",
                  "event", "src_ip", "dst_ip", "detail"]
COLUMNAS_EXPORT = ["timestamp", "timestamp_valid", "source", "severity",
                   "user", "host", "event", "src_ip", "dst_ip", "dst_port",
                   "detail", "record_json"]

def filas_a_planas(filas):
    """Vista plana IDENTICA a la consola + record_json (original completo,
    serializado). Misma estructura en cada fila sin importar la fuente."""
    planas = []
    for f in filas:
        fila = {k: f.get(k, "") for k in COLUMNAS_TABLA}
        fila["timestamp_valid"] = f["timestamp_valid"]
        fila["dst_port"] = f.get("dst_port", "")
        fila["record_json"] = json.dumps(f["record"], ensure_ascii=False)
        planas.append(fila)
    return planas
CAPS_TABLA = {"timestamp": 22, "source": 7, "severity": 10, "user": 16,
              "host": 18, "event": 28, "src_ip": 16, "dst_ip": 16,
              "detail": 50}

def _ajustar_ancho(col_w, term, separadores):
    """Encoge PROPORCIONALMENTE hasta caber en el terminal (min 10 c/u),
    y redistribuye el remanente a las columnas mas anchas."""
    disponible = term - separadores
    if sum(col_w) <= disponible:
        return col_w
    escala = disponible / sum(col_w)
    ajustados = [max(10, int(w * escala)) for w in col_w]
    while sum(ajustados) > disponible and max(ajustados) > 10:
        i = ajustados.index(max(ajustados))
        ajustados[i] -= 1
    while sum(ajustados) < disponible:
        i = max(range(len(ajustados)), key=lambda j: ajustados[j])
        ajustados[i] += 1
    return ajustados

def print_table(rows, columns, widths=None):
    """Tabla con ENVOLTURA de texto: ningun campo se trunca. Un registro
    ocupa tantas lineas fisicas como necesite su campo mas largo."""
    if not rows:
        print("Sin resultados.")
        return
    term = shutil.get_terminal_size(fallback=(150, 30)).columns
    caps = widths or {}
    col_w = _ajustar_ancho(
        [max(10, min(caps.get(c, 28), 60)) for c in columns],
        term, 3 * (len(columns) - 1))
    sep = "-+-" .join("-" * w for w in col_w)

    def linea(celdas):
        print(" | ".join(str(celdas[i])[:col_w[i]].ljust(col_w[i])
                         for i in range(len(columns))))

    linea([c.upper() for c in columns])
    print(sep)
    for row in rows:
        envueltas = []
        for i, c in enumerate(columns):
            texto = str(row.get(c, "") if row.get(c, "") not in (None, "")
                        else "-")
            partes = textwrap.wrap(texto, width=col_w[i],
                                   break_long_words=True,
                                   break_on_hyphens=False) or [""]
            envueltas.append(partes)
        alto = max(len(p) for p in envueltas)
        for n in range(alto):
            linea([p[n] if n < len(p) else "" for p in envueltas])
        print(sep)

def print_rows(rows, output_format="table", show_detail=False):
    if output_format == "json":
        print(json.dumps([f["record"] for f in rows],
                         ensure_ascii=False, indent=2))
    elif output_format == "csv":
        campos = ["timestamp", "timestamp_valid", "source", "severity",
                  "user", "host", "event", "src_ip", "dst_ip", "dst_port",
                  "detail"]
        w = csv.DictWriter(sys.stdout, fieldnames=campos)
        w.writeheader()
        for f in rows:
            w.writerow({k: f.get(k, "") for k in campos})
    else:
        print_table(rows, COLUMNAS_TABLA, CAPS_TABLA)
        if show_detail:
            for i, f in enumerate(rows, 1):
                print(f"\n===== REGISTRO COMPLETO {i} | {f.get('source','')} =====")
                print(json.dumps(f["record"], ensure_ascii=False, indent=2))
        else:
            print("[i] Tabla sin recortes (texto envuelto). El registro "
                  "original: --detail, opcion D o --format json.")

# --------------------------------------------------------------------------
# Exportacion
# --------------------------------------------------------------------------

def resolver_ruta_salida(nombre):
    """Nombre simple -> data/output/. Ruta explicita -> respecto del cwd."""
    p = Path(nombre)
    if p.parent == Path(".") and len(p.parts) == 1:
        p = DEFAULT_OUTPUT_DIR / p.name
    elif not p.is_absolute():
        p = Path.cwd() / p
    return p

def export_data(data, output_path, output_format=None):
    """Exporta a CSV (utf-8-sig, Excel) o JSON. Informa ruta abs y cantidad.
    Devuelve el Path o None. Solo informa exito si realmente escribio."""
    if not output_path:
        return None
    registros = data if isinstance(data, list) else [data]
    if not registros:
        print("[!] No hay registros para exportar.")
        return None
    ruta = resolver_ruta_salida(output_path)
    fmt = (output_format or ruta.suffix.lstrip(".") or "json").lower()
    if not ruta.suffix:  # nombre sin extension -> agregar la del formato
        ruta = ruta.with_suffix("." + fmt)
    if fmt not in ("csv", "json"):
        print(f"[!] Formato invalido: {fmt} (use csv o json)", file=sys.stderr)
        return None
    try:
        ruta.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "json":
            with ruta.open("w", encoding="utf-8") as fh:
                json.dump(registros, fh, ensure_ascii=False, indent=2,
                          default=str)
        else:
            normalizados = [{k: (json.dumps(v, ensure_ascii=False)
                                 if isinstance(v, (dict, list)) else v)
                             for k, v in r.items()} for r in registros]
            campos = list(dict.fromkeys(k for r in normalizados for k in r))
            with ruta.open("w", encoding="utf-8-sig", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=campos, extrasaction="ignore")
                w.writeheader()
                w.writerows(normalizados)
        print(f"[OK] {len(registros)} registro(s) exportado(s) a: "
              f"{ruta.resolve()}")
        return ruta
    except OSError as exc:
        print(f"[ERROR] No se pudo escribir: {exc}", file=sys.stderr)
        return None

def print_source_errors(errors):
    if errors:
        print("\n[!] Fuentes no disponibles:")
        for source, error in errors.items():
            print(f"  - {source.upper()}: {error}")

def apply_limit(rows, limit):
    return rows if not limit or limit <= 0 else rows[:limit]

# --------------------------------------------------------------------------
# Comandos
# --------------------------------------------------------------------------

def command_summary(args):
    data_dir = Path(args.data_dir)
    if args.source == "all":
        datasets, errors = load_all_sources(data_dir)
        print("=== RESUMEN DE FUENTES ===")
        resumen = [{"source": s.upper(),
                    "records": len(datasets.get(s, [])),
                    "status": "OK" if s in datasets else "NO DISPONIBLE"}
                   for s in SOURCES]
        print_table(resumen, ["source", "records", "status"])
        print_source_errors(errors)
        export_data(resumen, getattr(args, "output", None),
                    getattr(args, "export_format", None))
        return
    source = normalize_source(args.source)
    records = load_source(source, data_dir)
    print(f"=== RESUMEN: {source.upper()} ===\nTotal de registros: "
          f"{len(records)}")
    if source == "siem":
        severidades = Counter(str(r.get("siem_severity", "Unknown"))
                              for r in records)
        reglas = Counter(str(r.get("rule_name", "Unknown")) for r in records)
        print("\nAlertas por severidad:")
        for k, n in sorted(severidades.items(),
                           key=lambda x: (SEVERITY_ORDER.get(x[0].casefold(), 99),
                                          -x[1], x[0])):
            print(f"  {k}: {n}")
        print("\nAlertas por regla:")
        for k, n in reglas.most_common():
            print(f"  {k}: {n}")
        filas = apply_limit(sort_rows([event_row(source, r) for r in records],
                                      args.sort), args.limit)
        print("\nListado de alertas:")
        print_rows(filas, args.format, args.detail)
        export_data(filas_a_planas(filas), args.output, args.export_format)
    else:
        frecuencia = Counter(k for r in records for k in r.keys())
        campos = [{"field": k, "records_with_field": v}
                  for k, v in frecuencia.most_common()]
        print("\nCampos detectados (frecuencia):")
        print_table(campos, ["field", "records_with_field"])
        export_data(campos, args.output, args.export_format)

def _comando_busqueda(args, datasets, errors, titulo):
    """Nucleo comun de search-ioc / correlate / timeline."""
    selected = None
    if getattr(args, "source", "all") != "all":
        selected = [normalize_source(args.source)]
    resultados = search_all_sources(datasets, args.query, selected)
    filas = sort_rows(build_rows(resultados), args.sort)
    total = len(filas)
    filas = apply_limit(filas, args.limit)
    orden = f" | Orden: {args.sort.upper()}" if titulo == "TIMELINE" else ""
    print(f"=== {titulo}: {args.query} ===")
    print(f"Coincidencias: {total} | Mostradas: {len(filas)}{orden}")
    print_rows(filas, args.format, args.detail)
    invalidas = sum(not f["timestamp_valid"] for f in filas)
    if invalidas:
        print(f"\n[!] {invalidas} registro(s) sin timestamp valido; "
              f"se muestran al final (no se descartan).")
    print_source_errors(errors)
    export_data(filas_a_planas(filas), args.output, args.export_format)
    return total

def command_search_ioc(args):
    if args.source == "all":
        datasets, errors = load_all_sources(Path(args.data_dir))
    else:
        source = normalize_source(args.source)
        datasets = {source: load_source(source, Path(args.data_dir))}
        errors = {}
    return _comando_busqueda(args, datasets, errors, "BUSQUEDA")

def command_correlate(args):
    datasets, errors = load_all_sources(Path(args.data_dir))
    total = _comando_busqueda(args, datasets, errors,
                              "BUSQUEDA EXPLORATORIA ENTRE FUENTES")
    print("\nNota: coincidencia textual entre registros; "
          "no demuestra causalidad por si sola.")
    return total

def command_timeline(args):
    datasets, errors = load_all_sources(Path(args.data_dir))
    return _comando_busqueda(args, datasets, errors, "TIMELINE")

def command_group(args):
    source = normalize_source(args.source)
    records = load_source(source, Path(args.data_dir))
    grupos = defaultdict(list)
    for record in records:
        valor = get_nested_value(record, args.field)
        grupos[valor if valor not in (None, "") else "(sin valor)"].append(record)
    filas = [{"value": v, "count": len(items)} for v, items in grupos.items()]
    filas.sort(key=lambda f: (-f["count"], str(f["value"]).casefold()))
    filas = apply_limit(filas, args.limit)
    print(f"=== AGRUPACION: {source.upper()} POR '{args.field}' ===")
    print_table(filas, ["value", "count"], {"value": 70, "count": 10})
    export_data(filas, getattr(args, "output", None),
                getattr(args, "export_format", None))
    return len(filas)

# --------------------------------------------------------------------------
# Modo interactivo
# --------------------------------------------------------------------------

AYUDA = """
Comandos del menu:
  1  Resumen SIEM (severidades, reglas y listado de alertas).
  2  Buscar texto/IOC en una fuente o en todas.
  3  Timeline cronologico de un valor.
  4  Correlate: busqueda exploratoria cruzada (NO causal).
  5  Agrupar registros por un campo (resultado exportable).
  6  Perfil de usuario: TODOS sus datos cruzados (auth+edr+vpc+siem)
     con resumen de autenticaciones.
  7  Autenticaciones de un usuario: exitos/fallos, MFA, paises, agentes.
  E  Exportar el ultimo resultado (CSV/JSON, data/output/ por defecto).
  D  Ver registro(s) original(es) completo(s): numero o 'A' para todos.
  R  Recargar fuentes desde disco.
  H  Esta ayuda.
  Q  Salir.

Tras cada consulta se ofrece: exportar el resultado, ver detalle o
hacer una nueva busqueda. Las consultas se ingresan en tiempo de
ejecucion; no hay IOC prefijados. Las coincidencias textuales no
demuestran causalidad.
"""

def _pedir_exportacion(registros, export_rows=None):
    """Exporta la vista plana (misma estructura que la consola) si hay;
    si no, los registros tal cual."""
    datos = export_rows if export_rows else registros
    nombre = input("Nombre de archivo (ENTER=resultado): ").strip() \
        or "resultado"
    fmt = input("Formato [csv/json] (ENTER=segun extension o json): "
                ).strip().casefold() or None
    if fmt not in {None, "csv", "json"}:
        print("[!] Formato invalido; use csv o json.")
        return
    export_data(datos, nombre, fmt)

def _pedir_detalle(registros):
    if not registros:
        print("[!] No hay registros para ver.")
        return
    sel = input(f"Numero de registro (1-{len(registros)}) o A=todos: "
                ).strip().casefold()
    if sel in {"a", "all", "todos"}:
        elegidos = registros
    else:
        try:
            i = int(sel)
            if not 1 <= i <= len(registros):
                raise ValueError
            elegidos = [registros[i - 1]]
        except ValueError:
            print("[!] Numero invalido.")
            return
    for i, record in enumerate(elegidos, 1):
        print(f"\n===== REGISTRO ORIGINAL {i} =====")
        print(json.dumps(record, ensure_ascii=False, indent=2))

def _menu_post_consulta(estado):
    """Tras filtrar resultados: ofrece exportar, ver detalle o nueva busqueda."""
    while True:
        try:
            accion = input(
                "[E]xportar resultado  [D]etalle  [N]ueva consulta  "
                "[Q]salir\n> ").strip().casefold()
        except (EOFError, KeyboardInterrupt):
            print("\nSaliendo.")
            raise SystemExit(0)
        if accion in {"e", "export", "exportar"}:
            _pedir_exportacion(estado["records"],
                               estado.get("export_rows") or None)
        elif accion in {"d", "detail", "detalle"}:
            _pedir_detalle(estado["records"])
        elif accion in {"n", "nueva", "", "q", "salir"}:
            return accion not in {"q", "salir"}

def _resumen_auth(hits):
    """Mini-analitico de autenticaciones para el perfil de usuario."""
    if not hits:
        return
    tipos = Counter(str(h.get("event_type", "?")) for h in hits)
    mfa = Counter(str(h.get("mfa_used", "?")) for h in hits)
    geo = Counter(str(h.get("geo_country", "?")) for h in hits)
    ua = Counter(str(h.get("user_agent", "?")) for h in hits)
    print("\n--- Autenticaciones ---")
    print("  Eventos:  " + ", ".join(f"{k}={n}" for k, n in tipos.most_common()))
    print("  MFA:      " + ", ".join(f"{k}={n}" for k, n in mfa.most_common()))
    print("  Paises:   " + ", ".join(f"{k}={n}" for k, n in geo.most_common()))
    top_ua = ua.most_common(3)
    print("  UA top:   " + "; ".join(f"{k} ({n})" for k, n in top_ua))

def menu_interactivo(data_dir):
    data_dir = Path(data_dir)
    datasets, errors = load_all_sources(data_dir)
    print("\n=== SOC TOOL | MODO INTERACTIVO ===")
    print(f"Directorio de datos: {data_dir}")
    print("Escriba H para ayuda o Q para salir.")
    print_source_errors(errors)
    estado = {"records": [], "filas": [], "export_rows": []}

    def recargar():
        nonlocal datasets, errors
        datasets, errors = load_all_sources(data_dir)
        print_source_errors(errors)
        print("Fuentes: " + ", ".join(
            f"{s}({len(r)})" for s, r in datasets.items()))

    def publicar(encontrados, consulta, titulo, disclaimer=False):
        estado["records"] = [r for recs in encontrados.values()
                             for r in recs]
        estado["filas"] = sort_rows(build_rows(encontrados), "asc")
        estado["export_rows"] = filas_a_planas(estado["filas"])
        print(f"\n=== {titulo}: {consulta} ===")
        print(f"Coincidencias: {len(estado['filas'])}")
        for fuente, recs in sorted(encontrados.items(),
                                   key=lambda x: -len(x[1])):
            print(f"  {len(recs):>4}  {fuente}")
        print_rows(estado["filas"], "table")
        if disclaimer:
            print("Nota: coincidencia textual; no demuestra causalidad.")

    while True:
        try:
            opcion = input(
                "\n[1] Resumen SIEM  [2] Buscar  [3] Timeline  [4] Correlate\n"
                "[5] Agrupar  [6] Perfil usuario  [7] Autenticaciones\n"
                "[E] Exportar  [D] Detalle  [R] Recargar  [H] Ayuda  [Q] Salir\n"
                "> ").strip().casefold()
        except (EOFError, KeyboardInterrupt):
            print("\nSaliendo.")
            return

        if opcion in {"q", "exit", "salir"}:
            print("Saliendo del modo interactivo.")
            return
        if opcion in {"h", "help", "?"}:
            print(AYUDA)
            continue
        if opcion == "r":
            recargar()
            continue
        if opcion in {"e", "export", "exportar"}:
            if not estado["records"] and not estado["export_rows"]:
                print("[!] No hay un resultado previo (use 2-7 primero).")
            else:
                _pedir_exportacion(estado["records"],
                                   estado["export_rows"] or None)
            continue
        if opcion in {"d", "detail", "detalle"}:
            _pedir_detalle(estado["records"])
            continue

        if opcion == "1":
            records = datasets.get("siem", [])
            estado["records"] = list(records)
            filas_siem = sort_rows([event_row("siem", r) for r in records],
                                   "asc")
            estado["filas"] = filas_siem
            estado["export_rows"] = filas_a_planas(filas_siem)
            print(f"\nTotal de alertas SIEM: {len(records)}")
            if records:
                sev = Counter(str(r.get("siem_severity", "Unknown"))
                              for r in records)
                print("Por severidad:")
                for k, n in sev.most_common():
                    print(f"  {k}: {n}")
                print_rows(filas_siem, "table")
            continue

        if opcion in {"2", "3", "4"}:
            consulta = input("Valor a buscar (usuario, IP, host, hash, "
                             "proceso, texto): ").strip()
            if not consulta:
                print("[!] La consulta no puede estar vacia.")
                continue
            seleccionadas = list(SOURCES)
            if opcion == "2":
                fuente = input("Fuente [all/siem/auth/vpc/edr] (all): "
                               ).strip().casefold() or "all"
                if fuente != "all":
                    try:
                        seleccionadas = [normalize_source(fuente)]
                    except ValueError as exc:
                        print(f"[!] {exc}")
                        continue
            encontrados = search_all_sources(datasets, consulta, seleccionadas)
            titulos = {"2": "BUSQUEDA", "3": "TIMELINE",
                       "4": "BUSQUEDA EXPLORATORIA"}
            publicar(encontrados, consulta, titulos[opcion],
                     disclaimer=(opcion == "4"))
            seguir = _menu_post_consulta(estado)
            if not seguir:
                return
            continue

        if opcion == "5":
            fuente = input("Fuente [siem/auth/vpc/edr]: ").strip().casefold()
            try:
                fuente = normalize_source(fuente)
            except ValueError as exc:
                print(f"[!] {exc}")
                continue
            campo = input("Campo de agrupacion (ej. user, src_ip, "
                          "process_name, entity.user): ").strip()
            if not campo:
                print("[!] El campo no puede estar vacio.")
                continue
            grupos = defaultdict(int)
            for record in datasets.get(fuente, []):
                valor = get_nested_value(record, campo)
                grupos[valor if valor not in (None, "") else "(sin valor)"] += 1
            filas = [{"value": v, "count": n}
                     for v, n in sorted(grupos.items(),
                                        key=lambda x: (-x[1],
                                                       str(x[0]).casefold()))]
            estado["records"], estado["filas"] = filas, []
            estado["export_rows"] = filas  # ya es una vista plana
            print(f"\n'{fuente}' agrupado por '{campo}':")
            print_table(filas, ["value", "count"], {"value": 70, "count": 10})
            seguir = _menu_post_consulta(estado)
            if not seguir:
                return
            continue

        if opcion == "6":  # Perfil de usuario (todos sus datos cruzados)
            usuario = input("Usuario a perfilar: ").strip()
            if not usuario:
                print("[!] El usuario no puede estar vacio.")
                continue
            encontrados = search_all_sources(datasets, usuario, list(SOURCES))
            publicar(encontrados, usuario, "PERFIL DE USUARIO",
                     disclaimer=True)
            _resumen_auth(encontrados.get("auth", []))
            seguir = _menu_post_consulta(estado)
            if not seguir:
                return
            continue

        if opcion == "7":  # Autenticaciones de un usuario
            usuario = input("Usuario: ").strip()
            if not usuario:
                print("[!] El usuario no puede estar vacio.")
                continue
            hits = search_records(datasets.get("auth", []), usuario)
            estado["records"] = list(hits)
            filas_auth = (sort_rows(build_rows({"auth": hits}), "asc")
                          if hits else [])
            estado["filas"] = filas_auth
            estado["export_rows"] = filas_a_planas(filas_auth)
            print(f"\n=== AUTENTICACIONES DE '{usuario}' ===")
            print(f"Eventos: {len(hits)}")
            _resumen_auth(hits)
            if hits:
                print_rows(filas_auth, "table")
            seguir = _menu_post_consulta(estado)
            if not seguir:
                return
            continue

        print("Opcion no reconocida. H para ayuda, Q para salir.")

# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def add_output_options(parser, include_sort=True):
    parser.add_argument("--format", choices=["table", "json", "csv"],
                        default="table")
    parser.add_argument("--output", help="Exportar resultado "
                                          "(data/output/ si es nombre simple).")
    parser.add_argument("--detail", action="store_true",
                        help="Registro original completo tras la tabla.")
    parser.add_argument("--export-format", choices=["json", "csv"],
                        help="Formato de exportacion (default: segun "
                             "extension o json).")
    parser.add_argument("--limit", type=int, default=None,
                        help="Maximo de resultados (sin limite por defecto).")
    if include_sort:
        parser.add_argument("--sort", choices=["asc", "desc"], default="asc")

def build_parser():
    parser = argparse.ArgumentParser(
        prog="soc_tool.py",
        description="Herramienta SOC: resumen SIEM, busqueda de IOC, "
                    "agrupacion, timeline y correlacion exploratoria.")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {VERSION}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR),
                        help="Directorio con los JSON/zip "
                             "(default: data/raw junto al repo). Aceptado "
                             "antes o despues del subcomando.")
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("interactive", aliases=["i"], parents=[common],
                        help="Consola interactiva.")
    p.set_defaults(func=lambda args: menu_interactivo(args.data_dir))

    p = subs.add_parser("summary", aliases=["resumen"], parents=[common],
                        help="Resumen de alertas SIEM o de fuentes.")
    p.add_argument("--source", default="siem",
                   help="siem/auth/vpc/edr/all (default: siem). "
                        "Acepta aliases: alerts, network, ...")
    add_output_options(p)
    p.set_defaults(func=command_summary)

    p = subs.add_parser("search-ioc", aliases=["buscar"], parents=[common],
                        help="Buscar texto/IOC en una fuente o todas.")
    p.add_argument("query", help="IP, usuario, hash, host, dominio, texto.")
    p.add_argument("--source", default="all",
                   help="Fuente especifica o 'all' (default).")
    add_output_options(p)
    p.set_defaults(func=command_search_ioc)

    p = subs.add_parser("group", aliases=["agrupar"], parents=[common],
                        help="Agrupar registros por campo configurable.")
    p.add_argument("--source", required=True)
    p.add_argument("--field", required=True,
                   help="Campo simple o anidado (entity.user).")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--output")
    p.add_argument("--export-format", choices=["json", "csv"])
    p.set_defaults(func=command_group)

    p = subs.add_parser("correlate", parents=[common],
                        help="Busqueda exploratoria cruzada (NO causal).")
    p.add_argument("query", help="Indicador, usuario, IP, host, texto.")
    p.add_argument("--source", default="all",
                   help="Restringir a una fuente (default: all).")
    add_output_options(p)
    p.set_defaults(func=command_correlate)

    p = subs.add_parser("timeline", parents=[common],
                        help="Linea de tiempo por coincidencia textual.")
    p.add_argument("query", help="Usuario, IP, host, hash, texto.")
    p.add_argument("--source", default="all",
                   help="Restringir a una fuente (default: all).")
    add_output_options(p)
    p.set_defaults(func=command_timeline)
    return parser

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "limit", None) is not None and args.limit < 1:
        parser.error("--limit debe ser mayor que cero.")
    try:
        resultado = args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(2)
    except PermissionError as exc:
        print(f"[ERROR] Sin permisos: {exc}", file=sys.stderr)
        sys.exit(2)
    # Codigos: 1 = consulta sin coincidencias (busquedas), no es un fallo.
    if isinstance(resultado, int) and resultado == 0 and \
       args.command in ("search-ioc", "buscar", "correlate", "timeline"):
        sys.exit(1)

if __name__ == "__main__":
    main()
