# Lógica simplificada de las reglas actuales del SIEM

Referencia para el punto de afinado de reglas y para la regla nueva del challenge. Es una simplificación de cómo dispara cada regla hoy — no es el código real del SIEM, pero alcanza para proponer un ajuste o una regla nueva con criterio.

## Multiple Failed Logins Followed By Success

```
DISPARA SI:
  COUNT(login_failed) FROM auth_logs
  WHERE user = X AND src_ip = Y IN ventana_60_min >= 10
  AND EXISTE login_success PARA user = X, src_ip = Y DENTRO DE ESA MISMA VENTANA
```

## Potential Port Scan Detected

```
DISPARA SI:
  COUNT(DISTINCT dst_host) FROM vpc_flow_logs
  WHERE src_ip = X AND timestamp IN ventana_10_min >= 5
  AND COUNT(DISTINCT dst_port) EN LA MISMA VENTANA >= 20
```

## Impossible Travel Detected

```
DISPARA SI:
  EXISTEN 2 login_success PARA user = X
  DESDE geo_country DISTINTO EN ventana_60_min
  Y LA DISTANCIA ENTRE AMBAS GEOLOCALIZACIONES IMPLICA
  UNA VELOCIDAD DE DESPLAZAMIENTO FÍSICAMENTE IMPOSIBLE (> 800 km/h)
```

## Anomalous Periodic Outbound Connection

```
DISPARA SI:
  COUNT(*) FROM vpc_flow_logs
  WHERE src_ip = X AND dst_ip = Y AND dst_port = Z IN ventana_2_hs >= 15
  AND DESVIACIÓN ESTÁNDAR DEL INTERVALO ENTRE CONEXIONES < 30 segundos
  AND AVG(bytes_sent) < 5 KB
```

## High Connection Rate From Single Source

```
DISPARA SI:
  COUNT(*) FROM vpc_flow_logs
  WHERE src_ip = X AND timestamp IN ventana_24_hs >= 200
  (sin distinguir puerto ni patrón de bytes)
```

## Suspicious Use of certutil.exe

```
DISPARA SI:
  EXISTE process_create FROM edr_events
  WHERE process = "certutil.exe"
  AND command_line CONTIENE "-urlcache"
  (dispara con un solo evento; no requiere volumen)
```
