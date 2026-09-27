# Ajuste de reglas ruidosas

Solo se corrigieron 3 reglas (las que generaron falsos positivos / benignos
mal configurados en el turno). Las demas reglas se respetan tal como estan.

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

## Regla actualizada:

```
DISPARA SI:
  COUNT(DISTINCT dst_ip) FROM vpc_flow_logs
  WHERE src_ip = X IN ventana_10_min >= 5
  AND COUNT(DISTINCT dst_port) EN LA MISMA VENTANA >= 20
  AND RATIO_CONEXIONES_SIN_RESPUESTA(bytes_received = 0) >= 0.9
NO DISPARA SI:
  src_ip IN whitelist[rol='vulnerability_scanner']
```

## Impossible Travel Detected

```
DISPARA SI:
  EXISTEN 2 login_success PARA user = X
  DESDE geo_country DISTINTO EN ventana_60_min
  Y LA DISTANCIA ENTRE AMBAS GEOLOCALIZACIONES IMPLICA
  UNA VELOCIDAD DE DESPLAZAMIENTO FISICAMENTE IMPOSIBLE (> 800 km/h)
```

## Regla actualizada:

```
DISPARA SI:
  EXISTEN 2 login_success PARA user = X
  DESDE geo_country DISTINTO EN ventana_60_min
  Y LA DISTANCIA ENTRE AMBAS GEOLOCALIZACIONES IMPLICA
  UNA VELOCIDAD DE DESPLAZAMIENTO FISICAMENTE IMPOSIBLE (> 800 km/h)
NO DISPARA SI:
  ambos src_ip IN whitelist[rol='corporate_vpn']
  Y ambos login_success CON user_agent IDENTICO
  Y ambos login_success CON mfa_used = true
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

## Regla actualizada:

```
DISPARA SI:
  COUNT(*) FROM vpc_flow_logs
  WHERE src_ip = X EN ventana_1_hora >= 50
  Y NO (src_ip IN whitelist[rol='monitoring_tools']
        Y dst_port IN (5666, 161, 9100))
```
## Suspicious Use of certutil.exe

```
DISPARA SI:
  EXISTE process_create FROM edr_events
  WHERE process = "certutil.exe"
  AND command_line CONTIENE "-urlcache"
  (dispara con un solo evento; no requiere volumen)
```
