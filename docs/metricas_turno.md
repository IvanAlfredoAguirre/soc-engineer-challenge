# Metricas del turno - 2026-08-15 (Acme Fintech)

## Volumen y tiempo
- Alertas triageadas: 6
- Tiempo aproximado de triage: ~3 h
  (incluye validacion contra auth/vpc/edr logs y correlacion)

## Clasificacion
- True Positives: 3 (SIEM-1001, 1004, 1006 - una sola cadena de ataque)
- FP / benignos mal configurados: 3 (SIEM-1002, 1003, 1005)
- Pendientes de validar contra inventario: 3

## % de falsos positivos por regla
| Regla                                      | Alertas | FP | % FP |
|--------------------------------------------|---------|----|------|
| Multiple Failed Logins Followed By Success | 1       | 0  | 0%   |
| Suspicious Use of certutil.exe             | 1       | 0  | 0%   |
| Anomalous Periodic Outbound Connection     | 1       | 0  | 0%   |
| Potential Port Scan Detected               | 1       | 1  | 100% |
| Impossible Travel Detected                 | 1       | 1  | 100% |
| High Connection Rate From Single Source    | 1       | 1  | 100% |
--------------------------------------------------------------------
| Total                                      | 6       | 3  | 50%  |

Muestra pequeña (1 alerta por regla): el % es indicativo, no estadistico.

## Pendientes de validar contra inventario (3)
1. SIEM-1002: confirmar 10.50.2.15 como scanner Qualys autorizado (CMDB).
2. SIEM-1003: confirmar rangos de egress de VPN corporativa con Redes.
3. SIEM-1005: confirmar 10.50.9.9 como servidor de monitoreo (Nagios/NRPE).

Las 3 entradas quedan cargadas en whitelist.yaml marcadas como
PROVISORIAS, con owner y fecha de revision. La validacion pendiente
no bloquea el ajuste de las reglas (la evidencia de logs es fuerte),
pero debe cerrarse antes de la proxima revision trimestral.

## Acciones derivadas
- 1 escalamiento a Tier 2/IR (cadena fmartinez: compromiso de credencial
  + staging + exfiltracion)
- 3 ajustes de regla (ver ajuste_reglas.md)
- 3 reglas nuevas propuestas (ver regla_nueva.md)
- 4 IOCs para bloqueo: 185.220.101.47, 194.36.191.55, 45.146.164.110.
