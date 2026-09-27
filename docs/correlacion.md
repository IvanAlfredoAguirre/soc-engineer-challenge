## Alertas que comparten entidad: SIEM-1001, SIEM-1006, SIEM-1004

Entidad comun: usuario fmartinez / host WKS-FMARTINEZ-01 / IP 10.20.5.44
Ventana continua: 03:12 a 05:36 UTC (2h 24m)

| Hora        |            Alerta / evento                                |  Evidencia                                              |

| 03:12-03:47 | SIEM-1001: brute force + login exitoso                    | 12 failed + 1 success sin MFA desde 185.220.101.47 (NL) |
| 03:48-03:51 | (sin alerta) macro -> powershell -> schtasks -> discovery | EDR: Factura_0815.docm, persistencia, whoami/net/nltest |
| 04:05       | SIEM-1006: certutil -urlcache                             | Descarga upd.dat desde 194.36.191.55                    |
| 05:30       | (sin alerta) staging                                      | EDR: 7z con password sobre Documents\Finanzas           |
| 04:32-05:32 | SIEM-1004: beaconing C2                                   | 20 conexiones cada ~5 min a 45.146.164.110              |
| 05:36       | (sin alerta) exfiltracion                                 | VPC: 187MB hacia 45.146.164.110                         |

Relación CONFIRMADA. Al cruzar las alertas con los logs se observa que las tres corresponden al mismo usuario afectado (fmartinez): el atacante compromete sus credenciales, ejecuta código en el equipo, establece persistencia mediante tareas programadas, descarga el payload, copia los archivos de Finanzas en rutas temporales (staging) y, como cierre, realiza la exfiltración de la información.

Patrones MITRE ATT&CK observados:

- T1110.001: Brute Force - Password Guessing
- T1204.002: User Execution - Malicious File
- T1059.001: PowerShell
- T1105: Ingress Tool Transfer (certutil)
- T1560.001: Archive Collected Data
- T1041: Exfiltration Over C2 Channel

# Decision: SUBE A TIER 2 / IR

Criterio aplicado:
1. Credencial comprometida con login exitoso sin MFA (acceso valido).
2. Ejecucion de codigo y persistencia confirmadas en EDR.
3. Exfiltracion de datos financieros EN CURSO al momento del triage
   (187MB, 05:36).
4. Tres alertas SIEM son una sola intrusion: tratarlas como un incidente,
   no como tres casos.

Acciones:

1. Bloqueo de IOCs: 185.220.101.47, 194.36.191.55 y 45.146.164.110
(cdn-edge-sync.net).
2. Identidad: reset de credencial de fmartinez y blanqueo de MFA. 
Preventivo: blanqueo de todas las claves del colaborador en otros sistemas (una vez dentro, el atacante
pudo encontrar credenciales adicionales del usuario).
3. Aislamiento de WKS-FMARTINEZ-01 para analisis.


