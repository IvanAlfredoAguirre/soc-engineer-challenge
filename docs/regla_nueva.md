# Reglas nuevas propuestas

Patrones de actividad detectados en los logs de soporte que no generaron
ninguna alerta dedicada en el turno. Se agregan como reglas nuevas; las reglas
existentes no se modifican.

## Persistencia: tarea programada con payload encubierto


DISPARA SI:
  EXISTE process_create FROM edr_events
  WHERE process_name = 'schtasks.exe'
  AND command_line CONTIENE '/create'
  AND parent_process IN ('powershell.exe', 'pwsh.exe', 'cmd.exe',
                         'wscript.exe', 'cscript.exe', 'rundll32.exe')
  Y command_line CONTIENE ALGUNO DE
      ('-enc', '-encodedcommand', '-e ', '-hidden', '-w hidden',
       'frombase64string', 'bypass')


Detecta la creacion de tareas programadas desde un shell script (no desde
consolas de administracion) con payload ofuscado. Caso real: schtasks
"OneDriveSyncHelper" /sc onlogon /rl highest lanzando powershell -enc,
creado por powershell.exe en WKS-FMARTINEZ-01 (03:49).

## Staging: compresion con password hacia ruta temporal


DISPARA SI:
  EXISTE process_create FROM edr_events
  WHERE process_name IN ('7z.exe', '7za.exe', 'winrar.exe', 'tar.exe')
  AND command_line CONTIENE ALGUNO DE ('-p', ' a ', '/create')
  Y command_line CONTIENE ALGUNO DE ('\Temp\', '\tmp\', '/tmp/')


Detecta la creacion de archivos comprimidos con contraseña (-p) o en modo
creacion, con salida en una ruta temporal. Caso real: 7z a -p
sobre Documents\Finanzas hacia AppData\Local\Temp, lanzado por el binario
descargado (upd.dat.exe) en WKS-FMARTINEZ-01 (05:30).

## Exfiltracion: volumen de salida hacia internet


DISPARA SI:
  SUM(bytes_sent) PARA src_ip = X hacia dst_ip = Y EN ventana_10_min > 50 MB
  Y dst_ip ES IP PUBLICA (no pertenece a un segmento privado)
  Y dst_ip NOT IN whitelist[rol='saas_egreso']


Detecta salida masiva de datos: >50MB en 10 min hacia una IP publica sin
registro en la whitelist de egreso. 
