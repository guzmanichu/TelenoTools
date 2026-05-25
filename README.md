# TelenoForensicTool

Este repositorio contiene un conjunto de herramientas forenses diseñadas para el análisis de evidencias digitales, específicamente registros de servidores Apache y el archivo Maestro de Tablas de Archivos ($MFT) de sistemas NTFS.

## Herramientas Incluidas

### 1. Conversor de Logs de Apache (`ConversorLogsApache/conversorLogApache.py`)

Esta herramienta permite convertir archivos de logs de Apache (formato combinado) a un formato CSV estructurado para facilitar su análisis en herramientas como Excel o bases de datos.

**Funcionalidades:**
- **Interfaz Gráfica:** Utiliza una ventana de selección de archivos para facilitar su uso.
- **Normalización de Extensiones:** Si el archivo seleccionado no tiene la extensión `.txt`, el programa lo renombrará automáticamente para asegurar su correcta lectura.
- **Extracción de Datos:** Utiliza expresiones regulares para extraer campos como IP, Fecha/Hora, Petición, Código de Estado, Tamaño, Referer y User Agent.
- **Manejo de Errores:** Identifica líneas que no cumplen con el formato estándar y las incluye en el CSV para no perder información.

**Cómo usarlo:**
1. Ejecuta el script: `python ConversorLogsApache/conversor.py`
2. Selecciona el archivo de log de Apache cuando se abra la ventana.
3. El programa generará un archivo `.csv` en la misma carpeta con el mismo nombre que el original.

---

### 2. Teleno MFT Analyzer (`telenoMFTAnalyzer.py`)

Un analizador avanzado del archivo `$MFT` que proporciona una visión detallada de la actividad del sistema operativo Windows.

**Funcionalidades:**
- **Análisis de Inicios de Sesión:** Detecta el primer y último inicio de sesión aproximado basándose en la creación de carpetas de usuario y la modificación de `NTUSER.DAT`.
- **Rastreo de Descargas:** Identifica los últimos archivos descargados por cada usuario.
- **Ejecución de Programas:** Analiza los archivos Prefetch (`.pf`) para determinar qué aplicaciones se han ejecutado recientemente.
- **Actividad en Papelera:** Lista archivos eliminados recientemente analizando el directorio `$Recycle.Bin`.
- **Archivos Recientes:** Rastrea el acceso a documentos y carpetas mediante el análisis de archivos `.lnk` en la carpeta `Recent`.
- **Detección de Timestomping:** Busca anomalías entre los timestamps de `$STANDARD_INFORMATION` y `$FILE_NAME` que puedan indicar manipulación de fechas.
- **Instalaciones de Software:** Detecta nuevas aplicaciones instaladas mediante el análisis de la creación de directorios en `Program Files`.

**Requisitos:**
- **mftdump.exe:** Esta herramienta debe estar presente en el mismo directorio que el script.
- **Librerías Python:** Requiere `pandas` y `tkinter`. Puedes instalarlas con:
  ```bash
  pip install pandas
  ```

**Cómo usarlo:**
1. Ejecuta el script: `python telenoMFTAnalyzer.py`
2. Selecciona el archivo `$MFT` que deseas analizar.
3. El programa realizará las siguientes acciones:
   - Convertirá el `$MFT` a un archivo CSV intermedio (`_parsed.csv`).
   - Generará un reporte detallado en formato texto (`DDMMYYYY-TelenoMFTAnalyzer.txt`) en la misma ubicación del archivo original.
4. Consulta el archivo `.txt` generado para ver los resultados estratégicos del análisis forense.

## Requisitos Generales

- **Python 3.x**
- **Dependencias de Python:**
  - `pandas`
  - `tkinter` (incluido por defecto en la mayoría de instalaciones de Python)
    
## Autor - Disclaimer

* **Guzmán Salas Flórez** - [guzmanichu](https://github.com/guzmanichu)
* NO ME HAGO RESPONSABLE DEL USO DE NINGUNA DE ESTAS HERRAMIENTAS NI DE LA INFORMACIÓN OBTENIDA DE ELLAS.

---
*Desarrollado para propósitos de análisis forense digital en el Experience Plus de FGULEM-Proconsi.*
