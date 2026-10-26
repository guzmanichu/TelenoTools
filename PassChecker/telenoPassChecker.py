import re
import subprocess
from datetime import datetime
from pathlib import Path


# ----------------------------------------------------------------------
# CONFIGURACIÓN
# ----------------------------------------------------------------------

# Tiempo máximo de espera para cada comando.
TIEMPO_ESPERA_SEGUNDOS = 30

# Si quieres guardar también el resultado en un archivo CSV,
# cambia este valor a True.
GENERAR_CSV = False

# El CSV se guardará junto al programa.
ARCHIVO_CSV = Path(__file__).with_name("expiracion_passwords.csv")


FORMATOS_FECHA = (
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%d/%m/%y %H:%M:%S",
    "%d/%m/%y %H:%M",
    "%d-%m-%Y %H:%M:%S",
    "%d-%m-%Y %H:%M",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %I:%M %p",
    "%m/%d/%y %I:%M:%S %p",
    "%m/%d/%y %I:%M %p",
)


VALORES_SIN_EXPIRACION = (
    "nunca",
    "never",
    "jamais",
    "nie",
)


# ----------------------------------------------------------------------
# EJECUCIÓN DE COMANDOS
# ----------------------------------------------------------------------

def decodificar_salida_windows(datos):
    """
    Decodifica la salida de los comandos clásicos de Windows.

    net.exe suele utilizar una página de códigos OEM, como CP850,
    mientras que otros procesos pueden devolver UTF-8 o CP1252.
    """
    codificaciones = (
        "utf-8",
        "cp850",
        "cp858",
        "cp1252",
        "latin-1",
    )

    for codificacion in codificaciones:
        try:
            return datos.decode(codificacion)
        except UnicodeDecodeError:
            continue

    return datos.decode("latin-1", errors="replace")


def ejecutar_comando(comando):
    """
    Ejecuta un comando sin utilizar shell=True.

    Devuelve la salida combinada de stdout y stderr.
    """
    resultado = subprocess.run(
        comando,
        capture_output=True,
        shell=False,
        timeout=TIEMPO_ESPERA_SEGUNDOS,
    )

    salida_estandar = decodificar_salida_windows(
        resultado.stdout
    )

    salida_error = decodificar_salida_windows(
        resultado.stderr
    )

    salida_completa = "\n".join(
        parte
        for parte in (salida_estandar, salida_error)
        if parte.strip()
    ).strip()

    if resultado.returncode != 0:
        mensaje = (
            salida_completa
            or f"El comando terminó con código "
               f"{resultado.returncode}"
        )

        raise RuntimeError(mensaje)

    return salida_completa


# ----------------------------------------------------------------------
# OBTENCIÓN DE LOS USUARIOS DEL DOMINIO
# ----------------------------------------------------------------------

def obtener_usuarios_dominio():
    """
    Ejecuta:

        net user /domain

    Extrae los usuarios situados entre la línea de guiones y
    el mensaje final del comando.
    """
    salida = ejecutar_comando(
        ["net", "user", "/domain"]
    )

    usuarios = []
    leyendo_usuarios = False

    for linea in salida.splitlines():
        linea_limpia = linea.strip()

        if not linea_limpia:
            continue

        # La lista de usuarios comienza después de una línea larga
        # formada principalmente por guiones.
        if re.fullmatch(r"-{5,}", linea_limpia):
            leyendo_usuarios = True
            continue

        if not leyendo_usuarios:
            continue

        linea_minusculas = linea_limpia.lower()

        # Final habitual en Windows en español.
        if "se ha completado el comando correctamente" in linea_minusculas:
            break

        # Final habitual en Windows en inglés.
        if "the command completed successfully" in linea_minusculas:
            break

        # Evita interpretar mensajes adicionales como usuarios.
        if linea_minusculas.startswith("el comando"):
            break

        # net user /domain muestra normalmente varias cuentas por línea,
        # separadas mediante espacios.
        usuarios_linea = re.split(
            r"\s+",
            linea_limpia
        )

        for usuario in usuarios_linea:
            usuario = usuario.strip()

            if usuario:
                usuarios.append(usuario)

    # Elimina duplicados conservando el orden.
    usuarios_sin_duplicados = []
    usuarios_vistos = set()

    for usuario in usuarios:
        usuario_normalizado = usuario.lower()

        if usuario_normalizado not in usuarios_vistos:
            usuarios_sin_duplicados.append(usuario)
            usuarios_vistos.add(usuario_normalizado)

    if not usuarios_sin_duplicados:
        raise RuntimeError(
            "El comando 'net user /domain' se ejecutó, pero no se "
            "pudo extraer ningún usuario de su salida."
        )

    return usuarios_sin_duplicados


# ----------------------------------------------------------------------
# CONSULTA INDIVIDUAL DE USUARIOS
# ----------------------------------------------------------------------

def ejecutar_net_user(usuario):
    """
    Ejecuta:

        net user nombre_usuario /domain

    La operación es solamente de lectura.
    """
    return ejecutar_comando(
        ["net", "user", usuario, "/domain"]
    )


def extraer_cuenta_activa(salida):
    """Devuelve True si la cuenta está activa, False si está desactivada."""
    valores_activos = {"si", "sí", "yes", "oui", "ja"}
    valores_inactivos = {"no", "non", "nein"}

    for linea in salida.splitlines():
        linea_limpia = linea.strip()
        linea_minusculas = linea_limpia.lower()

        if not (
            linea_minusculas.startswith("cuenta activa")
            or linea_minusculas.startswith("account active")
        ):
            continue

        partes = re.split(r"\s{2,}", linea_limpia, maxsplit=1)
        if len(partes) != 2:
            return None

        valor = partes[1].strip().lower()
        if valor in valores_activos:
            return True
        if valor in valores_inactivos:
            return False
        return None

    return None


def extraer_valor_expiracion(salida):
    """
    Localiza una línea como:

        La contraseña expira        14/01/2027 10:44:23

    La búsqueda flexible evita problemas de codificación con la ñ.
    También evita confundirla con:

        La cuenta expira            Nunca
    """
    for linea in salida.splitlines():
        linea_limpia = linea.strip()
        linea_minusculas = linea_limpia.lower()

        es_expiracion_password = (
            linea_minusculas.startswith("la contra")
            and "expira" in linea_minusculas
        )

        es_expiracion_ingles = (
            linea_minusculas.startswith("password")
            and "expires" in linea_minusculas
        )

        if not (
            es_expiracion_password
            or es_expiracion_ingles
        ):
            continue

        # Los campos de net user están separados normalmente
        # mediante dos o más espacios.
        partes = re.split(
            r"\s{2,}",
            linea_limpia,
            maxsplit=1,
        )

        if len(partes) == 2:
            return partes[1].strip()

        # Método alternativo para español.
        coincidencia = re.search(
            r"expira\s+(.+?)\s*$",
            linea_limpia,
            flags=re.IGNORECASE,
        )

        if coincidencia:
            return coincidencia.group(1).strip()

        # Método alternativo para inglés.
        coincidencia = re.search(
            r"expires\s+(.+?)\s*$",
            linea_limpia,
            flags=re.IGNORECASE,
        )

        if coincidencia:
            return coincidencia.group(1).strip()

    return None


def convertir_fecha(texto):
    """
    Convierte la fecha obtenida a datetime.

    Devuelve None cuando la contraseña no expira.
    """
    texto = texto.strip()
    texto_minusculas = texto.lower()

    if texto_minusculas in VALORES_SIN_EXPIRACION:
        return None

    texto_normalizado = re.sub(
        r"\s+",
        " ",
        texto,
    ).strip()

    # Normalización de indicadores AM y PM.
    texto_normalizado = texto_normalizado.replace(
        "a. m.",
        "AM",
    )

    texto_normalizado = texto_normalizado.replace(
        "p. m.",
        "PM",
    )

    texto_normalizado = texto_normalizado.replace(
        "a.m.",
        "AM",
    )

    texto_normalizado = texto_normalizado.replace(
        "p.m.",
        "PM",
    )

    for formato in FORMATOS_FECHA:
        try:
            return datetime.strptime(
                texto_normalizado,
                formato,
            )
        except ValueError:
            continue

    raise ValueError(
        f"No se reconoce el formato de fecha: {texto!r}"
    )


def limpiar_mensaje_error(mensaje):
    """
    Convierte un mensaje de varias líneas en una línea.
    """
    lineas = [
        linea.strip()
        for linea in mensaje.splitlines()
        if linea.strip()
    ]

    if not lineas:
        return "Error desconocido"

    return " | ".join(lineas)


def consultar_usuario(usuario):
    """
    Consulta la expiración de contraseña de un usuario.

    Un error en una cuenta no detiene la consulta del resto.
    """
    try:
        salida = ejecutar_net_user(usuario)

        cuenta_activa = extraer_cuenta_activa(salida)
        if cuenta_activa is False:
            return {
                "usuario": usuario,
                "fecha": None,
                "estado": "Cuenta desactivada; se omite del informe",
                "error": False,
                "omitido": True,
            }

        valor_expiracion = extraer_valor_expiracion(
            salida
        )

        if valor_expiracion is None:
            return {
                "usuario": usuario,
                "fecha": None,
                "estado": (
                    "No se encontró el campo de expiración "
                    "de contraseña"
                ),
                "error": True,
            }

        fecha_expiracion = convertir_fecha(
            valor_expiracion
        )

        if fecha_expiracion is None:
            return {
                "usuario": usuario,
                "fecha": None,
                "estado": "La contraseña no expira",
                "error": False,
            }

        return {
            "usuario": usuario,
            "fecha": fecha_expiracion,
            "estado": "Fecha obtenida correctamente",
            "error": False,
        }

    except subprocess.TimeoutExpired:
        return {
            "usuario": usuario,
            "fecha": None,
            "estado": (
                f"La consulta superó los "
                f"{TIEMPO_ESPERA_SEGUNDOS} segundos"
            ),
            "error": True,
        }

    except RuntimeError as error:
        return {
            "usuario": usuario,
            "fecha": None,
            "estado": limpiar_mensaje_error(
                str(error)
            ),
            "error": True,
        }

    except ValueError as error:
        return {
            "usuario": usuario,
            "fecha": None,
            "estado": str(error),
            "error": True,
        }

    except OSError as error:
        return {
            "usuario": usuario,
            "fecha": None,
            "estado": (
                f"No se pudo ejecutar net.exe: {error}"
            ),
            "error": True,
        }


# ----------------------------------------------------------------------
# CÁLCULO DEL ESTADO
# ----------------------------------------------------------------------

def calcular_estado_fecha(fecha, ahora):
    """
    Calcula los días restantes y el estado de la contraseña.

    Añade "FIN DE SEMANA" si la expiración cae en sábado o domingo.
    """
    es_fin_de_semana = fecha.weekday() >= 5

    def marcar_fin_de_semana(estado):
        if es_fin_de_semana:
            return f"{estado} | FIN DE SEMANA"
        return estado

    segundos_restantes = (
        fecha - ahora
    ).total_seconds()

    if segundos_restantes < 0:
        dias_transcurridos = int(
            abs(segundos_restantes) // 86400
        )

        if dias_transcurridos == 0:
            return 0, marcar_fin_de_semana("EXPIRADA HOY")

        return -dias_transcurridos, marcar_fin_de_semana("EXPIRADA")

    dias_restantes = int(
        segundos_restantes // 86400
    )

    if dias_restantes == 0:
        return 0, marcar_fin_de_semana("EXPIRA HOY")

    if dias_restantes <= 7:
        return dias_restantes, marcar_fin_de_semana("PRÓXIMA")

    return dias_restantes, marcar_fin_de_semana("ACTIVA")


# ----------------------------------------------------------------------
# GENERACIÓN OPCIONAL DEL CSV
# ----------------------------------------------------------------------

def escapar_csv(valor):
    """
    Escapa un valor para escribirlo correctamente en un CSV.
    """
    valor = str(valor)

    if any(
        caracter in valor
        for caracter in (';', '"', '\n', '\r')
    ):
        return '"' + valor.replace('"', '""') + '"'

    return valor


def generar_csv(resultados):
    """
    Guarda los resultados en un archivo CSV separado por punto y coma.

    Este formato suele abrirse correctamente en Excel configurado
    en español.
    """
    ahora = datetime.now()

    lineas = [
        "Usuario;Fecha de expiración;Días restantes;Estado;Error"
    ]

    resultados = [
        resultado
        for resultado in resultados
        if not resultado.get("omitido", False)
    ]

    resultados_ordenados = sorted(
        resultados,
        key=lambda resultado: (
            resultado["fecha"] is None,
            resultado["fecha"] or datetime.max,
            resultado["usuario"].lower(),
        ),
    )

    for resultado in resultados_ordenados:
        usuario = resultado["usuario"]
        error = resultado["estado"] if resultado["error"] else ""

        if resultado["fecha"] is not None:
            fecha_texto = resultado["fecha"].strftime(
                "%d/%m/%Y %H:%M:%S"
            )

            dias, estado = calcular_estado_fecha(
                resultado["fecha"],
                ahora,
            )

        elif resultado["error"]:
            fecha_texto = ""
            dias = ""
            estado = "ERROR"

        else:
            fecha_texto = "Nunca"
            dias = ""
            estado = "NO EXPIRA"

        campos = (
            usuario,
            fecha_texto,
            dias,
            estado,
            error,
        )

        linea = ";".join(
            escapar_csv(campo)
            for campo in campos
        )

        lineas.append(linea)

    ARCHIVO_CSV.write_text(
        "\n".join(lineas),
        encoding="utf-8-sig",
    )


# ----------------------------------------------------------------------
# PRESENTACIÓN DE RESULTADOS
# ----------------------------------------------------------------------

def mostrar_resultados(resultados):
    """
    Muestra los resultados ordenados desde la fecha más próxima
    hasta la más lejana.
    """
    resultados_con_fecha = sorted(
        (
            resultado
            for resultado in resultados
            if resultado["fecha"] is not None
        ),
        key=lambda resultado: resultado["fecha"],
    )

    resultados_sin_expiracion = sorted(
        (
            resultado
            for resultado in resultados
            if resultado["fecha"] is None
            and not resultado["error"]
        ),
        key=lambda resultado: resultado["usuario"].lower(),
    )

    resultados_con_error = sorted(
        (
            resultado
            for resultado in resultados
            if resultado["error"]
        ),
        key=lambda resultado: resultado["usuario"].lower(),
    )

    ahora = datetime.now()
    ancho = 124

    print()
    print("=" * ancho)
    print("EXPIRACIÓN DE CONTRASEÑAS DEL DOMINIO")
    print("=" * ancho)

    if resultados_con_fecha:
        print(
            f"{'USUARIO':<30}"
            f"{'FECHA DE EXPIRACIÓN':<24}"
            f"{'DÍAS':>10}"
            f"  {'ESTADO':<40}"
        )

        print("-" * ancho)

        for resultado in resultados_con_fecha:
            fecha = resultado["fecha"]

            dias, estado = calcular_estado_fecha(
                fecha,
                ahora,
            )

            print(
                f"{resultado['usuario']:<30}"
                f"{fecha.strftime('%d/%m/%Y %H:%M:%S'):<24}"
                f"{dias:>10}"
                f"  {estado:<40}"
            )

    else:
        print(
            "No se obtuvo ninguna fecha de expiración."
        )

    if resultados_sin_expiracion:
        print()
        print("CONTRASEÑAS QUE NO EXPIRAN")
        print("-" * ancho)

        for resultado in resultados_sin_expiracion:
            print(f"- {resultado['usuario']}")

    if resultados_con_error:
        print()
        print("USUARIOS NO CONSULTADOS O CON ERRORES")
        print("-" * ancho)

        for resultado in resultados_con_error:
            print(f"- {resultado['usuario']}")
            print(f"  Motivo: {resultado['estado']}")

    print()
    print("=" * ancho)

    print(
        f"Usuarios encontrados: {len(resultados)} | "
        f"Con fecha: {len(resultados_con_fecha)} | "
        f"No expiran: {len(resultados_sin_expiracion)} | "
        f"Errores: {len(resultados_con_error)}"
    )

    print("=" * ancho)
    print()

# ----------------------------------------------------------------------
# BANNER
# ----------------------------------------------------------------------

BANNER = r"""
  _______   _                  _____               _____ _               _             
 |__   __| | |                |  __ \             / ____| |             | |            
    | | ___| | ___ _ __   ___ | |__) |_ _ ___ ___| |    | |__   ___  ___| | _____ _ __ 
    | |/ _ \ |/ _ \ '_ \ / _ \|  ___/ _` / __/ __| |    | '_ \ / _ \/ __| |/ / _ \ '__|
    | |  __/ |  __/ | | | (_) | |  | (_| \__ \__ \ |____| | | |  __/ (__|   <  __/ |   
    |_|\___|_|\___|_| |_|\___/|_|   \__,_|___/___/\_____|_| |_|\___|\___|_|\_\___|_|
"""

# ----------------------------------------------------------------------
# PROGRAMA PRINCIPAL
# ----------------------------------------------------------------------

def main():
    
    print(BANNER)
    
    
    print()
    print("Obteniendo usuarios mediante net user /domain...")
    print()

    try:
        usuarios = obtener_usuarios_dominio()

    except subprocess.TimeoutExpired:
        print(
            "ERROR: La ejecución de 'net user /domain' "
            "superó el tiempo máximo de espera."
        )
        return

    except RuntimeError as error:
        print(
            "ERROR al obtener los usuarios del dominio:"
        )
        print(limpiar_mensaje_error(str(error)))
        return

    except OSError as error:
        print(
            f"ERROR: No se pudo ejecutar net.exe: {error}"
        )
        return

    print(
        f"Se han encontrado {len(usuarios)} usuarios "
        f"en el dominio."
    )

    print()
    print(
        "Consultando la expiración de contraseña "
        "de cada cuenta..."
    )
    print()

    resultados = []
    cuentas_desactivadas = 0

    for numero, usuario in enumerate(
        usuarios,
        start=1,
    ):
        print(
            f"[{numero}/{len(usuarios)}] "
            f"Consultando {usuario}..."
        )

        resultado = consultar_usuario(usuario)

        if resultado.get("omitido", False):
            cuentas_desactivadas += 1
            print("    Resultado: cuenta desactivada; omitida")
            continue

        resultados.append(resultado)

        if resultado["error"]:
            print("    Resultado: ERROR")

        elif resultado["fecha"] is None:
            print(
                "    Resultado: la contraseña no expira"
            )

        else:
            fecha_formateada = resultado[
                "fecha"
            ].strftime("%d/%m/%Y %H:%M:%S")

            print(
                f"    Resultado: {fecha_formateada}"
            )

    mostrar_resultados(resultados)
    print(f"Cuentas desactivadas omitidas: {cuentas_desactivadas}")
    print()

    if GENERAR_CSV:
        try:
            generar_csv(resultados)

            print(
                f"Archivo CSV generado: {ARCHIVO_CSV}"
            )

        except OSError as error:
            print(
                f"No se pudo generar el CSV: {error}"
            )


if __name__ == "__main__":
    main()