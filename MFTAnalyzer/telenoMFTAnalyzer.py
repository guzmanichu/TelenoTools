import tkinter as tk
from tkinter import filedialog
import subprocess
import os
import sys
import pandas as pd # type: ignore
from datetime import datetime

usuarios_excluir = ['Public', 'Default', 'Default User', 'All Users']

def seleccionar_mft():
    root = tk.Tk()
    root.withdraw()
    
    ruta_mft = filedialog.askopenfilename(title="Selecciona el archivo $MFT", filetypes=[("Archivos MFT", "*"), ("Todos los archivos", "*.*")]
    )
    
    return ruta_mft


def ejecutar_mftdump(ruta_mft, salida_csv):
    comando = [ "mftdump.exe","-o" , salida_csv, ruta_mft]
    
    try:
        subprocess.run(comando, check=True)
        print(f"[+] CSV generado en: {salida_csv}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error ejecutando mftdump: {e}")


def cargar_csv(ruta_csv):
    df = pd.read_csv(ruta_csv, sep='\t', low_memory=False)
    return df

def detectar_primer_logon(df):
    # Filtrar solo directorios dentro de C:\Users\
    prefix = "\\Users\\"
    df_users = df[
        (df['Directory'] == True) &
        (df['FullPath'].str.startswith(prefix, na=False))
    ].copy()

    # Extraer nombre de usuario
    df_users['Usuario'] = df_users['FullPath'].str.split('\\').str[2]
    df_users = df_users[~df_users['Usuario'].isin(usuarios_excluir)]
    
    # Convertir timestamp a datetime
    df_users['siCreateTime (UTC)'] = pd.to_datetime(
        df_users['siCreateTime (UTC)'],
        errors='coerce'
    )

    # Agrupar por usuario y obtener la fecha más antigua
    primeros_logon = df_users.groupby('Usuario')['siCreateTime (UTC)'].min()

    print("\n[+] Posibles primeros inicios de sesión:\n")
    print(primeros_logon.sort_values())

    return primeros_logon

def detectar_ultimo_logon(df):
    """
    Detecta aproximación de último logon usando NTUSER.DAT
    """

    # Filtrar solo archivos NTUSER.DAT
    df_ntuser = df[
        (df['Directory'] == False) & 
        (df['Filename'].str.upper() == "NTUSER.DAT")
    ].copy()

     # Extraer nombre de usuario
    df_ntuser['Usuario'] = df_ntuser['FullPath'].str.split('\\').str[2]
    df_ntuser = df_ntuser[~df_ntuser['Usuario'].isin(usuarios_excluir)]

    # Convertir timestamp a datetime
    df_ntuser['siModTime (UTC)'] = pd.to_datetime(
        df_ntuser['siModTime (UTC)'],
        errors='coerce'
    )

    # Agrupar por usuario y quedarnos con la última modificación
    ultimo_logon = df_ntuser.groupby('Usuario')['siModTime (UTC)'].max()

    print("\n[+] Últimos logons aproximados por usuario:\n")
    print(ultimo_logon.sort_values(ascending=False))

    return ultimo_logon

def detectar_descargas(df):
    print("\n[+] Analizando últimas descargas por usuario:")
    df_dl = df[
        (df['Directory'] == False) &
        (df['FullPath'].str.contains(r'\\Users\\[^\\]+\\(?:Downloads|Descargas)\\', case=False, na=False))
    ].copy()
    
    if df_dl.empty:
        print("  [-] No se han encontrado descargas recientes.")
        return
        
    df_dl['Usuario'] = df_dl['FullPath'].str.split('\\').str[2]
    df_dl = df_dl[~df_dl['Usuario'].isin(usuarios_excluir)]
    df_dl['siCreateTime (UTC)'] = pd.to_datetime(df_dl['siCreateTime (UTC)'], errors='coerce')
    
    for usuario in df_dl['Usuario'].unique():
        user_dl = df_dl[df_dl['Usuario'] == usuario].sort_values(by='siCreateTime (UTC)', ascending=False).head(5)
        if not user_dl.empty:
            print(f"\n  [Usuario: {usuario}] - Top 5 descargas recientes:")
            for _, row in user_dl.iterrows():
                print(f"    - | {row['siCreateTime (UTC)']} | {row['Filename']}")

def detectar_ejecucion_programas(df):
    print("\n[+] Analizando prefetch (.pf) para detectar ejecución de aplicaciones:")
    df_pf = df[
        (df['Directory'] == False) &
        (df['FullPath'].str.contains(r'\\Windows\\Prefetch\\', case=False, na=False)) &
        (df['Filename'].str.endswith('.pf', na=False))
    ].copy()
    
    if df_pf.empty:
        print("  [-] No se han encontrado archivos Prefetch.")
        return
        
    df_pf['siModTime (UTC)'] = pd.to_datetime(df_pf['siModTime (UTC)'], errors='coerce')
    top_pf = df_pf.sort_values(by='siModTime (UTC)', ascending=False).head(10)
    
    for _, row in top_pf.iterrows():
        print(f"    - | {row['siModTime (UTC)']} | {row['Filename']}")

def detectar_papelera_reciclaje(df):
    print("\n[+] Analizando Papelera de Reciclaje (Archivos borrados):")
    df_rb = df[
        (df['Directory'] == False) &
        (df['FullPath'].str.contains(r'\\\$Recycle\.Bin\\', case=False, na=False)) &
        (df['Filename'].str.startswith('$I', na=False))
    ].copy()
    
    if df_rb.empty:
        print("  [-] No se han encontrado archivos en la papelera.")
        return
        
    df_rb['siCreateTime (UTC)'] = pd.to_datetime(df_rb['siCreateTime (UTC)'], errors='coerce')
    top_rb = df_rb.sort_values(by='siCreateTime (UTC)', ascending=False).head(10)
    
    for _, row in top_rb.iterrows():
        sid = row['FullPath'].split('\\')[-2] if len(row['FullPath'].split('\\')) > 1 else 'Desconocido'
        print(f"    - Eliminado: {row['siCreateTime (UTC)']} | SID: {sid} | Archivo Info: {row['Filename']}")

def detectar_archivos_recientes(df):
    print("\n[+] Analizando archivos de acceso reciente (LNK):")
    df_lnk = df[
        (df['Directory'] == False) &
        (df['FullPath'].str.contains(r'\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\', case=False, na=False)) &
        (df['Filename'].str.endswith('.lnk', na=False))
    ].copy()
    
    if df_lnk.empty:
        print("  [-] No se han encontrado accesos recientes en la carpeta Recent.")
        return
        
    df_lnk['Usuario'] = df_lnk['FullPath'].str.split('\\').str[2]
    df_lnk = df_lnk[~df_lnk['Usuario'].isin(usuarios_excluir)]
    df_lnk['siModTime (UTC)'] = pd.to_datetime(df_lnk['siModTime (UTC)'], errors='coerce')
    
    for usuario in df_lnk['Usuario'].unique():
        user_lnk = df_lnk[df_lnk['Usuario'] == usuario].sort_values(by='siModTime (UTC)', ascending=False).head(5)
        if not user_lnk.empty:
            print(f"\n  [Usuario: {usuario}] - Top 5 accesos recientes:")
            for _, row in user_lnk.iterrows():
                print(f"    - | {row['siModTime (UTC)']} | {row['Filename']}")

def detectar_timestomping(df):
    print("\n[+] Buscando posible Timestomping (SI vs FN timestamps):")
    if 'fnCreateTime (UTC)' not in df.columns or 'siCreateTime (UTC)' not in df.columns:
        print("  [-] No hay suficientes columnas ($FILE_NAME no detectada) para evaluar Timestomping.")
        return

    df_ts = df[['FullPath', 'Filename', 'siCreateTime (UTC)', 'fnCreateTime (UTC)']].copy()
    df_ts['si'] = pd.to_datetime(df_ts['siCreateTime (UTC)'], errors='coerce')
    df_ts['fn'] = pd.to_datetime(df_ts['fnCreateTime (UTC)'], errors='coerce')
    df_ts = df_ts.dropna(subset=['si', 'fn'])
    
    df_ts['diff_days'] = (df_ts['fn'] - df_ts['si']).dt.days
    
    df_suspicious = df_ts[df_ts['diff_days'] > 1].sort_values(by='diff_days', ascending=False)
    
    if df_suspicious.empty:
         print("  [-] No se han detectado anomalias evidentes de cambio de fecha.")
    else:
         print(f"  [!] Encontrados {len(df_suspicious)} archivos sospechosos. Top 10:")
         for _, row in df_suspicious.head(10).iterrows():
             print(f"    - {row['Filename']} | Dif: {row['diff_days']} días | "
                   f"SI: {row['si']} | FN(Kernel): {row['fn']}")

def detectar_instalacion_software(df):
    print("\n[+] Analizando posibles instalaciones recientes de software:")
    
    df_prog = df[
        (df['Directory'] == True) &
        (df['FullPath'].str.contains(r'\\Program Files(?: \(x86\))?\\[^\\]+$', case=False, na=False))
    ].copy()
    
    if df_prog.empty:
        print("  [-] No se han encontrado carpetas de instalación en Program Files.")
        return
        
    df_prog['siCreateTime (UTC)'] = pd.to_datetime(df_prog['siCreateTime (UTC)'], errors='coerce')
    top_prog = df_prog.sort_values(by='siCreateTime (UTC)', ascending=False).head(10)
    
    for _, row in top_prog.iterrows():
         print(f"    - Instalado: {row['siCreateTime (UTC)']} | Ruta: {row['FullPath']}")

def main():
    ruta_mft = seleccionar_mft()
    
    if not ruta_mft:
        print("[!] No se seleccionó ningún archivo")
        return
        
    fecha_str = datetime.now().strftime("%d%m%Y")
    nombre_log = f"{fecha_str}-TelenoMFTAnalyzer.txt"
    # Guardamos el txt en el mismo directorio donde está el MFT
    ruta_log = os.path.join(os.path.dirname(ruta_mft), nombre_log)
    
    print(f"[*] Analizando la evidencia temporal: {ruta_mft}")
    print(f"[*] El informe detallado se guardará en: {ruta_log}")
    
    # Guardamos la salida estándar original para restaurarla después
    original_stdout = sys.stdout
    
    try:
        with open(ruta_log, 'w', encoding='utf-8') as f_log:
            # Redirigir todos los prints al archivo
            sys.stdout = f_log
            
            print(f"==================================================")
            print(f" Teleno MFT Analyzer Reporte - {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
            print(f"==================================================\n")
            
            salida_csv = os.path.splitext(ruta_mft)[0] + "_parsed.csv"
            
            ejecutar_mftdump(ruta_mft, salida_csv)
            
            df = cargar_csv(salida_csv)
            
            # Análisis Base
            detectar_primer_logon(df)
            detectar_ultimo_logon(df)
            
            # Análisis Avanzados
            detectar_descargas(df)
            detectar_ejecucion_programas(df)
            detectar_papelera_reciclaje(df)
            detectar_archivos_recientes(df)
            detectar_instalacion_software(df)
            detectar_timestomping(df)
            
    finally:
        # Restaurar salida por consola
        sys.stdout = original_stdout
        print(f"[+] Análisis completado. Revisa el archivo: {ruta_log}")

if __name__ == "__main__":
    main()