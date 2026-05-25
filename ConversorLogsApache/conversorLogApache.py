import os
import re
import csv
import tkinter as tk
from tkinter import filedialog, messagebox

def process_log_file():
    # Ocultar la ventana principal de tkinter
    root = tk.Tk()
    root.withdraw()
    
    # Mostrar el diálogo para seleccionar el archivo
    file_path = filedialog.askopenfilename(
        title="Selecciona el archivo de log de Apache",
        filetypes=[("Todos los archivos", "*.*"), ("Archivos de texto", "*.txt")]
    )
    
    if not file_path:
        return
    
    # Comprobar la extensión y añadir .txt si no la tiene
    _, ext = os.path.splitext(file_path)
    if ext.lower() != '.txt':
        new_file_path = file_path + '.txt'
        try:
            os.rename(file_path, new_file_path)
            file_path = new_file_path
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo renombrar el archivo a .txt:\n{e}")
            return
            
    # Preparar la ruta para el CSV (misma ruta pero cambiando la extensión final a .csv)
    base_name, _ = os.path.splitext(file_path)
    csv_path = base_name + '.csv'
    
    # Expresión regular para parsear las líneas del log de Apache (formato combinado)
    log_pattern = re.compile(
        r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(.*?)"\s+(\d{3})\s+(\S+)(?:\s+"(.*?)"\s+"(.*?)")?'
    )
    
    rows = []
    unparsed_lines = 0
    
    # Leer el archivo de log original
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                match = log_pattern.match(line)
                if match:
                    rows.append(match.groups())
                else:
                    # En caso de que haya una línea que no haga match con el regex,
                    # la podemos guardar como una sola columna para no perder información
                    rows.append([line, "", "", "", "", "", "", "", ""])
                    unparsed_lines += 1
    except Exception as e:
        messagebox.showerror("Error", f"Error al leer el archivo:\n{e}")
        return

    # Escribir el archivo CSV
    headers = ['IP', 'Identidad', 'Usuario', 'Fecha/Hora', 'Peticion', 'Codigo_Estado', 'Tamano_Bytes', 'Referer', 'User_Agent']
    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
            
        mensaje_exito = f"Archivo CSV generado correctamente en:\n{csv_path}"
        if unparsed_lines > 0:
            mensaje_exito += f"\n\nAviso: Hubo {unparsed_lines} línea(s) con formato diferente."
            
        messagebox.showinfo("Éxito", mensaje_exito)
        
    except Exception as e:
        messagebox.showerror("Error", f"Error al escribir el archivo CSV:\n{e}")

if __name__ == "__main__":
    process_log_file()
