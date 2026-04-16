import pandas as pd
import os
from datetime import datetime

def leer_iocs(filepath):
    """Lee IPs, URLs o Hashes desde TXT, CSV o Excel sin importar su disposición."""
    ext = os.path.splitext(filepath)[1].lower()
    iocs = []
    
    try:
        # Validar archivo vacío (0 bytes)
        if os.path.getsize(filepath) == 0:
            raise Exception("El archivo seleccionado está vacío (0 bytes).")

        if ext == ".txt":
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read().replace(',', '\n').replace(';', '\n')
                iocs = [line.strip() for line in content.split() if line.strip()]
                
        elif ext == ".csv":
            # Forzamos la separación por comas por defecto
            try:
                df = pd.read_csv(filepath, header=None, sep=',', on_bad_lines='skip')
            except:
                df = pd.read_csv(filepath, header=None, sep=None, engine='python')
                
            # Extraer TODAS las celdas (sin importar si son filas o columnas)
            iocs = pd.Series(df.values.flatten()).dropna().astype(str).str.strip()
            iocs = iocs[(iocs != '') & (iocs != 'nan')].tolist()
            
        elif ext in [".xlsx", ".xls"]:
            df = pd.read_excel(filepath, header=None)
            iocs = pd.Series(df.values.flatten()).dropna().astype(str).str.strip()
            iocs = iocs[(iocs != '') & (iocs != 'nan')].tolist()
            
        else:
            raise Exception("Formato de archivo no soportado.")

        if not iocs:
            raise Exception("No se encontraron elementos válidos en el archivo.")

        # Retornar lista limpia (y elimina duplicados manteniendo el orden)
        return list(dict.fromkeys(iocs))
        
    except Exception as e:
        raise Exception(f"Error procesando archivo: {str(e)}")

def generar_reporte_ti(resultados, tipo_ioc):
    """Genera un Excel y un TXT con los resultados."""
    if not resultados:
        return None, None
        
    fecha_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"Reporte_{tipo_ioc}_{fecha_str}"
    
    excel_path = f"{base_name}.xlsx"
    df = pd.DataFrame(resultados)
    df.to_excel(excel_path, index=False)
    
    txt_path = f"{base_name}.txt"
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(f"=== INFORME DE THREAT INTELLIGENCE ({tipo_ioc.upper()}) ===\n")
        f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*60 + "\n\n")
        for res in resultados:
            f.write(f"[*] Objeto: {res.get('IoC')}\n")
            for k, v in res.items():
                if k != 'IoC':
                    f.write(f"    - {k}: {v}\n")
            f.write("-" * 40 + "\n")
            
    return excel_path, txt_path