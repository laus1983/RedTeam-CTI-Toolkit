import os
import csv
import time
import requests
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv

def get_headers():
    load_dotenv()
    token = os.getenv("TREND_V1_TOKEN")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

def get_base_url():
    url = os.getenv("TREND_V1_URL", "").replace("https://", "").strip("/")
    return f"https://{url}/v3.0"

# --- MÉTRICAS IPS (ENDPOINT SECURITY) ---
def descargar_eventos_ips(fecha_inicio, fecha_fin, archivo_excel="Métricas Trend Vision One.xlsx", log_callback=None, stop_event=None):
    def log(msg):
        if log_callback: log_callback(msg)

    base_url = get_base_url()
    headers = get_headers()
    endpoint = f"{base_url}/search/logs"
    
    # Query específico para eventos de Intrusión (IPS)
    payload = {
        "query": "source:endpointSecurity AND eventName:\"Intrusion Prevention Event\"",
        "from": fecha_inicio,
        "to": fecha_fin,
        "source": "endpointSecurity"
    }

    log(f"[*] Consultando métricas IPS en el periodo indicado...")
    
    try:
        response = requests.post(endpoint, headers=headers, json=payload, timeout=30)
        
        # Validación de Rotación de Token
        if response.status_code == 401:
            return False, "TOKEN_EXPIRED: El token de Trend Vision One ha expirado. Por favor, genere uno nuevo en la consola (Recuerde la rotación cada 90 días)."
        
        if response.status_code != 200:
            return False, f"Error API Trend: HTTP {response.status_code}"
        
        eventos = response.json().get("logs", [])
        if not eventos:
            return True, "No se encontraron eventos IPS en este rango de fechas."

        log(f"[+] {len(eventos)} eventos encontrados. Actualizando Excel...")
        df_nuevos = pd.DataFrame(eventos)

        # Lógica para no sobrescribir el archivo Excel existente
        if os.path.exists(archivo_excel):
            with pd.ExcelWriter(archivo_excel, engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
                try:
                    start_row = writer.book["IPS_Events"].max_row
                    df_nuevos.to_excel(writer, sheet_name="IPS_Events", index=False, header=False, startrow=start_row)
                except KeyError:
                    df_nuevos.to_excel(writer, sheet_name="IPS_Events", index=False)
        else:
            df_nuevos.to_excel(archivo_excel, sheet_name="IPS_Events", index=False)

        return True, f"Métricas añadidas exitosamente a {archivo_excel}."

    except Exception as e:
        return False, f"Error en módulo IPS: {str(e)}"

# --- VALIDACIÓN DE ACTIVOS / SERVIDORES ---
def buscar_servidor_api(criterio):
    base_url = get_base_url()
    headers = get_headers()
    endpoint = f"{base_url}/endpointInventory/endpoints"
    
    # Detección automática: Si tiene puntos es IP, si no es Hostname
    params = {"ip": criterio} if "." in criterio else {"endpointName": criterio}

    try:
        response = requests.get(endpoint, headers=headers, params=params, timeout=15)
        if response.status_code == 401: return "EXPIRED"
        if response.status_code == 200:
            return response.json().get("items", [])
        return []
    except:
        return []

def procesar_archivo_servidores(ruta_archivo, log_callback=None, stop_event=None):
    def log(msg):
        if log_callback: log_callback(msg)

    try:
        ext = os.path.splitext(ruta_archivo)[1].lower()
        # Validación de integridad del archivo (soporta CSV con delimitadores automáticos)
        if ext == '.csv':
            df = pd.read_csv(ruta_archivo, sep=None, engine='python')
        else:
            df = pd.read_excel(ruta_archivo)

        if df.empty: return False, "El archivo seleccionado está vacío."

        lista_items = df.iloc[:, 0].dropna().astype(str).tolist()
        log(f"[*] Archivo validado. Iniciando búsqueda de {len(lista_items)} servidores...")

        resultados = []
        for i, item in enumerate(lista_items, 1):
            if stop_event and stop_event.is_set():
                log("🚫 Proceso de validación abortado.")
                break
            
            log(f"[*] Buscando ({i}/{len(lista_items)}): {item}")
            info = buscar_servidor_api(item.strip())
            
            if info == "EXPIRED":
                return False, "TOKEN_EXPIRED: Token de API caducado."
            
            if info:
                s = info[0]
                resultados.append([item, s.get("endpointName"), s.get("ip"), s.get("osName"), "Encontrado"])
            else:
                resultados.append([item, "N/A", "N/A", "N/A", "No encontrado"])
            
            time.sleep(0.1)

        # Generar reporte de validación
        df_res = pd.DataFrame(resultados, columns=["Busqueda", "Hostname", "IP Real", "SO", "Estado"])
        nom_reporte = f"Validacion_Trend_{int(time.time())}.csv"
        df_res.to_csv(nom_reporte, index=False)
        
        return True, f"Validación finalizada. Reporte generado: {nom_reporte}"

    except Exception as e:
        return False, f"Error al procesar archivo: {str(e)}"