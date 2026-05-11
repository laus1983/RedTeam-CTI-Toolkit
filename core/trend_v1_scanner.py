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
    
    # Query para eventos de Intrusion Prevention (IPS)
    payload = {
        "query": "source:endpointSecurity AND eventName:\"Intrusion Prevention Event\"",
        "from": fecha_inicio,
        "to": fecha_fin,
        "source": "endpointSecurity"
    }

    log(f"[*] Consultando métricas IPS en el periodo indicado...")
    
    try:
        response = requests.post(endpoint, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 401:
            return False, "TOKEN_EXPIRED: El token de Trend Vision One ha expirado. Por favor, rote su API Key (90 días recomendados)."
        
        if response.status_code != 200:
            return False, f"Error API Trend: HTTP {response.status_code}"
        
        eventos = response.json().get("logs", [])
        if not eventos:
            return True, "No se encontraron eventos IPS en este rango de fechas."

        log(f"[+] {len(eventos)} eventos encontrados. Actualizando archivo de métricas...")
        df_nuevos = pd.DataFrame(eventos)

        # Lógica para añadir datos al Excel sin sobrescribir lo anterior
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

# --- BÚSQUEDA Y VALIDACIÓN DE SERVIDORES ---
def buscar_servidor_api(criterio):
    base_url = get_base_url()
    headers = get_headers()
    endpoint = f"{base_url}/endpointInventory/endpoints"
    
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
        if ext == '.csv':
            df = pd.read_csv(ruta_archivo, sep=None, engine='python')
        else:
            df = pd.read_excel(ruta_archivo)

        if df.empty: return False, "El archivo está vacío."

        lista_items = df.iloc[:, 0].dropna().astype(str).tolist()
        log(f"[*] Procesando lista de {len(lista_items)} servidores...")

        resultados = []
        for i, item in enumerate(lista_items, 1):
            if stop_event and stop_event.is_set():
                log("🚫 Validación abortada por el usuario.")
                break
            
            log(f"[*] Validando ({i}/{len(lista_items)}): {item}")
            info = buscar_servidor_api(item.strip())
            
            if info == "EXPIRED":
                return False, "TOKEN_EXPIRED: API Key caducada."
            
            if info:
                s = info[0]
                resultados.append([item, s.get("endpointName"), s.get("ip"), s.get("osName"), "Válido"])
            else:
                resultados.append([item, "N/A", "N/A", "N/A", "No encontrado"])
            
            time.sleep(0.1) # Evitar saturar la API

        df_res = pd.DataFrame(resultados, columns=["Entrada", "Hostname", "IP", "SO", "Estado"])
        reporte = f"Validacion_Trend_{int(time.time())}.csv"
        df_res.to_csv(reporte, index=False)
        
        return True, f"Validación finalizada. Reporte: {reporte}"

    except Exception as e:
        return False, f"Error al procesar archivo: {str(e)}"