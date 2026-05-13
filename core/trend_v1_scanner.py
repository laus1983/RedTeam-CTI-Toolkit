import os
import time
import requests
import pandas as pd
import re
import json
from datetime import datetime
from dotenv import load_dotenv

# Carga de variables de entorno
load_dotenv(override=True)

# ==================================
# CACHÉ GLOBAL DE INVENTARIO
# ==================================
_INVENTARIO_CACHE = []

def get_headers():
    token = os.getenv("TREND_V1_TOKEN", "").strip()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

def get_base_url():
    url_raw = os.getenv("TREND_V1_URL", "").replace("https://", "").strip().strip("/")
    return f"https://{url_raw}/v3.0" if url_raw else "https://api.xdr.trendmicro.com/v3.0"

def format_trend_date(date_val, is_end=False):
    try:
        if isinstance(date_val, (int, float)) or (isinstance(date_val, str) and date_val.isdigit()):
            epoch = int(date_val)
            if epoch > 9999999999: epoch = epoch / 1000
            return datetime.utcfromtimestamp(epoch).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        d_str = str(date_val).strip()
        if len(d_str) == 10:
            return f"{d_str}T23:59:59Z" if is_end else f"{d_str}T00:00:00Z"
        if "T" in d_str and not d_str.endswith("Z"):
            return f"{d_str}Z"
        return d_str
    except Exception:
        return str(date_val)

def formatear_fecha_humana(epoch_val):
    if not epoch_val or str(epoch_val).upper() == "N/A": 
        return "N/A"
    try:
        epoch = float(epoch_val)
        if epoch > 9999999999: 
            epoch = epoch / 1000
        return datetime.fromtimestamp(epoch).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(epoch_val)

# ==================================
# EXTRACTORES LIMPIOS
# ==================================
def extract_ip_clean(val):
    match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(val))
    return match.group(0) if match else "N/A"

def extract_custom_tags(item):
    raw_tags = []
    for key in ["tags", "tag", "customTags", "eventTag"]:
        val = item.get(key)
        if isinstance(val, list): raw_tags.extend(val)
        elif isinstance(val, str): raw_tags.append(val)
            
    prov = item.get("providerMetadata", {})
    if isinstance(prov, dict):
        for key in ["tags", "tag"]:
            val = prov.get(key)
            if isinstance(val, list): raw_tags.extend(val)
            elif isinstance(val, str): raw_tags.append(val)

    custom_tags = []
    for t in raw_tags:
        t_str = str(t).strip()
        if "MITRE" not in t_str and "XSAE" not in t_str and "THREAT" not in t_str and t_str:
            custom_tags.append(t_str)

    return ", ".join(custom_tags) if custom_tags else "N/A"

def get_server_ip(item, fallback_ip=None):
    """ Extrae y une TODAS las IPs disponibles del servidor """
    ips_found = []
    
    ip_list = item.get("ipAddresses", [])
    if isinstance(ip_list, list):
        for ip in ip_list:
            ip_str = str(ip).strip()
            if ip_str not in ips_found and "." in ip_str:
                ips_found.append(ip_str)

    last_ip = item.get("lastUsedIp")
    if last_ip and isinstance(last_ip, str) and "." in last_ip:
        last_ip_str = last_ip.strip()
        if last_ip_str not in ips_found:
            ips_found.append(last_ip_str)
                
    if ips_found:
        # AHORA DEVUELVE TODAS LAS IPs SEPARADAS POR COMA EN LUGAR DE SOLO LA PRIMERA
        return ", ".join(ips_found)
        
    ip_regex = extract_ip_clean(item)
    if ip_regex != "N/A": return ip_regex
    
    if fallback_ip and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', fallback_ip):
        return fallback_ip

    return "N/A"

def get_server_os(item):
    for k in ["osName", "osDescription", "osVersion", "osPlatform"]:
        if item.get(k): return str(item.get(k))
    return "N/A"

# ==================================
# 1. EVENTOS IPS
# ==================================
def descargar_eventos_ips(fecha_inicio, fecha_fin, archivo_excel="Métricas Trend Vision One.xlsx", log_callback=None, stop_event=None):
    def log(msg):
        if log_callback: log_callback(msg)

    base_url = get_base_url()
    headers = get_headers()
    headers["TMV1-Query"] = 'Reset OR Prevent OR "Intrusion Prevention"'
    
    params = {
        "startDateTime": format_trend_date(fecha_inicio, is_end=False),
        "endDateTime": format_trend_date(fecha_fin, is_end=True),
        "top": 500
    }

    log(f"[*] Solicitando eventos IPS a la base de datos...")
    
    endpoints = [
        f"{base_url}/search/endpointActivities", 
        f"{base_url}/search/networkActivities", 
        f"{base_url}/search/detections"
    ]
    logs_totales = []
    
    for ep in endpoints:
        if stop_event and stop_event.is_set(): return False, "Abortado."
        
        for attempt in range(2): 
            try:
                resp = requests.get(ep, params=params, headers=headers, timeout=40)
                if resp.status_code == 200:
                    items = resp.json().get("items", [])
                    if items:
                        logs_totales.extend(items)
                        log(f"[+] ¡{len(items)} eventos hallados!")
                        break 
            except Exception:
                pass
                
            if not logs_totales:
                time.sleep(3) 

    if not logs_totales: 
        return True, "No se hallaron eventos de bloqueo."

    datos = []
    for l in logs_totales:
        clean_date = formatear_fecha_humana(l.get("eventTime"))
        host_name = l.get("endpointHostName", l.get("dhost", "N/A"))
        action_val = l.get("action", "N/A")
        
        etiquetas_limpias = extract_custom_tags(l)
        src_ip = extract_ip_clean(l.get("sourceIp", l.get("src", "N/A")))
        dst_ip = extract_ip_clean(l.get("destinationIp", l.get("dst", "N/A")))

        datos.append({
            "Date": clean_date,
            "Computer": host_name,
            "Reason": l.get("ruleName", l.get("reason", l.get("eventName", "N/A"))),
            "Tag(s)": etiquetas_limpias,
            "Action": action_val,
            "Source IP": src_ip,
            "Destination IP": dst_ip
        })

    df = pd.DataFrame(datos)
    if os.path.exists(archivo_excel):
        with pd.ExcelWriter(archivo_excel, engine='openpyxl', mode='a', if_sheet_exists='overlay') as writer:
            try:
                df.to_excel(writer, sheet_name="Intrusion_Prevention_Events", index=False, header=False, startrow=writer.book["Intrusion_Prevention_Events"].max_row)
            except KeyError:
                df.to_excel(writer, sheet_name="Intrusion_Prevention_Events", index=False)
    else:
        df.to_excel(archivo_excel, sheet_name="Intrusion_Prevention_Events", index=False)

    return True, f"Éxito: {len(datos)} eventos guardados."

# ==================================
# 2. VALIDACIÓN DE ACTIVOS (INYECCIÓN DE LLAVES)
# ==================================

def get_inventario_maestro(log_callback=None, stop_event=None):
    global _INVENTARIO_CACHE
    if _INVENTARIO_CACHE:
        return _INVENTARIO_CACHE
        
    base_url = get_base_url()
    headers = get_headers()
    url = f"{base_url}/endpointSecurity/endpoints"
    params = {"top": 1000} 
    
    inventario = []
    pagina = 1

    if log_callback: log_callback("[*] Descargando Inventario Maestro...")
    
    try:
        while url:
            if stop_event and stop_event.is_set(): break
            resp = requests.get(url, params=params, headers=headers, timeout=30)
            if resp.status_code != 200: break
            data = resp.json()
            items = data.get("items", [])
            inventario.extend(items)
            if log_callback: log_callback(f"[+] Página {pagina} ok. Servidores: {len(inventario)}")
            next_link = data.get("nextLink")
            if next_link:
                url = next_link
                params = None 
                pagina += 1
            else: break
                
        if inventario:
            _INVENTARIO_CACHE = inventario
        return inventario
    except Exception as e:
        return inventario

def buscar_servidor_local(criterio, inventario):
    criterio_lower = str(criterio).strip().lower()
    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', criterio_lower))
    resultados_encontrados = []

    for item in inventario:
        match_found = False
        if is_ip:
            last_ip = str(item.get("lastUsedIp", "")).lower()
            if last_ip == criterio_lower: match_found = True
            for ip in item.get("ipAddresses", []):
                if str(ip).lower() == criterio_lower: match_found = True
        else:
            hostname = str(item.get("endpointName", "")).lower()
            if criterio_lower in hostname: match_found = True
                
        if match_found:
            # Extraemos la información real de manera segura (AQUÍ ESTÁN MÚLTIPLES IPs)
            ip_real = get_server_ip(item, fallback_ip=criterio if is_ip else None)
            host_real = item.get("endpointName", "N/A")
            so_real = get_server_os(item)

            # Inyectamos en el diccionario
            item["IP"] = ip_real
            item["ip"] = ip_real
            item["Ip"] = ip_real
            item["ipAddress"] = ip_real
            item["lastUsedIp"] = ip_real
            
            item["Hostname"] = host_real
            item["hostname"] = host_real
            
            item["SO"] = so_real
            item["so"] = so_real
            item["osName"] = so_real

            resultados_encontrados.append(item)
                
    return resultados_encontrados

def buscar_servidor_api(criterio):
    """ Función para búsqueda manual en la interfaz """
    inventario = get_inventario_maestro()
    if not inventario: return []
    return buscar_servidor_local(criterio, inventario)

def procesar_archivo_servidores(ruta_archivo, log_callback=None, stop_event=None):
    def log(msg):
        if log_callback: log_callback(msg)
    try:
        inventario_maestro = get_inventario_maestro(log_callback, stop_event)
        if not inventario_maestro: return False, "Error al descargar inventario."
            
        log("[*] Inventario maestro en memoria. Procesando Excel...")
        df = pd.read_excel(ruta_archivo) if ruta_archivo.endswith('.xlsx') else pd.read_csv(ruta_archivo)
        lista = df.iloc[:, 0].dropna().astype(str).str.strip().tolist()

        resultados_exportar = []
        for i, item in enumerate(lista, 1):
            if stop_event and stop_event.is_set(): break
            log(f"   ({i}/{len(lista)}) Cruzando datos: {item}")
            
            matches = buscar_servidor_local(item, inventario_maestro)
            if matches:
                for s in matches:
                    resultados_exportar.append([item, s.get("Hostname"), s.get("IP"), s.get("SO"), "Válido"])
            else:
                resultados_exportar.append([item, "N/A", "N/A", "N/A", "No encontrado"])

        pd.DataFrame(resultados_exportar, columns=["Busqueda", "Hostname", "IP", "SO", "Estado"]).to_csv(f"Validacion_v3_{int(time.time())}.csv", index=False)
        return True, "Validación finalizada con éxito."
    except Exception as e:
        return False, str(e)