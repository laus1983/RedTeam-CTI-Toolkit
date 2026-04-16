import requests
import time

def extraer_info_cpe(cve_item):
    cpes_raw = []
    tecnologias = []

    configurations = cve_item.get("configurations", [])
    for conf in configurations:
        nodes = conf.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for match in cpe_matches:
                criteria = match.get("criteria", "")
                if criteria:
                    cpes_raw.append(criteria)
                    partes = criteria.split(":")
                    if len(partes) >= 6:
                        vendor = partes[3].capitalize()
                        product = partes[4].capitalize()
                        version = partes[5]
                        tech_str = f"{vendor} {product}" if version in ["*", "-", ""] else f"{vendor} {product} v{version}"
                        tecnologias.append(tech_str)

    raw_str = " | ".join(list(dict.fromkeys(cpes_raw))[:3]) if cpes_raw else "N/A"
    tech_str = " | ".join(list(dict.fromkeys(tecnologias))[:3]) if tecnologias else "Sin datos de software específicos"

    return raw_str, tech_str

def ejecutar_escaneo_cve(params, headers, callback_log, stop_event):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cve_list = []
    total_results = 1
    
    try:
        while params["startIndex"] < total_results:
            if stop_event.is_set():
                break # Sale inmediatamente

            response = requests.get(url, params=params, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                total_results = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])
                
                if total_results == 0:
                    callback_log("∅ No se encontraron CVEs con estos filtros.")
                    break
                    
                callback_log(f"📥 Progreso NVD: {min(params['startIndex'] + len(vulnerabilities), total_results)} / {total_results}")

                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "N/A")
                    published = cve.get("published", "N/A")
                    descriptions = cve.get("descriptions", [])
                    description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "N/A")
                    
                    raw_cpe, tech_info = extraer_info_cpe(cve)
                    
                    cve_list.append({
                        "CVE ID": cve_id, 
                        "Fecha de Publicación": published, 
                        "Tecnología / Versión": tech_info,
                        "CPE Identificador": raw_cpe,
                        "Description": description
                    })
                
                params["startIndex"] += params["resultsPerPage"]
                
                if params["startIndex"] < total_results: 
                    for _ in range(6): 
                        if stop_event.is_set(): break
                        time.sleep(0.1)
            else:
                callback_log(f"❌ Error HTTP NVD: {response.status_code}.")
                break
                
        return cve_list
    except Exception as e:
        # Solo lo mostramos como error si NO fue un aborto intencional del usuario
        if not stop_event.is_set():
            callback_log(f"❌ Error crítico NVD: {str(e)}")
        return cve_list