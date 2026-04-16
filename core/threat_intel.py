import requests
import hashlib
import base64

def check_ip(ip, vt_key, abuse_key):
    resultado = {"IoC": ip, "VT_Positivos": "N/A", "AbuseIPDB_Score": "N/A", "Pais": "N/A", "ISP": "N/A"}
    if abuse_key:
        try:
            url_abuse = "https://api.abuseipdb.com/api/v2/check"
            headers_abuse = {'Accept': 'application/json', 'Key': abuse_key}
            res_abuse = requests.get(url_abuse, headers=headers_abuse, params={'ipAddress': ip, 'maxAgeInDays': '90'}, timeout=10)
            if res_abuse.status_code == 200:
                data = res_abuse.json().get('data', {})
                resultado['AbuseIPDB_Score'] = f"{data.get('abuseConfidenceScore', 0)}%"
                resultado['Pais'] = data.get('countryCode', 'N/A')
                resultado['ISP'] = data.get('isp', 'N/A')
        except: pass
    if vt_key:
        try:
            url_vt = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers_vt = {"x-apikey": vt_key}
            res_vt = requests.get(url_vt, headers=headers_vt, timeout=10)
            if res_vt.status_code == 200:
                stats = res_vt.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                resultado['VT_Positivos'] = f"{stats.get('malicious', 0)} / {sum(stats.values())}"
        except: pass
    return resultado

def check_url(url_target, vt_key):
    resultado = {"IoC": url_target, "VT_Positivos": "N/A", "Categoria": "N/A"}
    if not vt_key: return resultado
    try:
        url_id = base64.urlsafe_b64encode(url_target.encode()).decode().strip("=")
        url_vt = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers_vt = {"x-apikey": vt_key}
        res_vt = requests.get(url_vt, headers=headers_vt, timeout=10)
        if res_vt.status_code == 200:
            attrs = res_vt.json().get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            resultado['VT_Positivos'] = f"{stats.get('malicious', 0)} / {sum(stats.values())}"
            categories = attrs.get('categories', {})
            if categories: resultado['Categoria'] = list(categories.values())[0]
    except: pass
    return resultado

def check_file_hash(filepath, vt_key):
    resultado = {"IoC": filepath, "SHA256": "Error", "VT_Positivos": "N/A", "Status": "No encontrado"}
    if not vt_key: return resultado
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()
        resultado["SHA256"] = file_hash
        url_vt = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers_vt = {"x-apikey": vt_key}
        res_vt = requests.get(url_vt, headers=headers_vt, timeout=10)
        if res_vt.status_code == 200:
            stats = res_vt.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            resultado['VT_Positivos'] = f"{stats.get('malicious', 0)} / {sum(stats.values())}"
            resultado['Status'] = "Analizado"
        elif res_vt.status_code == 404:
            resultado['Status'] = "No visto en VT"
    except Exception as e:
        resultado["Status"] = f"Error local: {e}"
    return resultado