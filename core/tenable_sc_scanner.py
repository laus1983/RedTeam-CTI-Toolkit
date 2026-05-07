import os
import csv
from dotenv import load_dotenv
from tenable.sc import TenableSC

def analizar_impacto(archivo_entrada_cves="listado_cves_nuevos.csv", archivo_resumen="resumen_impacto_global.csv"):
    """
    Lee un archivo CSV con CVEs, consulta Tenable SC y genera reportes de impacto.
    Retorna una tupla: (bool_exito, mensaje_resultado)
    """
    load_dotenv()

    SC_IP = os.getenv("SC_IP")
    SC_ACCESS_KEY = os.getenv("SC_ACCESS_KEY")
    SC_SECRET_KEY = os.getenv("SC_SECRET_KEY")

    if not all([SC_IP, SC_ACCESS_KEY, SC_SECRET_KEY]):
        return False, "Faltan credenciales en el archivo .env (SC_IP, SC_ACCESS_KEY, SC_SECRET_KEY)."

    try:
        sc = TenableSC(SC_IP, access_key=SC_ACCESS_KEY, secret_key=SC_SECRET_KEY)
    except Exception as e:
        return False, f"Error al conectar con Security Center: {e}"

    datos_resumen_maestro = []

    if not os.path.exists(archivo_entrada_cves):
        return False, f"No se encontró el archivo de entrada: {archivo_entrada_cves}. Ejecute primero la extracción de CVEs."

    try:
        with open(archivo_entrada_cves, mode='r', encoding='utf-8') as f_entrada:
            lector = csv.reader(f_entrada)
            for fila in lector:
                if not fila:
                    continue
                
                cve_actual = fila[0].strip()
                if not cve_actual.startswith("CVE-"):
                    continue

                try:
                    resultados = sc.analysis.vulns(('cveID', '=', cve_actual), tool='sumip')
                    lista_hosts = list(resultados)
                    numero_de_hosts = len(lista_hosts)

                    if numero_de_hosts == 0:
                        datos_resumen_maestro.append([cve_actual, "0", "Sin impacto detectado"])
                    else:
                        datos_resumen_maestro.append([cve_actual, str(numero_de_hosts), "Requiere remediación"])
                        
                        # Generar archivo específico por CVE
                        archivo_detalle = f"afectados_{cve_actual}.csv"
                        with open(archivo_detalle, mode='w', newline='', encoding='utf-8') as f_detalle:
                            writer = csv.writer(f_detalle)
                            writer.writerow(["IP del Host", "DNS / Hostname", "Severidad", "MAC Address", "Repositorio"])
                            
                            for host in lista_hosts:
                                ip = host.get('ip', 'N/A')
                                dns = host.get('dnsName', 'N/A')
                                severity = host.get('severity', 'N/A')
                                mac = host.get('macAddress', 'N/A')
                                repositorio = host.get('repository', {}).get('name', 'N/A') 
                                
                                writer.writerow([ip, dns, severity, mac, repositorio])

                except Exception as e:
                    datos_resumen_maestro.append([cve_actual, "Error", f"Error en API: {e}"])

        # Escribir el resumen maestro
        with open(archivo_resumen, mode='w', newline='', encoding='utf-8') as f_resumen:
            writer = csv.writer(f_resumen)
            writer.writerow(["CVE", "Total Servidores Afectados", "Estado"])
            writer.writerows(datos_resumen_maestro)

        return True, f"Análisis completado. Resumen guardado en {archivo_resumen}"

    except Exception as e:
        return False, f"Error durante el procesamiento: {e}"