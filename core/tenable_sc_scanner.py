import os
import csv
import time
from dotenv import load_dotenv
from tenable.sc import TenableSC

def analizar_impacto(archivo_entrada_cves="listado_cves_nuevos.csv", archivo_resumen="resumen_impacto_global.csv", log_callback=None, stop_event=None):
    """
    Lee un archivo CSV con CVEs, consulta Tenable SC y genera reportes de impacto.
    Ahora soporta eventos de parada y reportes de progreso a una GUI.
    """
    # Función interna para enviar mensajes a la consola de la GUI si existe
    def log(msg):
        if log_callback:
            log_callback(msg)

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
        return False, f"No se encontró el archivo de entrada: {archivo_entrada_cves}."

    try:
        with open(archivo_entrada_cves, mode='r', encoding='utf-8') as f_entrada:
            lector = csv.reader(f_entrada)
            
            # Primero leemos todas las filas válidas para saber el total y mostrar progreso
            cves_a_procesar = []
            for fila in lector:
                if fila and fila[0].strip().startswith("CVE-"):
                    cves_a_procesar.append(fila[0].strip())
            
            total_cves = len(cves_a_procesar)
            
            if total_cves == 0:
                return False, "No se encontraron CVEs válidos para procesar."
                
            log(f"[*] Se detectaron {total_cves} CVE(s) para evaluar en Tenable SC.")

            # Bucle de procesamiento
            for i, cve_actual in enumerate(cves_a_procesar, start=1):
                # Validar si el usuario presionó el botón "Abortar"
                if stop_event and stop_event.is_set():
                    log("🚫 [Tenable] El análisis fue abortado por el usuario.")
                    break

                log(f"[*] Analizando {i}/{total_cves}: {cve_actual}...")

                try:
                    resultados = sc.analysis.vulns(('cveID', '=', cve_actual), tool='sumip')
                    lista_hosts = list(resultados)
                    numero_de_hosts = len(lista_hosts)

                    if numero_de_hosts == 0:
                        datos_resumen_maestro.append([cve_actual, "0", "Sin impacto detectado"])
                    else:
                        log(f"   [!] IMPACTO DETECTADO: {numero_de_hosts} servidor(es) afectados.")
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
                    log(f"   [-] Error consultando API para {cve_actual}: {e}")
                    datos_resumen_maestro.append([cve_actual, "Error", f"Error en API: {e}"])
                
                # Pequeña pausa para no saturar la API y permitir que la GUI se actualice
                time.sleep(0.2)

        # Si se procesó al menos algo, guardamos el reporte maestro
        if datos_resumen_maestro:
            with open(archivo_resumen, mode='w', newline='', encoding='utf-8') as f_resumen:
                writer = csv.writer(f_resumen)
                writer.writerow(["CVE", "Total Servidores Afectados", "Estado"])
                writer.writerows(datos_resumen_maestro)

        return True, f"Análisis finalizado. Resumen guardado en {archivo_resumen}"

    except Exception as e:
        return False, f"Error durante el procesamiento: {e}"