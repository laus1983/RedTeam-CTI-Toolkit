import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import pandas as pd
import os
import time
import signal
import sys
from datetime import datetime

import config
from core.nvd_scanner import ejecutar_escaneo_cve
from core.threat_intel import check_ip, check_url, check_file_hash
from core.tenable_sc_scanner import analizar_impacto
from utils.file_manager import leer_iocs, generar_reporte_ti

class RedTeamToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced CTI & Vulnerability Toolkit")
        self.root.geometry("820x720")
        
        # Eventos para abortar hilos
        self.stop_event_cve = threading.Event()
        self.stop_event_ti = threading.Event()
        self.stop_event_tenable = threading.Event() # <--- NUEVO EVENTO
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Pestañas
        self.tab_cve = ttk.Frame(self.notebook)
        self.tab_ti = ttk.Frame(self.notebook)
        self.tab_tenable = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_cve, text="🛡️ Buscador CVE (NVD)")
        self.notebook.add(self.tab_ti, text="🕵️ Threat Intel (IoCs)")
        self.notebook.add(self.tab_tenable, text="🎯 Impacto Tenable SC")
        
        self.setup_cve_tab()
        self.setup_ti_tab()
        self.setup_tenable_tab()
        self.setup_console()

    def log(self, mensaje):
        self.log_area.insert(tk.END, mensaje + "\n")
        self.log_area.see(tk.END)

    def limpiar_consola(self):
        self.log_area.delete(1.0, tk.END)

    def setup_console(self):
        frame_consola = ttk.Frame(self.root)
        frame_consola.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        header_frame = ttk.Frame(frame_consola)
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="Consola de Estado:").pack(side="left")
        ttk.Button(header_frame, text="🧹 Limpiar Consola", command=self.limpiar_consola).pack(side="right")
        
        self.log_area = scrolledtext.ScrolledText(frame_consola, height=12, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True, pady=(5, 0))

    # ==========================================
    # TAB 1: BUSCADOR CVE
    # ==========================================
    def setup_cve_tab(self):
        frame = ttk.LabelFrame(self.tab_cve, text="Parámetros de Búsqueda NVD", padding=15)
        frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame, text="Inicio (DD/MM/AAAA):").grid(row=0, column=0, sticky="w")
        self.entry_inicio = ttk.Entry(frame, width=15)
        self.entry_inicio.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Fin (DD/MM/AAAA):").grid(row=0, column=2, sticky="w", padx=10)
        self.entry_fin = ttk.Entry(frame, width=15)
        self.entry_fin.grid(row=0, column=3, padx=5, pady=5)

        ttk.Label(frame, text="Palabra Clave:").grid(row=1, column=0, sticky="w")
        self.entry_keyword = ttk.Entry(frame, width=15)
        self.entry_keyword.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(frame, text="CPE Name:").grid(row=1, column=2, sticky="w", padx=10)
        self.entry_cpe = ttk.Entry(frame, width=25)
        self.entry_cpe.grid(row=1, column=3, padx=5, pady=5)

        ttk.Label(frame, text="Severidad CVSS:").grid(row=2, column=0, sticky="w", pady=5)
        self.combo_severidad = ttk.Combobox(frame, values=["TODAS", "LOW", "MEDIUM", "HIGH", "CRITICAL"], state="readonly", width=12)
        self.combo_severidad.current(0)
        self.combo_severidad.grid(row=2, column=1, padx=5, pady=5)

        btn_frame = ttk.Frame(self.tab_cve)
        btn_frame.pack(pady=10)
        
        self.btn_cve = ttk.Button(btn_frame, text="▶ Extraer CVEs", command=self.lanzar_cve)
        self.btn_cve.grid(row=0, column=0, padx=5)
        
        self.btn_abort_cve = ttk.Button(btn_frame, text="🛑 Abortar Proceso", command=self.abortar_cve, state=tk.DISABLED)
        self.btn_abort_cve.grid(row=0, column=1, padx=5)

    def abortar_cve(self):
        self.log("⚠️ Señal de aborto enviada... esperando a que la NVD libere la conexión de red.")
        self.stop_event_cve.set()
        self.btn_abort_cve.config(state=tk.DISABLED, text="⏳ Cancelando...")

    def lanzar_cve(self):
        params = {"resultsPerPage": 2000, "startIndex": 0}
        
        f_inicio = self.entry_inicio.get().strip()
        f_fin = self.entry_fin.get().strip()
        try:
            if f_inicio: params["pubStartDate"] = datetime.strptime(f_inicio, "%d/%m/%Y").strftime("%Y-%m-%dT00:00:00.000Z")
            if f_fin: params["pubEndDate"] = datetime.strptime(f_fin, "%d/%m/%Y").strftime("%Y-%m-%dT23:59:59.000Z")
        except:
            messagebox.showerror("Error", "Formato de fecha inválido.")
            return

        kw = self.entry_keyword.get().strip()
        cpe = self.entry_cpe.get().strip()
        severidad = self.combo_severidad.get()
        
        if kw: params["keywordSearch"] = kw
        if cpe: params["cpeName"] = cpe
        if severidad != "TODAS": params["cvssV3Severity"] = severidad

        self.log("\n🚀 Iniciando búsqueda de CVEs...")
        self.btn_cve.config(state=tk.DISABLED)
        self.btn_abort_cve.config(state=tk.NORMAL, text="🛑 Abortar Proceso")
        self.stop_event_cve.clear()
        
        threading.Thread(target=self.hilo_cve, args=(params,)).start()

    def hilo_cve(self, params):
        try:
            headers = {"apiKey": getattr(config, 'NVD_API_KEY', '')} if getattr(config, 'NVD_API_KEY', '') else {}
            cve_list = ejecutar_escaneo_cve(params, headers, self.log, self.stop_event_cve)
            
            if self.stop_event_cve.is_set():
                self.log("🚫 Proceso cancelado exitosamente. No se modificó el archivo Excel.")
                return 
                
            if cve_list:
                archivo_excel = "cve_data.xlsx"
                df_nuevo = pd.DataFrame(cve_list)
                
                df_nuevo["CVE ID"] = df_nuevo["CVE ID"].astype(str).str.strip()
                
                if os.path.exists(archivo_excel):
                    df_existente = pd.read_excel(archivo_excel)
                    
                    if not df_existente.empty and "CVE ID" in df_existente.columns:
                        df_existente["CVE ID"] = df_existente["CVE ID"].astype(str).str.strip()
                        nuevos = df_nuevo[~df_nuevo["CVE ID"].isin(df_existente["CVE ID"])]
                        
                        if not nuevos.empty:
                            df_final = pd.concat([df_existente, nuevos], ignore_index=True)
                            df_final = df_final.drop_duplicates(subset=["CVE ID"], keep="last")
                            df_final.to_excel(archivo_excel, index=False)
                            self.log(f"✅ ÉXITO: Se descargaron {len(df_nuevo)} CVEs. {len(nuevos)} eran nuevos y se agregaron al Excel.")
                        else:
                            self.log(f"ℹ️ SIN CAMBIOS: La API encontró {len(df_nuevo)} CVEs, pero TODOS ya estaban registrados previamente.")
                    else:
                        df_nuevo.to_excel(archivo_excel, index=False)
                        self.log(f"✅ ÉXITO: Archivo reconstruido con {len(df_nuevo)} registros.")
                else:
                    df_nuevo.to_excel(archivo_excel, index=False)
                    self.log(f"🆕 ÉXITO: Archivo creado con {len(df_nuevo)} registros.")
                    
        except PermissionError:
            self.log("❌ ERROR: El archivo 'cve_data.xlsx' está abierto en otro programa.")
        except Exception as e:
            self.log(f"❌ ERROR INESPERADO al procesar el Excel: {e}")
        finally:
            self.btn_cve.config(state=tk.NORMAL)
            self.btn_abort_cve.config(state=tk.DISABLED, text="🛑 Abortar Proceso")

    # ==========================================
    # TAB 2: THREAT INTEL (IoCs)
    # ==========================================
    def setup_ti_tab(self):
        frame = ttk.LabelFrame(self.tab_ti, text="Análisis de IoCs (AbuseIPDB & VirusTotal)", padding=15)
        frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame, text="Tipo de Análisis:").grid(row=0, column=0, sticky="w", pady=5)
        self.tipo_ioc = ttk.Combobox(frame, values=["IP", "URL", "File Hash"], state="readonly", width=12)
        self.tipo_ioc.current(0)
        self.tipo_ioc.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame, text="Entrada Manual:").grid(row=1, column=0, sticky="w", pady=5)
        self.entry_ioc = ttk.Entry(frame, width=35)
        self.entry_ioc.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

        ttk.Label(frame, text="O Cargar Archivo:").grid(row=2, column=0, sticky="w", pady=5)
        self.lbl_file = ttk.Label(frame, text="Ningún archivo...", foreground="gray")
        self.lbl_file.grid(row=2, column=1, sticky="w", padx=5)
        ttk.Button(frame, text="Examinar", command=self.seleccionar_archivo).grid(row=2, column=2, padx=5)

        btn_frame_ti = ttk.Frame(self.tab_ti)
        btn_frame_ti.pack(pady=10)

        self.btn_ti = ttk.Button(btn_frame_ti, text="▶ Ejecutar Análisis", command=self.lanzar_ti)
        self.btn_ti.grid(row=0, column=0, padx=5)
        
        self.btn_abort_ti = ttk.Button(btn_frame_ti, text="🛑 Abortar Proceso", command=self.abortar_ti, state=tk.DISABLED)
        self.btn_abort_ti.grid(row=0, column=1, padx=5)
        
        self.archivo_ioc = None

    def abortar_ti(self):
        self.log("⚠️ Señal de aborto enviada al motor de Threat Intel...")
        self.stop_event_ti.set()
        self.btn_abort_ti.config(state=tk.DISABLED, text="⏳ Cancelando...")

    def seleccionar_archivo(self):
        tipo_actual = self.tipo_ioc.get()
        if tipo_actual == "File Hash":
            tipos_permitidos = [("Todos los archivos", "*.*")]
        else:
            tipos_permitidos = [("Listas de datos Soportadas", "*.txt *.csv *.xlsx *.xls")]

        filepath = filedialog.askopenfilename(filetypes=tipos_permitidos)
        if filepath:
            self.archivo_ioc = filepath
            self.lbl_file.config(text=os.path.basename(filepath)[:30], foreground="blue")
            self.entry_ioc.delete(0, tk.END)

    def lanzar_ti(self):
        tipo = self.tipo_ioc.get()
        manual = self.entry_ioc.get().strip()
        iocs_a_procesar = []
        
        if manual:
            iocs_a_procesar.append(manual)
            self.archivo_ioc = None 
            self.lbl_file.config(text="Ningún archivo...", foreground="gray")
        elif self.archivo_ioc:
            ext = os.path.splitext(self.archivo_ioc)[1].lower()
            if tipo != "File Hash" and ext not in [".txt", ".csv", ".xlsx", ".xls"]:
                messagebox.showerror("Error", f"Has seleccionado '{tipo}', pero el archivo es un '{ext}'.")
                self.archivo_ioc = None
                self.lbl_file.config(text="Ningún archivo...", foreground="gray")
                return
            
            try:
                if tipo == "File Hash":
                    iocs_a_procesar.append(self.archivo_ioc)
                else:
                    iocs_a_procesar = leer_iocs(self.archivo_ioc)
            except Exception as e:
                self.log(f"❌ Error leyendo archivo: {e}")
                return
        else:
            messagebox.showwarning("Aviso", "Ingrese un IoC o seleccione un archivo válido.")
            return

        self.log(f"\n🚀 Iniciando Análisis TI ({tipo}) para {len(iocs_a_procesar)} elemento(s)...")
        self.btn_ti.config(state=tk.DISABLED)
        self.btn_abort_ti.config(state=tk.NORMAL, text="🛑 Abortar Proceso")
        self.stop_event_ti.clear()
        
        threading.Thread(target=self.hilo_ti, args=(tipo, iocs_a_procesar)).start()

    def hilo_ti(self, tipo, iocs):
        try:
            resultados = []
            vt_key = getattr(config, 'VT_API_KEY', '')
            abuse_key = getattr(config, 'ABUSEIPDB_API_KEY', '')

            for index, ioc in enumerate(iocs, start=1):
                if self.stop_event_ti.is_set():
                    self.log("🚫 [TI] Análisis cancelado exitosamente.")
                    break

                self.log(f"[*] Analizando {index}/{len(iocs)}: {ioc}")
                if tipo == "IP": res = check_ip(ioc, vt_key, abuse_key)
                elif tipo == "URL": res = check_url(ioc, vt_key)
                elif tipo == "File Hash": res = check_file_hash(ioc, vt_key)
                
                resultados.append(res)
                
                for _ in range(10): 
                    if self.stop_event_ti.is_set(): break
                    time.sleep(0.1)

            if resultados:
                excel_path, txt_path = generar_reporte_ti(resultados, tipo)
                if excel_path:
                    self.log(f"\n✅ Análisis Completado.")
                    self.log(f"   📊 Excel: {excel_path}")
                    self.log(f"   📄 TXT: {txt_path}")
        except Exception as e:
            self.log(f"❌ Error crítico en el hilo TI: {e}")
        finally:
            self.btn_ti.config(state=tk.NORMAL)
            self.btn_abort_ti.config(state=tk.DISABLED, text="🛑 Abortar Proceso")

    # ==========================================
    # TAB 3: TENABLE SC 
    # ==========================================
    def setup_tenable_tab(self):
        frame = ttk.LabelFrame(self.tab_tenable, text="Cruce de Inteligencia con Tenable Security Center", padding=15)
        frame.pack(fill="x", padx=10, pady=10)

        # Entrada del archivo de CVEs
        ttk.Label(frame, text="Archivo Excel/CSV origen (CVEs):").grid(row=0, column=0, sticky="w", pady=5)
        self.entry_tenable_in = ttk.Entry(frame, width=40)
        self.entry_tenable_in.insert(0, "cve_data.xlsx") 
        self.entry_tenable_in.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Examinar", command=self.seleccionar_archivo_tenable).grid(row=0, column=2, padx=5)

        # Salida del reporte maestro
        ttk.Label(frame, text="Nombre del reporte final (.csv):").grid(row=1, column=0, sticky="w", pady=5)
        self.entry_tenable_out = ttk.Entry(frame, width=40)
        self.entry_tenable_out.insert(0, "resumen_impacto_global.csv")
        self.entry_tenable_out.grid(row=1, column=1, padx=5, pady=5)

        # Botones de ejecución
        btn_frame_tenable = ttk.Frame(self.tab_tenable)
        btn_frame_tenable.pack(pady=15)
        
        self.btn_tenable = ttk.Button(btn_frame_tenable, text="▶ Evaluar Impacto en Tenable SC", command=self.lanzar_tenable)
        self.btn_tenable.grid(row=0, column=0, padx=5)

        self.btn_abort_tenable = ttk.Button(btn_frame_tenable, text="🛑 Abortar Proceso", command=self.abortar_tenable, state=tk.DISABLED)
        self.btn_abort_tenable.grid(row=0, column=1, padx=5)

    def abortar_tenable(self):
        self.log("⚠️ Señal de aborto enviada a Tenable SC... terminando conexión.")
        self.stop_event_tenable.set()
        self.btn_abort_tenable.config(state=tk.DISABLED, text="⏳ Cancelando...")

    def seleccionar_archivo_tenable(self):
        filepath = filedialog.askopenfilename(filetypes=[("Archivos Soportados", "*.xlsx *.xls *.csv")])
        if filepath:
            self.entry_tenable_in.delete(0, tk.END)
            self.entry_tenable_in.insert(0, filepath)

    def lanzar_tenable(self):
        archivo_in = self.entry_tenable_in.get().strip()
        archivo_out = self.entry_tenable_out.get().strip()

        if not os.path.exists(archivo_in):
            messagebox.showerror("Error", f"No se encontró el archivo de origen: {archivo_in}\nAsegúrate de ejecutar primero el Buscador CVE.")
            return

        self.log(f"\n🚀 Iniciando validación de impacto en Tenable SC...")
        self.log(f"[*] Preparando archivo: {archivo_in}")
        
        # Gestionar estados de los botones
        self.btn_tenable.config(state=tk.DISABLED)
        self.btn_abort_tenable.config(state=tk.NORMAL, text="🛑 Abortar Proceso")
        self.stop_event_tenable.clear()
        
        threading.Thread(target=self.hilo_tenable, args=(archivo_in, archivo_out)).start()

    def hilo_tenable(self, archivo_in, archivo_out):
        try:
            temp_csv = "temp_cves_tenable.csv"
            
            if archivo_in.endswith('.xlsx') or archivo_in.endswith('.xls'):
                df = pd.read_excel(archivo_in)
                if "CVE ID" in df.columns:
                    df[["CVE ID"]].to_csv(temp_csv, index=False, header=False)
                else:
                    self.log("❌ Error: El archivo Excel seleccionado no tiene la columna 'CVE ID'.")
                    return
            else:
                temp_csv = archivo_in 

            self.log("[*] Conectando a Tenable Security Center...")
            
            # Pasamos las nuevas variables de control al módulo
            exito, mensaje = analizar_impacto(
                archivo_entrada_cves=temp_csv, 
                archivo_resumen=archivo_out,
                log_callback=self.log,            # <--- Pasa el logger
                stop_event=self.stop_event_tenable # <--- Pasa el evento de parada
            )
            
            if exito:
                # Solo mostrar éxito si no fue abortado voluntariamente
                if not self.stop_event_tenable.is_set():
                    self.log(f"✅ Análisis de Tenable Completado.")
                    self.log(f"📄 {mensaje}")
                    messagebox.showinfo("Éxito Tenable SC", f"Análisis finalizado.\n\n{mensaje}")
            else:
                self.log(f"❌ Error o Aborto en Tenable SC: {mensaje}")
                if not self.stop_event_tenable.is_set():
                    messagebox.showerror("Error", f"Fallo en Tenable:\n{mensaje}")

            if temp_csv == "temp_cves_tenable.csv" and os.path.exists(temp_csv):
                os.remove(temp_csv)

        except Exception as e:
            self.log(f"❌ Error crítico en el hilo de Tenable SC: {e}")
        finally:
            self.btn_tenable.config(state=tk.NORMAL)
            self.btn_abort_tenable.config(state=tk.DISABLED, text="🛑 Abortar Proceso")

# ==========================================
# GESTIÓN DE SEÑALES (Ctrl+C en Terminal)
# ==========================================
def manejar_interrupcion(sig, frame):
    print("\n[!] Señal Ctrl+C detectada. Cerrando la aplicación de forma segura...")
    try:
        # Destruir la ventana root cierra el mainloop
        if root:
            root.quit()
            root.destroy()
    except:
        pass
    sys.exit(0)

# Para que el mainloop de Tkinter escuche el Handler de interrupción (Ctrl+C), 
# necesitamos que Python despierte periódicamente para procesar la cola de señales.
def monitorear_senales():
    root.after(200, monitorear_senales)

if __name__ == "__main__":
    # Registrar la señal SIGINT (Ctrl+C)
    signal.signal(signal.SIGINT, manejar_interrupcion)
    
    root = tk.Tk()
    app = RedTeamToolkitApp(root)
    
    # Iniciar ciclo de monitoreo de señales
    monitorear_senales()
    
    root.mainloop()