import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import pandas as pd
import os
import time
from datetime import datetime

import config
from core.nvd_scanner import ejecutar_escaneo_cve
from core.threat_intel import check_ip, check_url, check_file_hash
from utils.file_manager import leer_iocs, generar_reporte_ti

class RedTeamToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced CTI & Vulnerability Toolkit")
        self.root.geometry("820x720")
        
        self.stop_event_cve = threading.Event()
        self.stop_event_ti = threading.Event()
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.tab_cve = ttk.Frame(self.notebook)
        self.tab_ti = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_cve, text="🛡️ Buscador CVE (NVD)")
        self.notebook.add(self.tab_ti, text="🕵️ Threat Intel (IoCs)")
        
        self.setup_cve_tab()
        self.setup_ti_tab()
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
                
                # --- MEJORA: Limpiar espacios ocultos en los IDs para evitar falsos positivos ---
                df_nuevo["CVE ID"] = df_nuevo["CVE ID"].astype(str).str.strip()
                
                if os.path.exists(archivo_excel):
                    df_existente = pd.read_excel(archivo_excel)
                    
                    if not df_existente.empty and "CVE ID" in df_existente.columns:
                        # Limpiar espacios también en el archivo existente
                        df_existente["CVE ID"] = df_existente["CVE ID"].astype(str).str.strip()
                        
                        # Buscar diferencias
                        nuevos = df_nuevo[~df_nuevo["CVE ID"].isin(df_existente["CVE ID"])]
                        
                        if not nuevos.empty:
                            df_final = pd.concat([df_existente, nuevos], ignore_index=True)
                            df_final = df_final.drop_duplicates(subset=["CVE ID"], keep="last") # Doble seguridad
                            df_final.to_excel(archivo_excel, index=False)
                            # --- MEJORA: Log detallado ---
                            self.log(f"✅ ÉXITO: Se descargaron {len(df_nuevo)} CVEs. {len(nuevos)} eran nuevos y se agregaron al Excel.")
                        else:
                            # --- MEJORA: Explicación clara ---
                            self.log(f"ℹ️ SIN CAMBIOS: La API encontró {len(df_nuevo)} CVEs, pero TODOS ya estaban registrados previamente en tu Excel.")
                    else:
                        df_nuevo.to_excel(archivo_excel, index=False)
                        self.log(f"✅ ÉXITO: Archivo reconstruido con {len(df_nuevo)} registros.")
                else:
                    df_nuevo.to_excel(archivo_excel, index=False)
                    self.log(f"🆕 ÉXITO: Archivo creado con {len(df_nuevo)} registros.")
                    
        except PermissionError:
            self.log("❌ ERROR: El archivo 'cve_data.xlsx' está abierto en otro programa. Ciérrelo e intente de nuevo.")
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
                messagebox.showerror("Error", f"Has seleccionado '{tipo}', pero el archivo es un '{ext}'.\nPor favor, cambia el tipo de análisis a 'File Hash' o carga un archivo válido (.csv, .txt, .xlsx).")
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

if __name__ == "__main__":
    root = tk.Tk()
    app = RedTeamToolkitApp(root)
    root.mainloop()