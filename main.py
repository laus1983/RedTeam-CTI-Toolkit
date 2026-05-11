import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import pandas as pd
import os
import time
import signal
import sys
from datetime import datetime

# Importación de configuraciones y módulos core
import config
from core.nvd_scanner import ejecutar_escaneo_cve
from core.threat_intel import check_ip, check_url, check_file_hash
from core.tenable_sc_scanner import analizar_impacto
from core.trend_v1_scanner import descargar_eventos_ips, procesar_archivo_servidores, buscar_servidor_api
from utils.file_manager import leer_iocs, generar_reporte_ti

class RedTeamToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced RedTeam & CTI Toolkit - Mercantil")
        self.root.geometry("950x850")
        
        # Eventos de control para hilos (Abortar procesos de forma segura)
        self.stop_events = {
            "cve": threading.Event(),
            "ti": threading.Event(),
            "tenable": threading.Event(),
            "trend": threading.Event()
        }
        
        # Estructura de Pestañas
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.tab_cve = ttk.Frame(self.notebook)
        self.tab_ti = ttk.Frame(self.notebook)
        self.tab_tenable = ttk.Frame(self.notebook)
        self.tab_trend = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_cve, text="🛡️ Buscador CVE (NVD)")
        self.notebook.add(self.tab_ti, text="🕵️ Threat Intel (IoCs)")
        self.notebook.add(self.tab_tenable, text="🎯 Tenable SC")
        self.notebook.add(self.tab_trend, text="🔴 Trend Vision One")
        
        # Inicialización de interfaces
        self.setup_cve_tab()
        self.setup_ti_tab()
        self.setup_tenable_tab()
        self.setup_trend_tab()
        self.setup_console()

    # ==========================================
    # CONSOLA DE LOGS
    # ==========================================
    def setup_console(self):
        frame_consola = ttk.Frame(self.root)
        frame_consola.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        header_frame = ttk.Frame(frame_consola)
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="Consola de Estado y Progreso:").pack(side="left")
        ttk.Button(header_frame, text="🧹 Limpiar Consola", command=self.limpiar_consola).pack(side="right")
        
        self.log_area = scrolledtext.ScrolledText(frame_consola, height=12, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True, pady=(5, 0))

    def log(self, mensaje):
        self.log_area.insert(tk.END, f"{mensaje}\n")
        self.log_area.see(tk.END)

    def limpiar_consola(self):
        self.log_area.delete(1.0, tk.END)

    # ==========================================
    # PESTAÑA 1: NVD (Buscador CVE)
    # ==========================================
    def setup_cve_tab(self):
        frame = ttk.LabelFrame(self.tab_cve, text="Parámetros de Búsqueda NVD", padding=15)
        frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame, text="Inicio (DD/MM/AAAA):").grid(row=0, column=0, sticky="w")
        self.entry_cve_ini = ttk.Entry(frame, width=15); self.entry_cve_ini.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(frame, text="Fin (DD/MM/AAAA):").grid(row=0, column=2, sticky="w", padx=10)
        self.entry_cve_fin = ttk.Entry(frame, width=15); self.entry_cve_fin.grid(row=0, column=3, padx=5, pady=5)

        ttk.Label(frame, text="Palabra Clave:").grid(row=1, column=0, sticky="w")
        self.entry_kw = ttk.Entry(frame, width=15); self.entry_kw.grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(frame, text="Severidad:").grid(row=1, column=2, sticky="w", padx=10)
        self.combo_sev = ttk.Combobox(frame, values=["TODAS", "LOW", "MEDIUM", "HIGH", "CRITICAL"], state="readonly", width=12)
        self.combo_sev.current(0); self.combo_sev.grid(row=1, column=3, padx=5, pady=5)

        btn_frame = ttk.Frame(self.tab_cve)
        btn_frame.pack(pady=10)
        self.btn_cve = ttk.Button(btn_frame, text="▶ Extraer CVEs", command=self.lanzar_cve)
        self.btn_cve.grid(row=0, column=0, padx=5)
        self.btn_abort_cve = ttk.Button(btn_frame, text="🛑 Abortar", command=lambda: self.stop_events["cve"].set(), state=tk.DISABLED)
        self.btn_abort_cve.grid(row=0, column=1, padx=5)

    def lanzar_cve(self):
        params = {"resultsPerPage": 2000, "startIndex": 0}
        try:
            if self.entry_cve_ini.get(): params["pubStartDate"] = datetime.strptime(self.entry_cve_ini.get(), "%d/%m/%Y").strftime("%Y-%m-%dT00:00:00.000Z")
            if self.entry_cve_fin.get(): params["pubEndDate"] = datetime.strptime(self.entry_cve_fin.get(), "%d/%m/%Y").strftime("%Y-%m-%dT23:59:59.000Z")
        except: messagebox.showerror("Error", "Formato de fecha inválido."); return

        if self.entry_kw.get(): params["keywordSearch"] = self.entry_kw.get()
        if self.combo_sev.get() != "TODAS": params["cvssV3Severity"] = self.combo_sev.get()

        self.log("\n🚀 Iniciando búsqueda NVD..."); self.stop_events["cve"].clear()
        self.btn_cve.config(state=tk.DISABLED); self.btn_abort_cve.config(state=tk.NORMAL)
        threading.Thread(target=self.hilo_cve, args=(params,)).start()

    def hilo_cve(self, params):
        headers = {"apiKey": getattr(config, 'NVD_API_KEY', '')}
        cve_list = ejecutar_escaneo_cve(params, headers, self.log, self.stop_events["cve"])
        if cve_list and not self.stop_events["cve"].is_set():
            pd.DataFrame(cve_list).to_excel("cve_data.xlsx", index=False)
            self.log("✅ Datos guardados en cve_data.xlsx")
        self.btn_cve.config(state=tk.NORMAL); self.btn_abort_cve.config(state=tk.DISABLED)

    # ==========================================
    # PESTAÑA 2: THREAT INTEL (IoCs)
    # ==========================================
    def setup_ti_tab(self):
        frame = ttk.LabelFrame(self.tab_ti, text="Análisis de IoCs (AbuseIPDB & VirusTotal)", padding=15)
        frame.pack(fill="x", padx=10, pady=10)

        self.tipo_ioc = ttk.Combobox(frame, values=["IP", "URL", "File Hash"], state="readonly", width=12)
        self.tipo_ioc.current(0); self.tipo_ioc.grid(row=0, column=0, padx=5)
        
        self.entry_ioc = ttk.Entry(frame, width=35); self.entry_ioc.grid(row=0, column=1, padx=5)
        ttk.Button(frame, text="📂 Cargar Archivo", command=self.cargar_ti_file).grid(row=0, column=2, padx=5)

        btn_frame = ttk.Frame(self.tab_ti)
        btn_frame.pack(pady=10)
        self.btn_ti = ttk.Button(btn_frame, text="▶ Ejecutar Análisis", command=self.lanzar_ti)
        self.btn_ti.grid(row=0, column=0, padx=5)
        self.btn_abort_ti = ttk.Button(btn_frame, text="🛑 Abortar", command=lambda: self.stop_events["ti"].set(), state=tk.DISABLED)
        self.btn_abort_ti.grid(row=0, column=1, padx=5)
        self.archivo_ti = None

    def cargar_ti_file(self):
        self.archivo_ti = filedialog.askopenfilename()
        if self.archivo_ti: self.log(f"[*] Archivo cargado para TI: {os.path.basename(self.archivo_ti)}")

    def lanzar_ti(self):
        tipo = self.tipo_ioc.get()
        iocs = [self.entry_ioc.get().strip()] if self.entry_ioc.get() else (leer_iocs(self.archivo_ti) if self.archivo_ti else [])
        if not iocs: messagebox.showwarning("Aviso", "Ingrese un IoC o cargue un archivo."); return
        
        self.log(f"\n🚀 Analizando {len(iocs)} IoCs..."); self.stop_events["ti"].clear()
        self.btn_ti.config(state=tk.DISABLED); self.btn_abort_ti.config(state=tk.NORMAL)
        threading.Thread(target=self.hilo_ti, args=(tipo, iocs)).start()

    def hilo_ti(self, tipo, iocs):
        resultados = []
        vt_key = getattr(config, 'VT_API_KEY', '')
        abuse_key = getattr(config, 'ABUSEIPDB_API_KEY', '')
        for i, ioc in enumerate(iocs, 1):
            if self.stop_events["ti"].is_set(): break
            self.log(f"[*] ({i}/{len(iocs)}) Escaneando: {ioc}")
            if tipo == "IP": resultados.append(check_ip(ioc, vt_key, abuse_key))
            elif tipo == "URL": resultados.append(check_url(ioc, vt_key))
            elif tipo == "File Hash": resultados.append(check_file_hash(ioc, vt_key))
        
        if resultados: generar_reporte_ti(resultados, tipo); self.log("✅ Análisis de TI completo.")
        self.btn_ti.config(state=tk.NORMAL); self.btn_abort_ti.config(state=tk.DISABLED)

    # ==========================================
    # PESTAÑA 3: TENABLE SC
    # ==========================================
    def setup_tenable_tab(self):
        frame = ttk.LabelFrame(self.tab_tenable, text="Impacto en Tenable Security Center", padding=15)
        frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame, text="Origen de CVEs:").grid(row=0, column=0)
        self.ent_ten_in = ttk.Entry(frame, width=30); self.ent_ten_in.insert(0, "cve_data.xlsx"); self.ent_ten_in.grid(row=0, column=1, padx=5)
        
        btn_frame = ttk.Frame(self.tab_tenable)
        btn_frame.pack(pady=10)
        self.btn_tenable = ttk.Button(btn_frame, text="▶ Evaluar Impacto Interno", command=self.lanzar_tenable)
        self.btn_tenable.grid(row=0, column=0, padx=5)
        self.btn_abort_ten = ttk.Button(btn_frame, text="🛑 Abortar", command=lambda: self.stop_events["tenable"].set(), state=tk.DISABLED)
        self.btn_abort_ten.grid(row=0, column=1, padx=5)

    def lanzar_tenable(self):
        archivo_in = self.ent_ten_in.get()
        if not os.path.exists(archivo_in): messagebox.showerror("Error", "No existe cve_data.xlsx"); return
        self.log("\n🚀 Conectando a Tenable SC..."); self.stop_events["tenable"].clear()
        self.btn_tenable.config(state=tk.DISABLED); self.btn_abort_ten.config(state=tk.NORMAL)
        threading.Thread(target=self.hilo_tenable, args=(archivo_in,)).start()

    def hilo_tenable(self, archivo_in):
        try:
            temp_csv = "temp_tenable.csv"
            pd.read_excel(archivo_in)[["CVE ID"]].to_csv(temp_csv, index=False, header=False)
            exito, msg = analizar_impacto(temp_csv, log_callback=self.log, stop_event=self.stop_events["tenable"])
            if os.path.exists(temp_csv): os.remove(temp_csv)
            self.log(f"🏁 Resultado: {msg}")
        finally:
            self.btn_tenable.config(state=tk.NORMAL); self.btn_abort_ten.config(state=tk.DISABLED)

    # ==========================================
    # PESTAÑA 4: TREND VISION ONE
    # ==========================================
    def setup_trend_tab(self):
        f1 = ttk.LabelFrame(self.tab_trend, text="Métricas IPS & Endpoint Security", padding=15)
        f1.pack(fill="x", padx=10, pady=5)

        ttk.Label(f1, text="Inicio (DD/MM/AAAA):").grid(row=0, column=0)
        self.t_ini = ttk.Entry(f1, width=15); self.t_ini.insert(0, "01/04/2026"); self.t_ini.grid(row=0, column=1, padx=5)
        ttk.Label(f1, text="Fin (DD/MM/AAAA):").grid(row=0, column=2, padx=10)
        self.t_fin = ttk.Entry(f1, width=15); self.t_fin.insert(0, datetime.now().strftime("%d/%m/%Y")); self.t_fin.grid(row=0, column=3, padx=5)

        ttk.Button(f1, text="📥 Descargar Métricas IPS", command=self.lanzar_trend_ips).grid(row=1, column=0, columnspan=4, pady=10)

        f2 = ttk.LabelFrame(self.tab_trend, text="Inventario de Activos (Validación de Servidores)", padding=15)
        f2.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(f2, text="IP o Hostname:").grid(row=0, column=0)
        self.ent_trend_srv = ttk.Entry(f2, width=30); self.ent_trend_srv.grid(row=0, column=1, padx=5)
        ttk.Button(f2, text="🔍 Buscar", command=self.buscar_trend_manual).grid(row=0, column=2, padx=5)
        
        ttk.Label(f2, text="Carga Masiva:").grid(row=1, column=0, pady=10)
        ttk.Button(f2, text="📂 Seleccionar Archivo", command=self.validar_trend_masivo).grid(row=1, column=1, sticky="w")

        self.btn_abort_trend = ttk.Button(self.tab_trend, text="🛑 ABORTAR PROCESO TREND", command=lambda: self.stop_events["trend"].set(), state=tk.DISABLED)
        self.btn_abort_trend.pack(pady=15)

    def lanzar_trend_ips(self):
        try:
            # Conversión de formato dd/mm/aaaa a ISO para la API
            ini_iso = datetime.strptime(self.t_ini.get(), "%d/%m/%Y").strftime("%Y-%m-%dT00:00:00Z")
            fin_iso = datetime.strptime(self.t_fin.get(), "%d/%m/%Y").strftime("%Y-%m-%dT23:59:59Z")
        except: messagebox.showerror("Error", "Formato de fecha inválido."); return

        self.log("\n🚀 Descargando métricas IPS de Trend Micro..."); self.stop_events["trend"].clear()
        self.btn_abort_trend.config(state=tk.NORMAL)
        threading.Thread(target=self.hilo_trend_ips, args=(ini_iso, fin_iso)).start()

    def hilo_trend_ips(self, ini, fin):
        exito, msg = descargar_eventos_ips(ini, fin, log_callback=self.log, stop_event=self.stop_events["trend"])
        self.procesar_fin_trend(exito, msg)

    def buscar_trend_manual(self):
        item = self.ent_trend_srv.get().strip()
        if not item: return
        res = buscar_servidor_api(item)
        if res == "EXPIRED": messagebox.showwarning("Rotación Requerida", "Token expirado. Actualice el .env.")
        elif res: s = res[0]; messagebox.showinfo("Info", f"Host: {s.get('endpointName')}\nIP: {s.get('ip')}\nSO: {s.get('osName')}")
        else: messagebox.showinfo("Info", "Servidor no encontrado.")

    def validar_trend_masivo(self):
        path = filedialog.askopenfilename()
        if not path: return
        self.log(f"\n🚀 Iniciando validación masiva: {os.path.basename(path)}")
        self.stop_events["trend"].clear(); self.btn_abort_trend.config(state=tk.NORMAL)
        threading.Thread(target=self.hilo_trend_file, args=(path,)).start()

    def hilo_trend_file(self, path):
        exito, msg = procesar_archivo_servidores(path, log_callback=self.log, stop_event=self.stop_events["trend"])
        self.procesar_fin_trend(exito, msg)

    def procesar_fin_trend(self, exito, msg):
        self.btn_abort_trend.config(state=tk.DISABLED)
        if "TOKEN_EXPIRED" in msg: self.root.after(0, lambda: messagebox.showwarning("Aviso", msg))
        else: self.root.after(0, lambda: messagebox.showinfo("Resultado", msg))

# ==========================================
# GESTIÓN DE CIERRE SEGURO (CTRL+C)
# ==========================================
def manejar_interrupcion(sig, frame):
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, manejar_interrupcion)
    root = tk.Tk()
    app = RedTeamToolkitApp(root)
    def keep_alive(): root.after(500, keep_alive)
    root.after(500, keep_alive)
    root.mainloop()