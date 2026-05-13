import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
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

# ==========================================
# CONFIGURACIÓN ESTÉTICA CORPORATIVA
# ==========================================
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

class RedTeamToolkitApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Cambio de nombre (Eliminando "Mercantil")
        self.title("Advanced RedTeam & CTI Toolkit")
        self.geometry("1100x850")
        self.minsize(950, 700)
        
        # Eventos de control para hilos (Abortar procesos de forma segura)
        self.stop_events = {
            "cve": threading.Event(),
            "ti": threading.Event(),
            "tenable": threading.Event(),
            "trend": threading.Event()
        }
        
        # Configuración de la cuadrícula principal
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        
        # ==========================================
        # PANEL LATERAL (SIDEBAR) - AZUL NAVAL
        # ==========================================
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#1A2A3A")
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(6, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar, text="REDTEAM\nTOOLKIT", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 40))

        # Botones de navegación
        self.btn_nav_cve = ctk.CTkButton(self.sidebar, text="🛡️ Buscador CVE (NVD)", command=lambda: self.select_tab("cve"), fg_color="transparent", border_width=1, anchor="w")
        self.btn_nav_cve.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.btn_nav_ti = ctk.CTkButton(self.sidebar, text="🕵️ Threat Intel (IoCs)", command=lambda: self.select_tab("ti"), fg_color="transparent", border_width=1, anchor="w")
        self.btn_nav_ti.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_nav_tenable = ctk.CTkButton(self.sidebar, text="🎯 Tenable SC", command=lambda: self.select_tab("tenable"), fg_color="transparent", border_width=1, anchor="w")
        self.btn_nav_tenable.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        self.btn_nav_trend = ctk.CTkButton(self.sidebar, text="🔴 Trend Vision One", command=lambda: self.select_tab("trend"), fg_color="transparent", border_width=1, anchor="w")
        self.btn_nav_trend.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        
        # ==========================================
        # ÁREA PRINCIPAL
        # ==========================================
        self.main_content = ctk.CTkFrame(self, fg_color="transparent")
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_content.grid_rowconfigure(0, weight=1) # Espacio para la pestaña activa
        self.main_content.grid_rowconfigure(1, weight=0) # Espacio para la consola

        # Contenedor de las pestañas (se apilan una sobre otra)
        self.tabs_container = ctk.CTkFrame(self.main_content, fg_color="transparent")
        self.tabs_container.grid(row=0, column=0, sticky="nsew")
        self.tabs_container.grid_rowconfigure(0, weight=1)
        self.tabs_container.grid_columnconfigure(0, weight=1)

        # Creación de los marcos para cada pestaña
        self.tab_cve = ctk.CTkFrame(self.tabs_container, fg_color="transparent")
        self.tab_ti = ctk.CTkFrame(self.tabs_container, fg_color="transparent")
        self.tab_tenable = ctk.CTkFrame(self.tabs_container, fg_color="transparent")
        self.tab_trend = ctk.CTkFrame(self.tabs_container, fg_color="transparent")

        for frame in (self.tab_cve, self.tab_ti, self.tab_tenable, self.tab_trend):
            frame.grid(row=0, column=0, sticky="nsew")

        # Inicialización de interfaces
        self.setup_cve_tab()
        self.setup_ti_tab()
        self.setup_tenable_tab()
        self.setup_trend_tab()
        self.setup_console()
        
        # Cargar pestaña por defecto
        self.select_tab("cve")

    # ==========================================
    # MANEJO DE PESTAÑAS Y NAVEGACIÓN
    # ==========================================
    def select_tab(self, tab_name):
        # Resetear colores de botones
        for btn in [self.btn_nav_cve, self.btn_nav_ti, self.btn_nav_tenable, self.btn_nav_trend]:
            btn.configure(fg_color="transparent")

        # Elevar la pestaña seleccionada y pintar el botón activo
        if tab_name == "cve":
            self.tab_cve.tkraise()
            self.btn_nav_cve.configure(fg_color="#1f538d")
        elif tab_name == "ti":
            self.tab_ti.tkraise()
            self.btn_nav_ti.configure(fg_color="#1f538d")
        elif tab_name == "tenable":
            self.tab_tenable.tkraise()
            self.btn_nav_tenable.configure(fg_color="#1f538d")
        elif tab_name == "trend":
            self.tab_trend.tkraise()
            self.btn_nav_trend.configure(fg_color="#1f538d")

    # ==========================================
    # CONSOLA DE LOGS (DISEÑO HACKER/TERMINAL)
    # ==========================================
    def setup_console(self):
        frame_consola = ctk.CTkFrame(self.main_content, fg_color="transparent")
        frame_consola.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        
        header_frame = ctk.CTkFrame(frame_consola, fg_color="transparent")
        header_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(header_frame, text="Consola de Estado y Progreso:", font=ctk.CTkFont(weight="bold")).pack(side="left")
        ctk.CTkButton(header_frame, text="🧹 Limpiar Consola", command=self.limpiar_consola, width=120, fg_color="#555555", hover_color="#333333").pack(side="right")
        
        self.log_area = ctk.CTkTextbox(frame_consola, height=220, fg_color="#1e1e1e", text_color="#00ff00", font=("Consolas", 12))
        self.log_area.pack(fill="both", expand=True)

    def log(self, mensaje):
        self.log_area.insert("end", f"{mensaje}\n")
        self.log_area.see("end")

    def limpiar_consola(self):
        self.log_area.delete("1.0", "end")

    # ==========================================
    # PESTAÑA 1: NVD (Buscador CVE) - TRADUCCIÓN EXACTA
    # ==========================================
    def setup_cve_tab(self):
        ctk.CTkLabel(self.tab_cve, text="🛡️ Buscador CVE (NVD)", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 15))

        frame = ctk.CTkFrame(self.tab_cve)
        frame.pack(fill="x", pady=5)

        ctk.CTkLabel(frame, text="Inicio (DD/MM/AAAA):").grid(row=0, column=0, sticky="w", padx=10, pady=10)
        self.entry_cve_ini = ctk.CTkEntry(frame, width=140)
        self.entry_cve_ini.grid(row=0, column=1, padx=5, pady=10)
        
        ctk.CTkLabel(frame, text="Fin (DD/MM/AAAA):").grid(row=0, column=2, sticky="w", padx=10, pady=10)
        self.entry_cve_fin = ctk.CTkEntry(frame, width=140)
        self.entry_cve_fin.grid(row=0, column=3, padx=5, pady=10)

        ctk.CTkLabel(frame, text="Palabra Clave:").grid(row=1, column=0, sticky="w", padx=10, pady=10)
        self.entry_kw = ctk.CTkEntry(frame, width=140)
        self.entry_kw.grid(row=1, column=1, padx=5, pady=10)
        
        ctk.CTkLabel(frame, text="Severidad:").grid(row=1, column=2, sticky="w", padx=10, pady=10)
        self.combo_sev = ctk.CTkComboBox(frame, values=["TODAS", "LOW", "MEDIUM", "HIGH", "CRITICAL"], width=140, state="readonly")
        self.combo_sev.set("TODAS")
        self.combo_sev.grid(row=1, column=3, padx=5, pady=10)

        btn_frame = ctk.CTkFrame(self.tab_cve, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        self.btn_cve = ctk.CTkButton(btn_frame, text="▶ Extraer CVEs", command=self.lanzar_cve, fg_color="#1f538d")
        self.btn_cve.grid(row=0, column=0, padx=10)
        
        self.btn_abort_cve = ctk.CTkButton(btn_frame, text="🛑 Abortar", command=lambda: self.stop_events["cve"].set(), state="disabled", fg_color="#A71D2A", hover_color="#801520")
        self.btn_abort_cve.grid(row=0, column=1, padx=10)

    def lanzar_cve(self):
        params = {"resultsPerPage": 2000, "startIndex": 0}
        try:
            if self.entry_cve_ini.get(): params["pubStartDate"] = datetime.strptime(self.entry_cve_ini.get(), "%d/%m/%Y").strftime("%Y-%m-%dT00:00:00.000Z")
            if self.entry_cve_fin.get(): params["pubEndDate"] = datetime.strptime(self.entry_cve_fin.get(), "%d/%m/%Y").strftime("%Y-%m-%dT23:59:59.000Z")
        except: 
            messagebox.showerror("Error", "Formato de fecha inválido.")
            return

        if self.entry_kw.get(): params["keywordSearch"] = self.entry_kw.get()
        if self.combo_sev.get() != "TODAS": params["cvssV3Severity"] = self.combo_sev.get()

        self.log("\n🚀 Iniciando búsqueda NVD..."); self.stop_events["cve"].clear()
        self.btn_cve.configure(state="disabled")
        self.btn_abort_cve.configure(state="normal")
        threading.Thread(target=self.hilo_cve, args=(params,)).start()

    def hilo_cve(self, params):
        headers = {"apiKey": getattr(config, 'NVD_API_KEY', '')}
        cve_list = ejecutar_escaneo_cve(params, headers, self.log, self.stop_events["cve"])
        if cve_list and not self.stop_events["cve"].is_set():
            pd.DataFrame(cve_list).to_excel("cve_data.xlsx", index=False)
            self.log("✅ Datos guardados en cve_data.xlsx")
        self.btn_cve.configure(state="normal")
        self.btn_abort_cve.configure(state="disabled")

    # ==========================================
    # PESTAÑA 2: THREAT INTEL (IoCs) - TRADUCCIÓN EXACTA
    # ==========================================
    def setup_ti_tab(self):
        ctk.CTkLabel(self.tab_ti, text="🕵️ Threat Intel (IoCs)", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 15))

        frame = ctk.CTkFrame(self.tab_ti)
        frame.pack(fill="x", pady=5)

        self.tipo_ioc = ctk.CTkComboBox(frame, values=["IP", "URL", "File Hash"], width=120, state="readonly")
        self.tipo_ioc.set("IP")
        self.tipo_ioc.grid(row=0, column=0, padx=15, pady=15)
        
        self.entry_ioc = ctk.CTkEntry(frame, width=350, placeholder_text="Ingrese IoC...")
        self.entry_ioc.grid(row=0, column=1, padx=5, pady=15)
        
        ctk.CTkButton(frame, text="📂 Cargar Archivo", command=self.cargar_ti_file, width=120).grid(row=0, column=2, padx=15, pady=15)

        btn_frame = ctk.CTkFrame(self.tab_ti, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        self.btn_ti = ctk.CTkButton(btn_frame, text="▶ Ejecutar Análisis", command=self.lanzar_ti, fg_color="#1f538d")
        self.btn_ti.grid(row=0, column=0, padx=10)
        
        self.btn_abort_ti = ctk.CTkButton(btn_frame, text="🛑 Abortar", command=lambda: self.stop_events["ti"].set(), state="disabled", fg_color="#A71D2A", hover_color="#801520")
        self.btn_abort_ti.grid(row=0, column=1, padx=10)
        self.archivo_ti = None

    def cargar_ti_file(self):
        self.archivo_ti = filedialog.askopenfilename()
        if self.archivo_ti: self.log(f"[*] Archivo cargado para TI: {os.path.basename(self.archivo_ti)}")

    def lanzar_ti(self):
        tipo = self.tipo_ioc.get()
        iocs = [self.entry_ioc.get().strip()] if self.entry_ioc.get() else (leer_iocs(self.archivo_ti) if self.archivo_ti else [])
        if not iocs: 
            messagebox.showwarning("Aviso", "Ingrese un IoC o cargue un archivo.")
            return
        
        self.log(f"\n🚀 Analizando {len(iocs)} IoCs..."); self.stop_events["ti"].clear()
        self.btn_ti.configure(state="disabled")
        self.btn_abort_ti.configure(state="normal")
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
        
        if resultados: 
            generar_reporte_ti(resultados, tipo)
            self.log("✅ Análisis de TI completo.")
            
        self.btn_ti.configure(state="normal")
        self.btn_abort_ti.configure(state="disabled")

    # ==========================================
    # PESTAÑA 3: TENABLE SC - TRADUCCIÓN EXACTA
    # ==========================================
    def setup_tenable_tab(self):
        ctk.CTkLabel(self.tab_tenable, text="🎯 Tenable SC", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 15))

        frame = ctk.CTkFrame(self.tab_tenable)
        frame.pack(fill="x", pady=5)

        ctk.CTkLabel(frame, text="Origen de CVEs:").grid(row=0, column=0, padx=15, pady=20)
        self.ent_ten_in = ctk.CTkEntry(frame, width=300)
        self.ent_ten_in.insert(0, "cve_data.xlsx")
        self.ent_ten_in.grid(row=0, column=1, padx=5, pady=20)
        
        btn_frame = ctk.CTkFrame(self.tab_tenable, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        self.btn_tenable = ctk.CTkButton(btn_frame, text="▶ Evaluar Impacto Interno", command=self.lanzar_tenable, fg_color="#1f538d")
        self.btn_tenable.grid(row=0, column=0, padx=10)
        
        self.btn_abort_ten = ctk.CTkButton(btn_frame, text="🛑 Abortar", command=lambda: self.stop_events["tenable"].set(), state="disabled", fg_color="#A71D2A", hover_color="#801520")
        self.btn_abort_ten.grid(row=0, column=1, padx=10)

    def lanzar_tenable(self):
        archivo_in = self.ent_ten_in.get()
        if not os.path.exists(archivo_in): 
            messagebox.showerror("Error", "No existe cve_data.xlsx")
            return
            
        self.log("\n🚀 Conectando a Tenable SC..."); self.stop_events["tenable"].clear()
        self.btn_tenable.configure(state="disabled")
        self.btn_abort_ten.configure(state="normal")
        threading.Thread(target=self.hilo_tenable, args=(archivo_in,)).start()

    def hilo_tenable(self, archivo_in):
        try:
            temp_csv = "temp_tenable.csv"
            pd.read_excel(archivo_in)[["CVE ID"]].to_csv(temp_csv, index=False, header=False)
            exito, msg = analizar_impacto(temp_csv, log_callback=self.log, stop_event=self.stop_events["tenable"])
            if os.path.exists(temp_csv): os.remove(temp_csv)
            self.log(f"🏁 Resultado: {msg}")
        finally:
            self.btn_tenable.configure(state="normal")
            self.btn_abort_ten.configure(state="disabled")

    # ==========================================
    # PESTAÑA 4: TREND VISION ONE - TRADUCCIÓN EXACTA
    # ==========================================
    def setup_trend_tab(self):
        ctk.CTkLabel(self.tab_trend, text="🔴 Trend Vision One", font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 15))

        f1 = ctk.CTkFrame(self.tab_trend)
        f1.pack(fill="x", pady=10)

        ctk.CTkLabel(f1, text="Métricas IPS", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, columnspan=4, pady=(10,5), sticky="w", padx=10)
        
        ctk.CTkLabel(f1, text="Inicio (DD/MM/AAAA):").grid(row=1, column=0, padx=10, pady=10)
        self.t_ini = ctk.CTkEntry(f1, width=120)
        self.t_ini.insert(0, "01/04/2026")
        self.t_ini.grid(row=1, column=1, padx=5, pady=10)
        
        ctk.CTkLabel(f1, text="Fin (DD/MM/AAAA):").grid(row=1, column=2, padx=10, pady=10)
        self.t_fin = ctk.CTkEntry(f1, width=120)
        self.t_fin.insert(0, datetime.now().strftime("%d/%m/%Y"))
        self.t_fin.grid(row=1, column=3, padx=5, pady=10)

        ctk.CTkButton(f1, text="📥 Descargar Métricas IPS", command=self.lanzar_trend_ips, fg_color="#1f538d").grid(row=2, column=0, columnspan=4, pady=15)

        f2 = ctk.CTkFrame(self.tab_trend)
        f2.pack(fill="x", pady=10)
        
        ctk.CTkLabel(f2, text="Inventario de Activos (Validación de Servidores)", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, columnspan=3, pady=(10,5), sticky="w", padx=10)
        
        ctk.CTkLabel(f2, text="IP o Hostname:").grid(row=1, column=0, padx=10, pady=10)
        self.ent_trend_srv = ctk.CTkEntry(f2, width=280)
        self.ent_trend_srv.grid(row=1, column=1, padx=5, pady=10)
        ctk.CTkButton(f2, text="🔍 Buscar", command=self.buscar_trend_manual, width=100).grid(row=1, column=2, padx=15, pady=10)
        
        ctk.CTkLabel(f2, text="Carga Masiva:").grid(row=2, column=0, padx=10, pady=15)
        ctk.CTkButton(f2, text="📂 Seleccionar Archivo", command=self.validar_trend_masivo, fg_color="#28a745", hover_color="#218838").grid(row=2, column=1, sticky="w", padx=5, pady=15)

        self.btn_abort_trend = ctk.CTkButton(self.tab_trend, text="🛑 ABORTAR PROCESO TREND", command=lambda: self.stop_events["trend"].set(), state="disabled", fg_color="#A71D2A", hover_color="#801520")
        self.btn_abort_trend.pack(pady=20)

    def lanzar_trend_ips(self):
        try:
            ini_iso = datetime.strptime(self.t_ini.get(), "%d/%m/%Y").strftime("%Y-%m-%dT00:00:00Z")
            fin_iso = datetime.strptime(self.t_fin.get(), "%d/%m/%Y").strftime("%Y-%m-%dT23:59:59Z")
        except: 
            messagebox.showerror("Error", "Formato de fecha inválido.")
            return

        self.log("\n🚀 Descargando métricas IPS de Trend Micro..."); self.stop_events["trend"].clear()
        self.btn_abort_trend.configure(state="normal")
        threading.Thread(target=self.hilo_trend_ips, args=(ini_iso, fin_iso)).start()

    def hilo_trend_ips(self, ini, fin):
        exito, msg = descargar_eventos_ips(ini, fin, log_callback=self.log, stop_event=self.stop_events["trend"])
        self.procesar_fin_trend(exito, msg)

    def buscar_trend_manual(self):
        item = self.ent_trend_srv.get().strip()
        if not item: return
        res = buscar_servidor_api(item)
        if res == "EXPIRED": messagebox.showwarning("Rotación Requerida", "Token expirado. Actualice el .env.")
        elif res: 
            s = res[0]
            messagebox.showinfo("Info", f"Host: {s.get('endpointName', s.get('Hostname'))}\nIP: {s.get('ip', s.get('IP'))}\nSO: {s.get('osName', s.get('SO'))}")
        else: 
            messagebox.showinfo("Info", "Servidor no encontrado.")

    def validar_trend_masivo(self):
        path = filedialog.askopenfilename()
        if not path: return
        self.log(f"\n🚀 Iniciando validación masiva: {os.path.basename(path)}")
        self.stop_events["trend"].clear()
        self.btn_abort_trend.configure(state="normal")
        threading.Thread(target=self.hilo_trend_file, args=(path,)).start()

    def hilo_trend_file(self, path):
        exito, msg = procesar_archivo_servidores(path, log_callback=self.log, stop_event=self.stop_events["trend"])
        self.procesar_fin_trend(exito, msg)

    def procesar_fin_trend(self, exito, msg):
        self.btn_abort_trend.configure(state="disabled")
        if "TOKEN_EXPIRED" in msg: self.after(0, lambda: messagebox.showwarning("Aviso", msg))
        else: self.after(0, lambda: messagebox.showinfo("Resultado", msg))

# ==========================================
# GESTIÓN DE CIERRE SEGURO (CTRL+C)
# ==========================================
def manejar_interrupcion(sig, frame):
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, manejar_interrupcion)
    app = RedTeamToolkitApp()
    def keep_alive(): app.after(500, keep_alive)
    app.after(500, keep_alive)
    app.mainloop()