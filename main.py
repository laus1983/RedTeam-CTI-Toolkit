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
        self.root.geometry("850x800")
        
        # Eventos de control para hilos (Abortar procesos)
        self.stop_event_cve = threading.Event()
        self.stop_event_ti = threading.Event()
        self.stop_event_tenable = threading.Event()
        self.stop_event_trend = threading.Event()
        
        # Estructura de Pestañas (Notebook)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.tab_cve = ttk.Frame(self.notebook)
        self.tab_ti = ttk.Frame(self.notebook)
        self.tab_tenable = ttk.Frame(self.notebook)
        self.tab_trend = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab_cve, text="🛡️ Buscador CVE")
        self.notebook.add(self.tab_ti, text="🕵️ Threat Intel")
        self.notebook.add(self.tab_tenable, text="🎯 Tenable SC")
        self.notebook.add(self.tab_trend, text="🔴 Trend Vision One")
        
        # Inicialización de cada pestaña
        self.setup_cve_tab()
        self.setup_ti_tab()
        self.setup_tenable_tab()
        self.setup_trend_tab()
        
        # Consola inferior
        self.setup_console()

    # ==========================================
    # CONSOLA Y LOGS
    # ==========================================
    def setup_console(self):
        frame_consola = ttk.Frame(self.root)
        frame_consola.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        header_frame = ttk.Frame(frame_consola)
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text="Consola de Estado y Progreso:").pack(side="left")
        ttk.Button(header_frame, text="🧹 Limpiar", command=self.limpiar_consola).pack(side="right")
        
        self.log_area = scrolledtext.ScrolledText(frame_consola, height=10, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True, pady=(5, 0))

    def log(self, mensaje):
        self.log_area.insert(tk.END, mensaje + "\n")
        self.log_area.see(tk.END)

    def limpiar_consola(self):
        self.log_area.delete(1.0, tk.END)

    # ==========================================
    # PESTAÑA: TREND VISION ONE (NUEVO)
    # ==========================================
    def setup_trend_tab(self):
        # --- SECCIÓN 1: MÉTRICAS IPS ---
        f_ips = ttk.LabelFrame(self.tab_trend, text="Métricas IPS (Endpoint Security)", padding=10)
        f_ips.pack(fill="x", padx=10, pady=5)

        ttk.Label(f_ips, text="Inicio (ISO):").grid(row=0, column=0, sticky="w")
        self.ent_trend_ini = ttk.Entry(f_ips, width=25)
        self.ent_trend_ini.insert(0, "2026-04-01T00:00:00Z")
        self.ent_trend_ini.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(f_ips, text="Fin (ISO):").grid(row=0, column=2, sticky="w")
        self.ent_trend_fin = ttk.Entry(f_ips, width=25)
        self.ent_trend_fin.insert(0, datetime.now().strftime("%Y-%m-%dT23:59:59Z"))
        self.ent_trend_fin.grid(row=0, column=3, padx=5, pady=5)

        ttk.Button(f_ips, text="📥 Descargar y Actualizar Excel", command=self.lanzar_trend_ips).grid(row=1, column=0, columnspan=4, pady=10)

        # --- SECCIÓN 2: VALIDACIÓN DE SERVIDORES ---
        f_srv = ttk.LabelFrame(self.tab_trend, text="Validación de Servidores (Activos)", padding=10)
        f_srv.pack(fill="x", padx=10, pady=5)

        ttk.Label(f_srv, text="IP o Hostname:").grid(row=0, column=0, sticky="w")
        self.ent_srv_manual = ttk.Entry(f_srv, width=30)
        self.ent_srv_manual.grid(row=0, column=1, padx=5, pady=10)
        ttk.Button(f_srv, text="🔍 Buscar", command=self.buscar_trend_manual).grid(row=0, column=2)

        ttk.Label(f_srv, text="Validación Masiva:").grid(row=1, column=0, sticky="w")
        ttk.Button(f_srv, text="📂 Cargar Archivo (CSV/Excel)", command=self.validar_trend_masivo).grid(row=1, column=1, sticky="w", padx=5)

        # --- BOTÓN ABORTAR ---
        self.btn_abort_trend = ttk.Button(self.tab_trend, text="🛑 ABORTAR PROCESO TREND", command=self.abortar_trend, state=tk.DISABLED)
        self.btn_abort_trend.pack(pady=15)

    def abortar_trend(self):
        self.log("⚠️ Solicitando interrupción de Trend Vision One...")
        self.stop_event_trend.set()
        self.btn_abort_trend.config(state=tk.DISABLED, text="⏳ Abortando...")

    def lanzar_trend_ips(self):
        self.btn_abort_trend.config(state=tk.NORMAL, text="🛑 ABORTAR PROCESO TREND")
        self.stop_event_trend.clear()
        threading.Thread(target=self.hilo_trend_ips).start()

    def hilo_trend_ips(self):
        ini = self.ent_trend_ini.get()
        fin = self.ent_trend_fin.get()
        exito, msg = descargar_eventos_ips(ini, fin, log_callback=self.log, stop_event=self.stop_event_trend)
        self.procesar_fin_trend(exito, msg)

    def buscar_trend_manual(self):
        criterio = self.ent_srv_manual.get().strip()
        if not criterio: return
        self.log(f"[*] Buscando activo: {criterio}")
        res = buscar_servidor_api(criterio)
        if res == "EXPIRED":
            messagebox.showwarning("Token Expirado", "El token de Trend Vision One ha caducado. Por favor, actualice su .env.")
        elif res:
            s = res[0]
            messagebox.showinfo("Servidor Encontrado", f"Host: {s.get('endpointName')}\nIP: {s.get('ip')}\nOS: {s.get('osName')}")
        else:
            messagebox.showinfo("Resultado", "No se encontró información del servidor.")

    def validar_trend_masivo(self):
        path = filedialog.askopenfilename(filetypes=[("Archivos de datos", "*.xlsx *.xls *.csv")])
        if not path: return
        self.btn_abort_trend.config(state=tk.NORMAL, text="🛑 ABORTAR PROCESO TREND")
        self.stop_event_trend.clear()
        threading.Thread(target=self.hilo_trend_archivo, args=(path,)).start()

    def hilo_trend_archivo(self, path):
        exito, msg = procesar_archivo_servidores(path, log_callback=self.log, stop_event=self.stop_event_trend)
        self.procesar_fin_trend(exito, msg)

    def procesar_fin_trend(self, exito, mensaje):
        self.btn_abort_trend.config(state=tk.DISABLED)
        if "TOKEN_EXPIRED" in mensaje:
            self.root.after(0, lambda: messagebox.showwarning("Rotación Requerida", mensaje))
        elif not exito:
            self.root.after(0, lambda: messagebox.showerror("Error", mensaje))
        else:
            self.root.after(0, lambda: messagebox.showinfo("Éxito", mensaje))

    # ==========================================
    # LOGICA DE OTRAS PESTAÑAS (Mantenida)
    # ==========================================
    # (Aquí van tus métodos setup_cve_tab, setup_ti_tab, setup_tenable_tab, etc.)
    # Por brevedad, se omiten los detalles internos de cada tab ya proporcionados anteriormente,
    # pero deben permanecer en tu main.py para que la app sea funcional.
    
    def setup_cve_tab(self):
        # ... lógica de UI de NVD ...
        pass
    
    def setup_ti_tab(self):
        # ... lógica de UI de Threat Intel ...
        pass
        
    def setup_tenable_tab(self):
        # ... lógica de UI de Tenable SC ...
        pass

# ==========================================
# GESTIÓN DE CIERRE SEGURO (CTRL+C)
# ==========================================
def manejar_interrupcion(sig, frame):
    print("\n[!] Cerrando Toolkit de forma segura...")
    sys.exit(0)

if __name__ == "__main__":
    # Capturar Ctrl+C en la terminal
    signal.signal(signal.SIGINT, manejar_interrupcion)
    
    root = tk.Tk()
    app = RedTeamToolkitApp(root)
    
    # Truco para que Tkinter permita que Python procese señales del sistema en Windows/Linux
    def check(): root.after(500, check)
    root.after(500, check)
    
    root.mainloop()