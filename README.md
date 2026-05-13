# 🛡️ Advanced RedTeam & CTI Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/GUI-CustomTkinter-blueviolet?style=for-the-badge" alt="GUI">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20Windows-lightgrey?style=for-the-badge" alt="OS">
</p>

Una plataforma de escritorio avanzada con interfaz moderna diseñada para operadores de Red Team y analistas de Threat Intelligence. Facilita la correlación de vulnerabilidades (NVD), el análisis de impacto interno (Tenable.sc) y la telemetría ofensiva/defensiva en **TrendAI Vision One**, todo bajo un entorno gráfico profesional de alto rendimiento.

---

## 🚀 Características Principales

### 1. Interfaz Ejecutiva de Próxima Generación

- **Dashboard Moderno:** Construido con `customtkinter`, ofreciendo un modo oscuro nativo y una disposición optimizada para flujos de trabajo de seguridad.
- **Consola Operativa:** Log en tiempo real con estética de terminal para el monitoreo de procesos en segundo plano.

### 2. Módulo Avanzado TrendAI Vision One (XDR)

- **Omni-Extractor de Datos:** Motor de búsqueda capaz de extraer IPs, Hostnames y etiquetas (Tags) con precisión quirúrgica, incluso cuando la API devuelve datos parciales.
- **Caché Global de Inventario:** Descarga y almacenamiento en memoria del inventario completo de activos para permitir búsquedas instantáneas y coincidencias aproximadas ("contiene").
- **Detección de Etiquetas Manuales:** Algoritmo recursivo diseñado para identificar etiquetas colocadas manualmente (ej. `nessus`, `vulnerabilidad`) ocultas en los metadatos del proveedor.
- **Soporte Multi-IP:** Capacidad para listar y exportar todas las direcciones IP asociadas a un mismo activo (VPN, LAN, Virtuales).

### 3. Buscador de Vulnerabilidades (NVD API v2.0)

- **Minería de CVEs:** Extracción automatizada superando límites de paginación para análisis histórico.
- **Filtros de Severidad:** Clasificación instantánea por impacto CVSS v3.

### 4. Threat Intelligence & IoC Scanner

- **Validación Multi-Fuente:** Integración con AbuseIPDB y VirusTotal para reputación de IPs, URLs y Hashes.
- **Cruce Tenable.sc:** Identificación de activos internos vulnerables a CVEs específicos detectados en fuentes externas.

---

## ⚙️ Requisitos y Dependencias

El toolkit requiere Python 3.8+ y las siguientes librerías:

```bash
pip install requests pandas openpyxl python-dotenv pyTenable customtkinter
```

---

## 🔐 Configuración de Credenciales

Configura tu archivo `.env` en la raíz del proyecto para habilitar las integraciones:

```env
# Inteligencia Externa
NVD_API_KEY="tu_api_key_nvd"
VT_API_KEY="tu_api_key_virustotal"
ABUSEIPDB_API_KEY="tu_api_key_abuseipdb"

# Tenable Security Center
SC_IP="ip_o_dominio_sc"
SC_ACCESS_KEY="tu_access_key"
SC_SECRET_KEY="tu_secret_key"

# TrendAI Vision One
TREND_V1_URL="api.xdr.trendmicro.com"
TREND_V1_TOKEN="tu_token_trend_v1"
```

---

## 🛠️ Arquitectura del Sistema

```text
├── main.py                # Punto de entrada (GUI CustomTkinter)
├── config.py              # Gestión de entorno y constantes
├── core/
│   ├── nvd_scanner.py     # Lógica de extracción de vulnerabilidades
│   ├── threat_intel.py    # Análisis de indicadores (IoCs)
│   ├── tenable_sc_scanner.py # Integración interna Tenable.sc
│   └── trend_v1_scanner.py   # Motor avanzado TrendAI (Omni-Extractor)
└── utils/
    └── file_manager.py    # Generación de reportes y manejo de archivos
```

---

## ⚖️ Disclaimer Legal y Ético

Este toolkit debe ser utilizado únicamente en entornos donde se posea autorización explícita para la auditoría de seguridad. El desarrollador no asume responsabilidad por el uso indebido de las capacidades de automatización aquí presentadas.

---

_Optimizado para la excelencia operativa en Ciberseguridad Ofensiva y Gestión de Amenazas._
