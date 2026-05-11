# 🛡️ Advanced CTI & Vulnerability Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Maintained%3F-yes-brightgreen?style=for-the-badge" alt="Maintained">
  <img src="https://img.shields.io/badge/OS-Linux%20%7C%20Windows-lightgrey?style=for-the-badge" alt="OS">
</p>

Una herramienta de escritorio con Interfaz Gráfica (GUI) diseñada para especialistas en ciberseguridad, equipos Red Team e investigadores de Threat Intelligence. Permite la extracción automatizada de vulnerabilidades (CVEs) desde la National Vulnerability Database (NVD), el cruce de inteligencia con infraestructuras internas vía Tenable Security Center, el análisis de telemetría en **Trend Vision One** y el escaneo masivo de Indicadores de Compromiso (IoCs) utilizando VirusTotal y AbuseIPDB.

---

## 🚀 Características Principales

### 1. Buscador Avanzado de CVEs (NVD API v2.0)

- **Extracción Masiva:** Supera los límites de paginación de la API de NVD para descargar bases de datos históricas completas.
- **Filtros Granulares:** Búsqueda por rango de fechas, Severidad CVSS, Keywords y CPE.
- **Deduplicación Inteligente:** Solo añade registros nuevos al Excel local, ignorando duplicados.

### 2. Motor de Threat Intelligence (IoC Scanner)

- **Análisis Multi-Vector:** Soporte para IP, URL y Hashes de archivos.
- **OpSec Safe:** Cálculo de hash local antes de consulta para evitar exposición de artefactos sensibles.
- **Reportes Automatizados:** Generación de archivos `.txt` y `.xlsx` con los resultados del análisis.

### 3. Integración con Tenable Security Center (Tenable.sc)

- **Cruce Automático:** Cruza CVEs detectados con la base de datos de vulnerabilidades interna.
- **Validación de Impacto:** Identifica servidores afectados en tiempo real y genera reportes individuales por CVE crítico.

### 4. Módulo Avanzado Trend Vision One (XDR)

- **Métricas IPS (Endpoint Security):** Extracción automatizada de eventos de "Intrusion Prevention" filtrados por periodo. Los datos se integran sin sobrescribir en el archivo corporativo `Métricas Trend Vision One.xlsx`.
- **Validación de Activos (Asset Search):** Búsqueda bidireccional (IP o Hostname) para obtener información técnica del servidor (SO, Agent GUID, etc.).
- **Procesamiento Masivo:** Soporte para carga de archivos `.txt`, `.csv` y `.xlsx` con validación de integridad y detección automática de delimitadores.
- **Gestión de Sesión:** Sistema de alerta integrado para la rotación de API Keys (recomendado cada 90 días).

---

## ⚙️ Requisitos y Dependencias

El toolkit es compatible con entornos Linux y Windows.

Para instalar las dependencias necesarias, ejecuta:

```bash
pip install requests pandas openpyxl python-dotenv pyTenable
```

---

## 🔐 Configuración de Credenciales

Crea un archivo llamado `.env` en el directorio raíz del proyecto con el siguiente formato:

```env
# Inteligencia Externa
NVD_API_KEY="tu_api_key_nvd"
VT_API_KEY="tu_api_key_virustotal"
ABUSEIPDB_API_KEY="tu_api_key_abuseipdb"

# Tenable Security Center
SC_IP="ip_o_dominio_sc"
SC_ACCESS_KEY="tu_access_key"
SC_SECRET_KEY="tu_secret_key"

# Trend Vision One
TREND_V1_URL="api.xdr.trendmicro.com"
TREND_V1_TOKEN="tu_token_trend_v1"
```

> [!CAUTION]
> **Nota de Seguridad Crítica:** El archivo `.env` está excluido vía `.gitignore`. **NUNCA** subas este archivo a repositorios públicos. Se recomienda asignar el rol de **Auditor** a la API Key de Trend Vision One.

---

## 🛠️ Uso y Arquitectura

Ejecuta el script principal para lanzar la interfaz gráfica:

```bash
python main.py
```

### Funciones de Control de Flujo

- **Aborto Seguro:** Botones dedicados en cada módulo para detener procesos largos sin corromper archivos o bases de datos locales.
- **Consola de Estado:** Visualización en tiempo real del progreso (ej. `Analizando 5/150`) y alertas de caducidad de tokens.

### 📁 Estructura del Proyecto

```text
├── .env                  # Credenciales de APIs (Ignorado)
├── .gitignore            # Reglas de exclusión
├── config.py             # Cargador de variables de entorno
├── main.py               # Punto de entrada y GUI (Tkinter)
├── README.md             # Documentación
├── core/
│   ├── nvd_scanner.py    # Lógica de la NVD
│   ├── threat_intel.py   # Lógica de IoCs
│   ├── tenable_sc_scanner.py # Lógica de Tenable
│   └── trend_v1_scanner.py   # Lógica de Trend Vision One (IPS y Assets)
└── utils/
    └── file_manager.py   # Gestión de archivos y reportes
```

---

## ⚖️ Disclaimer Legal y Ético

> [!WARNING]
> Este proyecto ha sido desarrollado exclusivamente con fines **educativos** y para su uso en **entornos corporativos autorizados**. El desarrollador no se hace responsable por el mal uso de esta herramienta.

---

_Desarrollado para facilitar la eficiencia operativa en CTI y Gestión de Vulnerabilidades._
