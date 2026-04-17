# 🛡️ Advanced CTI & Vulnerability Toolkit

<p align="center">
  <img src="[https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white)" alt="Python">
  <img src="[https://img.shields.io/badge/License-MIT-green?style=for-the-badge](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)" alt="License">
  <img src="[https://img.shields.io/badge/Maintained%3F-yes-brightgreen?style=for-the-badge](https://img.shields.io/badge/Maintained%3F-yes-brightgreen?style=for-the-badge)" alt="Maintained">
  <img src="[https://img.shields.io/badge/OS-Linux%20%7C%20Windows-lightgrey?style=for-the-badge](https://img.shields.io/badge/OS-Linux%20%7C%20Windows-lightgrey?style=for-the-badge)" alt="OS">
</p>

Una herramienta de escritorio con Interfaz Gráfica (GUI) diseñada para especialistas en ciberseguridad, equipos Red Team e investigadores de Threat Intelligence. Permite la extracción automatizada de vulnerabilidades (CVEs) desde la National Vulnerability Database (NVD) y el escaneo masivo de Indicadores de Compromiso (IoCs) utilizando VirusTotal y AbuseIPDB.

---

## 🚀 Características Principales

### 1. Buscador Avanzado de CVEs (NVD API v2.0)

- **Extracción Masiva:** Supera los límites de paginación de la API de NVD para descargar bases de datos históricas completas de forma automatizada.
- **Filtros Granulares:** Búsqueda por rango de fechas, Severidad CVSS (Low a Critical), Keywords específicas y CPE (Common Platform Enumeration).
- **Deduplicación Inteligente:** Detecta qué CVEs ya existen en tu base de datos local (Excel) y solo añade los registros nuevos, ignorando duplicados y limpiando espacios ocultos.
- **Extracción de Software Afectado:** Parsea la compleja estructura JSON de la NVD para entregar el nombre legible del fabricante, tecnología y versión vulnerable.

### 2. Motor de Threat Intelligence (IoC Scanner)

- **Análisis Multi-Vector:** Soporte para el escaneo de direcciones IP, URLs y Hashes de archivos.
- **OpSec Safe (File Hashing):** Calcula el hash SHA-256 localmente antes de consultar a VirusTotal, evitando la exposición en la nube de archivos o artefactos internos sensibles.
- **Ingesta Masiva:** Capacidad de procesar miles de IoCs importando archivos `.txt`, `.csv` o `.xlsx`. El motor auto-detecta la estructura del documento y extrae los datos automáticamente.
- **Reportes Automatizados:** Generación automática de volcados en texto plano (`.txt`) para evidencias y matrices manejables en Excel (`.xlsx`).

---

## ⚙️ Requisitos y Dependencias

El toolkit es compatible con entornos Linux (testeado en Arch Linux) y Windows.

Para instalar las dependencias necesarias, ejecuta:

```bash
pip install requests pandas openpyxl python-dotenv
```

---

## 🔐 Configuración de Credenciales

Para interactuar con las APIs de inteligencia de amenazas sin sufrir bloqueos por _Rate Limiting_, es necesario configurar tus API Keys gratuitas.

1. Crea un archivo llamado `.env` en el directorio raíz del proyecto.
2. Agrega las siguientes variables (reemplazando con tus datos):

```env
NVD_API_KEY=tu_api_key_nvd
VT_API_KEY=tu_api_key_virustotal
ABUSEIPDB_API_KEY=tu_api_key_abuseipdb
```

> [!CAUTION]
> **Nota de Seguridad Crítica:** El archivo `.env` ya se encuentra excluido mediante el `.gitignore`. **NUNCA** realices un commit ni subas este archivo a repositorios públicos, ya que expondrás tus credenciales privadas.

---

## 🛠️ Uso y Arquitectura

Ejecuta el script principal para lanzar la interfaz gráfica:

```bash
python main.py
```

### Funciones de Control de Flujo

- **Aborto Seguro:** Ambos módulos incluyen un botón para abortar procesos largos. Esta función detiene la ejecución inmediatamente cerrando las conexiones de red, sin corromper los archivos Excel generados.
- **Consola de Estado:** Visualización en tiempo real del progreso de peticiones, errores de red y status del rate limiting.

### 📁 Estructura del Proyecto

```text
├── .env                  # (Ignorado por Git) Credenciales de API
├── .gitignore            # Reglas de exclusión del repositorio
├── config.py             # Cargador centralizado de variables de entorno
├── main.py               # Punto de entrada UI (Tkinter) y control multihilo
├── README.md             # Documentación principal
├── core/
│   ├── nvd_scanner.py    # Lógica de peticiones y parseo JSON del NIST
│   └── threat_intel.py   # Lógica de interacciones con VirusTotal y AbuseIPDB
└── utils/
    └── file_manager.py   # Motor de lectura de listas y generación de reportes
```

---

## ⚖️ Disclaimer Legal y Ético

> [!WARNING]
> Este proyecto ha sido desarrollado exclusivamente con fines **educativos** y para su uso en **entornos corporativos autorizados** o durante **auditorías de seguridad (Red Team / Pentesting)** que cuenten con el consentimiento explícito y por escrito del propietario de la infraestructura. El desarrollador no se hace responsable por el mal uso de esta herramienta.

---

_Desarrollado para facilitar la eficiencia operativa en CTI y Gestión de Vulnerabilidades._
