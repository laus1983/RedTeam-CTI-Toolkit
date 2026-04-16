# 🛡️ Advanced CTI & Vulnerability Toolkit

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)

Una herramienta de escritorio con Interfaz Gráfica (GUI) diseñada para especialistas en ciberseguridad, equipos Red Team e investigadores de Threat Intelligence. Permite la extracción automatizada de vulnerabilidades (CVEs) desde la National Vulnerability Database (NVD) y el escaneo masivo de Indicadores de Compromiso (IoCs) utilizando VirusTotal y AbuseIPDB.

## 🚀 Características Principales

### 1. Buscador Avanzado de CVEs (NVD API v2.0)

- **Extracción Masiva:** Supera los límites de paginación de la API de NVD para descargar bases de datos históricas completas.
- **Filtros Granulares:** Búsqueda por rango de fechas, Severidad CVSS (Low a Critical), Keywords específicas y CPE (Common Platform Enumeration).
- **Deduplicación Inteligente:** Detecta qué CVEs ya existen en tu base de datos local (Excel) y solo añade los registros nuevos.
- **Extracción de Software Afectado:** Parsea la compleja estructura JSON de la NVD para entregar el nombre legible del fabricante, tecnología y versión vulnerable.

### 2. Motor de Threat Intelligence (IoC Scanner)

- **Análisis Multi-Vector:** Soporte para direcciones IP, URLs y Hashes de archivos.
- **OpSec Safe (File Hashing):** Calcula el hash SHA-256 localmente antes de consultar a VirusTotal, evitando la exposición de archivos o artefactos internos en la nube.
- **Ingesta Masiva:** Capacidad de procesar miles de IoCs importando archivos `.txt`, `.csv` o `.xlsx`.
- **Reportes Automatizados:** Generación automática de volcados en texto plano (`.txt`) para anexar a reportes de auditoría y matrices manejables en Excel (`.xlsx`).

## ⚙️ Requisitos y Dependencias

El toolkit es compatible con entornos Linux (testeado en Arch Linux) y Windows.

Instala las dependencias necesarias:

```bash
pip install requests pandas openpyxl python-dotenv
```

🔐 Configuración de Credenciales
Para interactuar con las APIs de inteligencia de amenazas sin sufrir bloqueos por Rate Limiting, es necesario configurar tus API Keys gratuitas.

Crea un archivo llamado .env en el directorio raíz del proyecto.

Agrega las siguientes variables (reemplazando los valores con tus propias llaves):

NVD_API_KEY=tu_api_key_nvd
VT_API_KEY=tu_api_key_virustotal
ABUSEIPDB_API_KEY=tu_api_key_abuseipdb

[!CAUTION]
Nota de Seguridad Crítica: El archivo .env ya se encuentra excluido mediante el .gitignore proporcionado. NUNCA realices un commit ni subas este archivo a repositorios públicos, ya que expondrás tus credenciales.

🛠️ Uso y Arquitectura
Ejecuta el script principal para lanzar la interfaz gráfica:

python main.py

Funciones de Control de Flujo Integradas
Aborto Seguro de Procesos: Ambos módulos incluyen un botón para cancelar operaciones largas (como descargas masivas de CVEs). Esta función detiene la ejecución inmediatamente y cierra los sockets de red, garantizando que no se corrompan los archivos Excel generados.

Consola de Estado: Visualización en tiempo real del progreso de las peticiones HTTP, detección de errores (ej. 403/404) y estatus del rate limiting, permitiendo monitorear la herramienta sin necesidad de observar la terminal de fondo.

📁 Estructura del Proyecto

├── .env # (Ignorado por Git) Credenciales de API
├── .gitignore # Reglas de exclusión del repositorio
├── config.py # Cargador centralizado de variables de entorno
├── main.py # Punto de entrada UI (Tkinter) y control multihilo
├── README.md # Documentación principal
├── core/  
│ ├── nvd_scanner.py # Lógica de peticiones y parseo JSON del NIST
│ └── threat_intel.py # Lógica de interacciones con VirusTotal y AbuseIPDB
└── utils/  
 └── file_manager.py # Motor de lectura de listas (CSV/TXT/XLSX) y generación de reportes

⚖️ Disclaimer Legal y Ético
[!WARNING]
Este proyecto ha sido desarrollado exclusivamente con fines educativos y para su uso en entornos corporativos autorizados o durante auditorías de seguridad (Red Team / Pentesting) que cuenten con el consentimiento explícito y por escrito del propietario de la infraestructura.

El uso de esta herramienta para la recolección de inteligencia o el escaneo sobre infraestructuras, dominios o activos de terceros sin autorización es una violación a la privacidad y a las leyes de ciberseguridad aplicables. El desarrollador no se hace responsable por el mal uso de esta herramienta.

Desarrollado para facilitar la eficiencia operativa en CTI y Gestión de Vulnerabilidades.
