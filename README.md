# Escáner de puertos TCP

Escáner de puertos TCP con **interfaz web en Flask**. Permite introducir una IP,
un hostname o un rango y visualizar en tiempo real qué puertos están abiertos, la
latencia de respuesta y el banner del servicio cuando está disponible. El escaneo
se ejecuta en segundo plano con un **pool de hilos (threading)**, de modo que la
interfaz nunca se bloquea mientras avanza.

> ⚠️ **Uso responsable.** Esta herramienta es para fines educativos y de
> auditoría autorizada. Escanea únicamente sistemas de tu propiedad o para los
> que tengas permiso explícito por escrito. El escaneo de puertos sin
> autorización puede ser ilegal según la jurisdicción.

---

## Características

- **Interfaz web** limpia con actualización de resultados en vivo.
- **Objetivos flexibles**: IP suelta, hostname (resolución DNS), red CIDR
  (`10.0.0.0/28`) o rango con guion (`192.168.1.10-20`). Se admiten varios
  separados por comas.
- **Puertos flexibles**: puertos comunes (`top`), rangos (`1-1024`), listas
  (`22,80,443`), `all` (1–65535) o combinaciones.
- **Banner grabbing**: captura la cabecera del servicio cuando responde
  (SSH, FTP, SMTP, HTTP…).
- **Latencia** medida por puerto en milisegundos.
- **Concurrencia configurable** mediante `ThreadPoolExecutor`.
- **Escaneo asíncrono** por trabajos: la UI hace *polling* del progreso y puede
  **detener** un escaneo en curso.
- **Límites de seguridad** para evitar escaneos accidentales gigantescos.

---

## Requisitos

- Python 3.10 o superior
- Flask (ver `requirements.txt`)

## Instalación

```bash
git clone https://github.com/xnext890/Esc-ner-de-puertos-TCP.git
cd Esc-ner-de-puertos-TCP

# (recomendado) entorno virtual
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

## Uso

### Interfaz web

```bash
python app.py
```

Abre `http://127.0.0.1:5000` en el navegador, introduce un objetivo y pulsa
**Iniciar escaneo**. Los puertos abiertos aparecen en la tabla a medida que se
descubren.

Para probar de forma legal puedes usar el host oficial de pruebas de Nmap:
`scanme.nmap.org`.

### Línea de comandos

El núcleo (`scanner.py`) también funciona sin la web:

```bash
python scanner.py scanme.nmap.org -p top
python scanner.py 192.168.1.0/28 -p 1-1024 -c 200 -t 0.8
```

Opciones: `-p/--ports`, `-t/--timeout`, `-c/--concurrency`.

---

## API

| Método | Ruta                     | Descripción                                  |
|--------|--------------------------|----------------------------------------------|
| `POST` | `/api/scan`              | Inicia un escaneo. Devuelve `job_id`.        |
| `GET`  | `/api/scan/<job_id>`     | Estado, progreso y puertos abiertos.         |
| `POST` | `/api/scan/<job_id>/stop`| Solicita cancelar el escaneo.                |

Cuerpo de ejemplo para `POST /api/scan`:

```json
{
  "target": "scanme.nmap.org",
  "ports": "top",
  "timeout": 1.0,
  "concurrency": 100
}
```

---

## Estructura del proyecto

```
Esc-ner-de-puertos-TCP/
├── app.py                # Aplicación Flask y API de escaneo por trabajos
├── scanner.py            # Núcleo: parseo, escaneo TCP, banner, concurrencia
├── requirements.txt
├── templates/
│   └── index.html        # Interfaz
├── static/
│   ├── css/style.css     # Estilos
│   └── js/app.js         # Lógica del cliente (polling en vivo)
├── LICENSE
└── README.md
```

## Cómo funciona (resumen técnico)

1. El cliente envía el objetivo a `POST /api/scan`. El servidor valida y expande
   objetivos y puertos, aplica los límites de seguridad y lanza el escaneo en un
   **hilo de fondo** (`threading.Thread`), devolviendo un `job_id` al instante.
2. Dentro del trabajo, `scanner.scan_targets` reparte todas las combinaciones
   `(host, puerto)` en un `ThreadPoolExecutor`. Cada tarea abre un socket TCP,
   mide la latencia con `time.perf_counter()` y, si el puerto está abierto,
   intenta capturar el banner.
3. El estado del trabajo (progreso y puertos abiertos) se comparte de forma
   segura con un `Lock`. El frontend consulta `GET /api/scan/<job_id>` cada
   ~500 ms y va pintando los resultados sin recargar la página.

## Notas y limitaciones

- Realiza un **TCP connect scan** (`connect()` completo), no un SYN scan, por lo
  que no requiere privilegios de administrador pero es más detectable.
- El banner grabbing es *best effort*: no todos los servicios envían banner y los
  puertos TLS (443, 8443…) no se interrogan a nivel de aplicación.
- El almacén de trabajos vive en memoria: pensado para uso local / demostración.

## Licencia

Distribuido bajo licencia [MIT](LICENSE).
