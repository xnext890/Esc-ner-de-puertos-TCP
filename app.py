"""
app.py
======
Interfaz web (Flask) del escáner de puertos TCP.

El escaneo puede tardar, así que NO se ejecuta dentro de la petición HTTP.
En su lugar:

  1. POST /api/scan   -> valida, crea un "trabajo", lo lanza en un hilo de
                         fondo y devuelve un job_id de inmediato.
  2. GET  /api/scan/<job_id>       -> estado + progreso + puertos encontrados.
  3. POST /api/scan/<job_id>/stop  -> solicita cancelar el trabajo.

De este modo la interfaz sigue respondiendo y se actualiza en vivo mientras
el escaneo avanza (el frontend hace polling del estado).

Aviso legal / ético: usa esta herramienta únicamente contra sistemas de tu
propiedad o para los que tengas autorización explícita por escrito.
"""

from __future__ import annotations

import threading
import time
import uuid

from flask import Flask, jsonify, render_template, request

import scanner

app = Flask(__name__)

# Almacén en memoria de trabajos de escaneo. Para un portfolio / uso local es
# suficiente; en producción se sustituiría por Redis, una base de datos, etc.
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()

# Topes defensivos sobre los parámetros que llegan del cliente.
_MAX_CONCURRENCY = 500
_MAX_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# Vista principal
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# API: iniciar un escaneo
# ---------------------------------------------------------------------------
@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json(silent=True) or {}

    target_spec = str(data.get("target", "")).strip()
    ports_spec = str(data.get("ports", "top")).strip() or "top"

    # Saneamos los parámetros numéricos dentro de límites razonables.
    timeout = _clamp_float(data.get("timeout", 1.0), 0.1, _MAX_TIMEOUT, 1.0)
    concurrency = _clamp_int(data.get("concurrency", 100), 1, _MAX_CONCURRENCY, 100)

    # Validación de objetivos y puertos (devuelve 400 con mensaje claro).
    try:
        hosts = scanner.parse_targets(target_spec)
        ports = scanner.parse_ports(ports_spec)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    total = scanner.count_tasks(hosts, ports)
    if total > scanner.MAX_TASKS:
        return (
            jsonify(
                {
                    "error": (
                        f"El escaneo generaría {total} conexiones y supera el "
                        f"límite de {scanner.MAX_TASKS}. Reduce el rango de IPs "
                        f"o de puertos."
                    )
                }
            ),
            400,
        )

    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "status": "running",           # running | done | stopped | error
        "target": target_spec,
        "ports": ports_spec,
        "timeout": timeout,
        "concurrency": concurrency,
        "hosts": len(hosts),
        "total": total,
        "done": 0,
        "open": [],                    # lista de puertos abiertos encontrados
        "error": None,
        "started_at": time.time(),
        "finished_at": None,
        "_stop": False,                # bandera interna de cancelación
    }
    with _jobs_lock:
        _jobs[job_id] = job

    worker = threading.Thread(
        target=_run_job,
        args=(job_id, hosts, ports, timeout, concurrency),
        daemon=True,
    )
    worker.start()

    return jsonify({"job_id": job_id, "total": total, "hosts": len(hosts)}), 202


# ---------------------------------------------------------------------------
# API: consultar estado / progreso
# ---------------------------------------------------------------------------
@app.route("/api/scan/<job_id>", methods=["GET"])
def scan_status(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return jsonify({"error": "Trabajo no encontrado."}), 404
        # Copia superficial sin campos internos (los que empiezan por "_").
        payload = {k: v for k, v in job.items() if not k.startswith("_")}

    elapsed = (payload["finished_at"] or time.time()) - payload["started_at"]
    payload["elapsed_s"] = round(elapsed, 2)
    payload["open_count"] = len(payload["open"])
    return jsonify(payload)


# ---------------------------------------------------------------------------
# API: solicitar cancelación
# ---------------------------------------------------------------------------
@app.route("/api/scan/<job_id>/stop", methods=["POST"])
def scan_stop(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return jsonify({"error": "Trabajo no encontrado."}), 404
        job["_stop"] = True
    return jsonify({"status": "stopping"})


# ---------------------------------------------------------------------------
# Ejecución del trabajo en segundo plano
# ---------------------------------------------------------------------------
def _run_job(job_id, hosts, ports, timeout, concurrency):
    """Corre en un hilo aparte; va actualizando el trabajo compartido."""

    def on_result(res: dict) -> None:
        with _jobs_lock:
            _jobs[job_id]["open"].append(res)

    def on_progress(done: int, total: int) -> None:
        with _jobs_lock:
            _jobs[job_id]["done"] = done

    def should_stop() -> bool:
        with _jobs_lock:
            return _jobs[job_id]["_stop"]

    try:
        scanner.scan_targets(
            hosts,
            ports,
            timeout=timeout,
            concurrency=concurrency,
            on_result=on_result,
            on_progress=on_progress,
            should_stop=should_stop,
        )
        final_status = "stopped" if should_stop() else "done"
    except Exception as exc:  # noqa: BLE001 - lo reportamos al cliente
        with _jobs_lock:
            _jobs[job_id]["error"] = str(exc)
        final_status = "error"

    with _jobs_lock:
        job = _jobs[job_id]
        job["status"] = final_status
        job["finished_at"] = time.time()
        # Ordenamos por host y puerto para una presentación estable.
        job["open"].sort(key=lambda r: (r["host"], r["port"]))


# ---------------------------------------------------------------------------
# Utilidades de saneamiento
# ---------------------------------------------------------------------------
def _clamp_int(value, low, high, default):
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


def _clamp_float(value, low, high, default):
    try:
        return max(low, min(high, float(value)))
    except (TypeError, ValueError):
        return default


if __name__ == "__main__":
    # host=127.0.0.1 por defecto: la herramienta solo escucha en local.
    app.run(host="127.0.0.1", port=5000, debug=True)
