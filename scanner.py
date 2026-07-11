"""
scanner.py
==========
Núcleo del escáner de puertos TCP.

Contiene toda la lógica independiente de la web:
  - Parseo de objetivos (IP suelta, hostname, rango CIDR, rango con guion).
  - Parseo de la especificación de puertos.
  - Conexión TCP (connect scan) con medición de tiempo de respuesta.
  - Banner grabbing del servicio cuando está disponible.
  - Control de concurrencia mediante un pool de hilos (threading).

Este módulo NO importa Flask a propósito: así puede reutilizarse desde la
línea de comandos, desde tests o desde cualquier otra interfaz.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# Catálogo de puertos comunes -> nombre de servicio.
# Se usa para el modo "top" y para etiquetar los resultados.
# ---------------------------------------------------------------------------
COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

# Límite de seguridad: nº máximo de tareas (host x puerto) por escaneo.
# Evita que un rango descuidado (p. ej. /8 con "all") dispare millones de
# conexiones sin querer.
MAX_TASKS = 65_536

# Puertos donde conviene enviar una sonda HTTP para provocar el banner.
_HTTP_PORTS = {80, 591, 3000, 8000, 8080, 8888, 5601, 9200}


# ---------------------------------------------------------------------------
# Parseo de la especificación de puertos
# ---------------------------------------------------------------------------
def parse_ports(spec: str) -> list[int]:
    """
    Convierte una especificación de puertos en una lista ordenada de enteros.

    Formatos aceptados (se pueden combinar con comas):
      - "top"        -> los puertos comunes de COMMON_PORTS
      - "all"        -> 1..65535
      - "80"         -> un puerto suelto
      - "1-1024"     -> un rango inclusivo
      - "22,80,443"  -> lista
      - "22,80,8000-8100,top" -> mezcla

    Lanza ValueError si algún token no es válido.
    """
    spec = (spec or "").strip().lower()
    if not spec:
        raise ValueError("La lista de puertos está vacía.")

    ports: set[int] = set()

    for raw_token in spec.split(","):
        token = raw_token.strip()
        if not token:
            continue

        if token == "top":
            ports.update(COMMON_PORTS.keys())
            continue
        if token == "all":
            ports.update(range(1, 65536))
            continue

        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start, end = _port_int(start_s), _port_int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(_port_int(token))

    if not ports:
        raise ValueError("No se ha reconocido ningún puerto válido.")
    return sorted(ports)


def _port_int(value: str) -> int:
    """Valida y convierte un puerto individual (1-65535)."""
    value = value.strip()
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"Puerto no numérico: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"Puerto fuera de rango (1-65535): {port}")
    return port


# ---------------------------------------------------------------------------
# Parseo de objetivos
# ---------------------------------------------------------------------------
def parse_targets(spec: str) -> list[str]:
    """
    Convierte una especificación de objetivos en una lista de IPs/hosts.

    Formatos aceptados (uno o varios separados por comas):
      - "192.168.1.10"                 -> IP suelta
      - "example.com"                  -> hostname (se resuelve por DNS)
      - "192.168.1.0/24"               -> red CIDR (se omiten red y broadcast)
      - "192.168.1.10-192.168.1.20"    -> rango con guion (IPs completas)
      - "192.168.1.10-20"              -> rango con guion (solo último octeto)

    Lanza ValueError si nada es interpretable.
    """
    spec = (spec or "").strip()
    if not spec:
        raise ValueError("El objetivo está vacío.")

    hosts: list[str] = []
    seen: set[str] = set()

    def add(host: str) -> None:
        if host not in seen:
            seen.add(host)
            hosts.append(host)

    for raw_token in spec.split(","):
        token = raw_token.strip()
        if not token:
            continue

        # 1) Red CIDR
        if "/" in token:
            network = ipaddress.ip_network(token, strict=False)
            # Para /31 y /32 usamos todas las direcciones; en el resto
            # omitimos red y broadcast con hosts().
            iterable = (
                network.hosts()
                if network.num_addresses > 2
                else network
            )
            for ip in iterable:
                add(str(ip))
            continue

        # 2) Rango con guion
        if "-" in token:
            for ip in _expand_dash_range(token):
                add(ip)
            continue

        # 3) IP suelta o hostname
        add(token)

    if not hosts:
        raise ValueError("No se ha reconocido ningún objetivo válido.")
    return hosts


def _expand_dash_range(token: str) -> Iterable[str]:
    """
    Expande rangos con guion:
      "192.168.1.10-192.168.1.20"  (IPs completas en ambos extremos)
      "192.168.1.10-20"            (solo el último octeto en el extremo final)
    """
    left, right = (part.strip() for part in token.split("-", 1))
    start_ip = ipaddress.ip_address(left)

    if "." not in right and ":" not in right:
        # Forma abreviada: sustituimos el último octeto de la IP inicial.
        base = str(start_ip).rsplit(".", 1)[0]
        right = f"{base}.{right}"

    end_ip = ipaddress.ip_address(right)
    if int(end_ip) < int(start_ip):
        start_ip, end_ip = end_ip, start_ip

    for value in range(int(start_ip), int(end_ip) + 1):
        yield str(ipaddress.ip_address(value))


def count_tasks(hosts: list[str], ports: list[int]) -> int:
    """Número total de conexiones (host x puerto) que implicaría el escaneo."""
    return len(hosts) * len(ports)


# ---------------------------------------------------------------------------
# Escaneo de un único puerto
# ---------------------------------------------------------------------------
def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    Intenta una conexión TCP a (host, port) y devuelve un diccionario:

        {
          "host": str,
          "port": int,
          "state": "open" | "closed" | "filtered" | "error",
          "service": str,           # nombre estimado del servicio
          "latency_ms": float | None,
          "banner": str,            # texto del banner o ""
        }

    "filtered" se usa cuando la conexión agota el tiempo (posible firewall).
    """
    service = COMMON_PORTS.get(port, "unknown")
    result = {
        "host": host,
        "port": port,
        "state": "closed",
        "service": service,
        "latency_ms": None,
        "banner": "",
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        code = sock.connect_ex((host, port))
        latency = (time.perf_counter() - start) * 1000.0

        if code == 0:
            result["state"] = "open"
            result["latency_ms"] = round(latency, 2)
            result["banner"] = _grab_banner(sock, port, timeout)
        else:
            # connect_ex devolvió un errno: puerto cerrado / rechazado.
            result["state"] = "closed"
    except socket.timeout:
        result["state"] = "filtered"
    except (socket.gaierror, OSError):
        # gaierror: no se pudo resolver el host. OSError: red inalcanzable, etc.
        result["state"] = "error"
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return result


def _grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
    """
    Intenta leer un banner del servicio ya conectado.

    Muchos servicios (SSH, FTP, SMTP, ...) envían una cabecera nada más
    conectar. Para HTTP hace falta provocar respuesta con una petición.
    Es un intento "best effort": si no llega nada, se devuelve "".
    """
    try:
        sock.settimeout(min(timeout, 2.0))
        if port in _HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(256)
        text = data.decode("utf-8", errors="replace")
        # Compactamos a una sola línea legible.
        return " ".join(text.split())[:200]
    except (socket.timeout, OSError):
        return ""


# ---------------------------------------------------------------------------
# Escaneo concurrente de múltiples objetivos/puertos
# ---------------------------------------------------------------------------
def scan_targets(
    hosts: list[str],
    ports: list[int],
    timeout: float = 1.0,
    concurrency: int = 100,
    on_result: Callable[[dict], None] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    """
    Escanea todas las combinaciones (host, puerto) usando un pool de hilos.

    Parámetros de callback (opcionales), pensados para una UI en vivo:
      - on_result(res):       se llama por cada puerto ABIERTO encontrado.
      - on_progress(done,tot): se llama tras cada conexión terminada.
      - should_stop():        si devuelve True, se deja de recoger resultados
                              (cancelación best-effort).

    Devuelve la lista de resultados de los puertos abiertos.
    """
    tasks = [(host, port) for host in hosts for port in ports]
    total = len(tasks)
    if total > MAX_TASKS:
        raise ValueError(
            f"El escaneo generaría {total} conexiones y supera el límite de "
            f"{MAX_TASKS}. Reduce el rango de IPs o de puertos."
        )

    # Nunca lanzamos más hilos que tareas, ni menos de 1.
    workers = max(1, min(concurrency, total))
    open_results: list[dict] = []
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): (host, port)
            for host, port in tasks
        }
        for future in as_completed(futures):
            if should_stop and should_stop():
                # Cancelamos lo que aún no haya empezado. Lo que ya corre
                # terminará solo, pero dejamos de procesarlo.
                for pending in futures:
                    pending.cancel()
                break

            done += 1
            try:
                res = future.result()
            except Exception:  # noqa: BLE001 - un fallo puntual no aborta todo
                res = None

            if on_progress:
                on_progress(done, total)

            if res and res["state"] == "open":
                open_results.append(res)
                if on_result:
                    on_result(res)

    open_results.sort(key=lambda r: (r["host"], r["port"]))
    return open_results


# ---------------------------------------------------------------------------
# Uso por línea de comandos (opcional, para probar sin la web)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Escáner de puertos TCP (CLI).")
    parser.add_argument("target", help="IP, hostname, CIDR o rango con guion.")
    parser.add_argument("-p", "--ports", default="top", help="Puertos (def: top).")
    parser.add_argument("-t", "--timeout", type=float, default=1.0)
    parser.add_argument("-c", "--concurrency", type=int, default=100)
    args = parser.parse_args()

    hosts_ = parse_targets(args.target)
    ports_ = parse_ports(args.ports)
    print(f"Escaneando {len(hosts_)} host(s) x {len(ports_)} puerto(s)...\n")

    found = scan_targets(
        hosts_,
        ports_,
        timeout=args.timeout,
        concurrency=args.concurrency,
        on_result=lambda r: print(
            f"  [+] {r['host']}:{r['port']:<5} {r['service']:<16} "
            f"{r['latency_ms']} ms  {r['banner']}"
        ),
    )
    print(f"\nTerminado. {len(found)} puerto(s) abierto(s).")
