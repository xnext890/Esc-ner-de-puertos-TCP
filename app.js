/* =========================================================================
   app.js — lógica del frontend.

   Flujo:
     1) POST /api/scan          -> obtiene un job_id.
     2) Polling GET /api/scan/<id> cada POLL_MS -> actualiza UI en vivo.
     3) Al terminar (done|stopped|error) se detiene el polling.

   El escaneo corre en el servidor en segundo plano, así que la interfaz
   nunca se bloquea: solo va pintando lo que el servidor reporta.
   ========================================================================= */

const POLL_MS = 500;

// --- Referencias al DOM --------------------------------------------------
const $ = (id) => document.getElementById(id);

const targetEl      = $("target");
const portsEl       = $("ports");
const timeoutEl     = $("timeout");
const concEl        = $("concurrency");
const concValue     = $("concValue");
const scanBtn       = $("scanBtn");
const stopBtn       = $("stopBtn");
const portChips     = $("portChips");

const statusDot     = $("statusDot");
const readoutValue  = $("readoutValue");
const sweepBar      = $("sweepBar");
const progressText  = $("progressText");
const progressPct   = $("progressPct");

const statHosts     = $("statHosts");
const statScanned   = $("statScanned");
const statOpen      = $("statOpen");
const statTime      = $("statTime");

const portsBody     = $("portsBody");
const emptyState    = $("emptyState");

// --- Estado en cliente ---------------------------------------------------
let currentJob = null;   // id del trabajo activo
let pollTimer  = null;   // handle del setTimeout de polling
let renderedOpen = 0;    // cuántos puertos abiertos ya hemos pintado

// --- Interacciones del panel --------------------------------------------
concEl.addEventListener("input", () => {
  concValue.textContent = concEl.value;
});

// Chips de presets de puertos.
portChips.addEventListener("click", (e) => {
  const chip = e.target.closest(".chip");
  if (!chip) return;
  portsEl.value = chip.dataset.ports;
  syncChips();
});
portsEl.addEventListener("input", syncChips);

function syncChips() {
  const val = portsEl.value.trim();
  portChips.querySelectorAll(".chip").forEach((c) => {
    c.classList.toggle("is-active", c.dataset.ports === val);
  });
}

// Enter en los campos de texto lanza el escaneo.
[targetEl, portsEl].forEach((el) =>
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter") startScan();
  })
);

scanBtn.addEventListener("click", startScan);
stopBtn.addEventListener("click", stopScan);

// --- Arrancar un escaneo -------------------------------------------------
async function startScan() {
  if (currentJob) return; // ya hay uno en curso

  const payload = {
    target: targetEl.value.trim(),
    ports: portsEl.value.trim() || "top",
    timeout: parseFloat(timeoutEl.value) || 1.0,
    concurrency: parseInt(concEl.value, 10) || 100,
  };

  if (!payload.target) {
    flashReadout("falta objetivo", "error");
    targetEl.focus();
    return;
  }

  resetResults();
  setRunning(true);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || "No se pudo iniciar el escaneo.");
    }

    currentJob = data.job_id;
    statHosts.textContent = data.hosts;
    progressText.textContent = `Escaneando ${data.total} sondas…`;
    poll();
  } catch (err) {
    setRunning(false);
    progressText.textContent = err.message;
    flashReadout("error", "error");
  }
}

// --- Polling del estado --------------------------------------------------
async function poll() {
  if (!currentJob) return;

  try {
    const res = await fetch(`/api/scan/${currentJob}`);
    const job = await res.json();
    if (!res.ok) throw new Error(job.error || "Trabajo no encontrado.");

    updateProgress(job);
    appendNewOpenPorts(job.open);

    if (job.status === "running") {
      pollTimer = setTimeout(poll, POLL_MS);
    } else {
      finishScan(job);
    }
  } catch (err) {
    progressText.textContent = err.message;
    finishScan({ status: "error" });
  }
}

// --- Actualización de UI -------------------------------------------------
function updateProgress(job) {
  const pct = job.total > 0 ? Math.round((job.done / job.total) * 100) : 0;
  sweepBar.style.width = pct + "%";
  progressPct.textContent = pct + "%";
  statScanned.textContent = job.done;
  statOpen.textContent = job.open_count;
  statHosts.textContent = job.hosts;
  statTime.textContent = job.elapsed_s.toFixed(1) + "s";

  if (job.status === "running") {
    progressText.textContent = `Escaneando… ${job.done}/${job.total} sondas`;
  }
}

// Pinta solo los puertos nuevos (los que aún no estaban en la tabla).
function appendNewOpenPorts(openList) {
  for (let i = renderedOpen; i < openList.length; i++) {
    const r = openList[i];
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(r.host)}</td>
      <td class="port-num">${r.port}</td>
      <td class="svc">${escapeHtml(r.service)}</td>
      <td class="num latency">${r.latency_ms != null ? r.latency_ms + " ms" : "—"}</td>
      <td class="banner">${escapeHtml(r.banner || "")}</td>
    `;
    portsBody.appendChild(tr);
  }
  if (openList.length > 0) emptyState.classList.add("is-hidden");
  renderedOpen = openList.length;
}

// --- Fin del escaneo -----------------------------------------------------
function finishScan(job) {
  clearTimeout(pollTimer);
  setRunning(false);
  sweepBar.classList.remove("is-scanning");

  const map = {
    done:    ["done",  "completado"],
    stopped: ["idle",  "detenido"],
    error:   ["error", "error"],
  };
  const [dotState, label] = map[job.status] || ["idle", "en espera"];
  statusDot.dataset.state = dotState;
  readoutValue.textContent = label;

  if (job.status === "done") {
    sweepBar.style.width = "100%";
    progressPct.textContent = "100%";
    const n = renderedOpen;
    progressText.textContent =
      n === 0 ? "Escaneo completado · sin puertos abiertos"
              : `Escaneo completado · ${n} puerto(s) abierto(s)`;
  } else if (job.status === "stopped") {
    progressText.textContent = "Escaneo detenido por el usuario";
  }

  currentJob = null;
}

// --- Detener -------------------------------------------------------------
async function stopScan() {
  if (!currentJob) return;
  stopBtn.disabled = true;
  progressText.textContent = "Deteniendo…";
  try {
    await fetch(`/api/scan/${currentJob}/stop`, { method: "POST" });
  } catch (_) {
    /* el polling reflejará el estado final igualmente */
  }
}

// --- Helpers de estado visual -------------------------------------------
function setRunning(running) {
  scanBtn.disabled = running;
  stopBtn.disabled = !running;
  targetEl.disabled = portsEl.disabled = running;
  statusDot.dataset.state = running ? "running" : statusDot.dataset.state;
  if (running) {
    readoutValue.textContent = "escaneando";
    sweepBar.classList.add("is-scanning");
  }
}

function resetResults() {
  portsBody.innerHTML = "";
  renderedOpen = 0;
  emptyState.classList.remove("is-hidden");
  sweepBar.style.width = "0%";
  progressPct.textContent = "0%";
  ["statScanned", "statOpen"].forEach((id) => ($(id).textContent = "0"));
  statTime.textContent = "0.0s";
}

function flashReadout(text, state) {
  readoutValue.textContent = text;
  statusDot.dataset.state = state === "error" ? "error" : "idle";
}

// Evita inyección de HTML al pintar banners/hosts de fuentes externas.
function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

// Inicialización.
syncChips();
