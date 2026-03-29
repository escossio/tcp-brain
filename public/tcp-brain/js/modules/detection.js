function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setList(id, items, formatter) {
  const el = document.getElementById(id);
  if (!el) return;
  if (!items || !items.length) {
    el.innerHTML = '<li class="tb-muted">Sem dados.</li>';
    return;
  }
  el.innerHTML = items
    .map((item) => `<li>${escapeHtml(formatter(item))}</li>`)
    .join("");
}

function setFlags(flags) {
  const el = document.getElementById("detector-flags");
  if (!el) return;
  if (!flags || !flags.length) {
    el.innerHTML = '<span class="tb-muted">Sem flags candidatas.</span>';
    return;
  }
  el.innerHTML = flags
    .map((flag) => `<span class="tb-chip">${escapeHtml(flag)}</span>`)
    .join(" ");
}

function setTemporalSummary(summary) {
  const labelEl = document.getElementById("detector-trend-label");
  const decisionEl = document.getElementById("detector-trend-decision");
  const badgeEl = document.getElementById("detector-operational-badge");
  const summaryEl = document.getElementById("detector-temporal-summary");
  const lastWindowEl = document.getElementById("detector-last-window-summary");
  const windowsEl = document.getElementById("detector-temporal-windows");

  if (!labelEl || !decisionEl || !summaryEl || !lastWindowEl || !windowsEl) return;

  if (!summary) {
    labelEl.textContent = "sem histórico temporal consolidado";
    decisionEl.textContent = "estado neutro";
    if (badgeEl) badgeEl.textContent = "em observação";
    summaryEl.textContent = "Sem histórico temporal consolidado nesta rodada.";
    lastWindowEl.textContent = "Sem resumo da última janela.";
    windowsEl.innerHTML = '<li class="tb-muted">Sem janelas temporais disponíveis.</li>';
    return;
  }

  labelEl.textContent = summary.trend_label || "estável";
  decisionEl.textContent = summary.trend_decision || "monitoramento leve";
  if (badgeEl) badgeEl.textContent = summary.operational_badge || summary.trend_label || "estável";
  summaryEl.textContent = summary.interpretation || "Resumo temporal disponível.";
  lastWindowEl.textContent = summary.last_window_summary || "Sem resumo da última janela.";

  const windows = Array.isArray(summary.windows) ? summary.windows : [];
  if (!windows.length) {
    windowsEl.innerHTML = '<li class="tb-muted">Sem janelas temporais disponíveis.</li>';
    return;
  }

  windowsEl.innerHTML = windows
    .map((w) => {
      const peer = w.top_peer ? ` • peer ${escapeHtml(w.top_peer)}` : "";
      const family = w.top_family ? ` • família ${escapeHtml(w.top_family)}` : "";
      return `<li><strong>${escapeHtml(w.label || "janela")}</strong> — score ${Number(w.score || 0).toFixed(2)} • udp_probe ${Number(w.udp_probe || 0)} • peers ${Number(w.unique_peers || 0)} • portas ${Number(w.unique_ports || 0)}${peer}${family}</li>`;
    })
    .join("");
}

function setStatusPill(state, kind = "muted") {
  const pill = document.getElementById("detector-status-pill");
  if (!pill) return;
  pill.classList.remove("tb-pill-muted", "tb-pill-ok", "tb-pill-warn", "tb-pill-bad");
  pill.classList.add(`tb-pill-${kind}`);
  pill.textContent = state;
}

export async function updateDetection() {
  try {
    const resp = await fetch("/api/detection/latest", { cache: "no-store" });
    const data = await resp.json();

    if (!resp.ok || data.detector_status === "unavailable") {
      setStatusPill("indisponível", "bad");
      setText("detector-state", "sem dados");
      setText("detector-decision", "aguardando");
      setText("detector-host", "—");
      setText("detector-score", "—");
      setText("detector-signal", "—");
      setText("detector-round", "—");
      setText("detector-origin", data.message || "Detector offline indisponível no momento.");
      setList("detector-reasons", [], () => "");
      setList("detector-peers", [], () => "");
      setList("detector-ports", [], () => "");
      setFlags([]);
      return;
    }

    const signal = data.primary_signal || {};
    const host = data.monitored_host || "—";
    const score = Number(data.monitored_host_risk_score || 0);
    const state = data.detector_status || "ok";
    const decision = data.monitored_host_decision || data.decision || "monitoramento leve";
    const alertState = data.alert_state || "sem alerta persistente";

    setStatusPill(state, state === "ok" ? "ok" : "warn");
    setText("detector-state", `${state} • ${alertState}`);
    setText("detector-decision", decision);
    setText("detector-host", host);
    setText("detector-score", score ? score.toFixed(2) : "0.00");
    setText("detector-signal", signal.label || signal.name || "—");
    setText("detector-round", data.detector_round_id || "—");
    setText(
      "detector-origin",
      [
        data.source_diagnostics_path ? `Origem: ${data.source_diagnostics_path}` : null,
        data.detector_timestamp ? `Rodada: ${data.detector_timestamp}` : null,
        data.monitored_host_status ? `Host: ${data.monitored_host_status}` : null,
      ]
        .filter(Boolean)
        .join(" • ")
    );

    setList("detector-reasons", data.key_reasons || [], (item) => item);
    setFlags(data.candidate_flags || []);
    setTemporalSummary(data.temporal_summary || null);
    setList("detector-peers", data.top_peers || [], (item) => {
      const peer = item.peer || "—";
      const events = Number(item.events || 0);
      const ports = (item.top_ports || [])
        .slice(0, 2)
        .map((p) => `${p.port}:${p.count}`)
        .join(", ");
      return `${peer} — ${events} eventos${ports ? ` — portas ${ports}` : ""}`;
    });
    setList("detector-ports", data.top_ports || [], (item) => `${item.port}: ${item.count}`);
  } catch {
    setStatusPill("erro", "bad");
    setText("detector-state", "erro • indisponível");
    setText("detector-decision", "indisponível");
    setText("detector-host", "—");
    setText("detector-score", "—");
    setText("detector-signal", "—");
    setText("detector-round", "—");
    setText("detector-origin", "Não foi possível ler o estado consolidado do detector.");
    setList("detector-reasons", [], () => "");
    setList("detector-peers", [], () => "");
    setList("detector-ports", [], () => "");
    setTemporalSummary(null);
    setFlags([]);
  }
}
