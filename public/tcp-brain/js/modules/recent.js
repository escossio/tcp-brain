function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export async function updateRecent() {
  const root = document.getElementById("recent-list");
  if (!root) return;

  try {
    const resp = await fetch("/api/recent", { cache: "no-store" });
    const data = await resp.json();
    if (!Array.isArray(data)) {
      root.innerHTML = '<div class="tb-muted">Sem feed recente.</div>';
      return;
    }

    root.innerHTML = data.slice(0, 10).map((item) => {
      const sev = String(item.severity || "unknown").toLowerCase();
      const cls = sev === "high" ? "severity-high" : sev === "medium" ? "severity-medium" : "severity-low";
      return `
        <div class="live-card ${cls}">
          <div><strong>${escapeHtml(item.severity || "unknown")}</strong> • ${escapeHtml(item.last_seen || "")}</div>
          <div class="snippet">${escapeHtml(item.snippet || "")}</div>
          <div>${escapeHtml(item.explanation || "")}</div>
        </div>
      `;
    }).join("");
  } catch {
    root.innerHTML = '<div class="tb-muted">Live feed indisponível.</div>';
  }
}
