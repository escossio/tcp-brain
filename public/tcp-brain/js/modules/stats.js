function formatMoney(value) {
  return new Intl.NumberFormat("pt-BR", {
    style: "currency",
    currency: "BRL",
  }).format(Number(value || 0));
}

export async function updateStats() {
  try {
    const resp = await fetch("/api/stats", { cache: "no-store" });
    const data = await resp.json();
    const totalHits = document.getElementById("total-hits");
    const hitRate = document.getElementById("hit-rate");
    const iaCalls = document.getElementById("ia-calls");
    const savings = document.getElementById("savings");

    if (totalHits) totalHits.textContent = String(data.total_hits ?? data.total_requests ?? 0);
    if (hitRate) hitRate.textContent = `${Math.round((Number(data.cache_hit_rate || 0) * 100))}%`;
    if (iaCalls) iaCalls.textContent = String(data.ia_calls ?? data.upstream_calls ?? 0);
    if (savings) savings.textContent = formatMoney(data.estimated_savings_brl ?? 0);
  } catch {
    // Mantém os valores atuais em caso de falha.
  }
}
