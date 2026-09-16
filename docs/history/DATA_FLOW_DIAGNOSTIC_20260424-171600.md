# HISTORICAL DOCUMENT

Este documento descreve um estado anterior da infraestrutura e nao representa necessariamente a producao atual. Consulte README.md e docs/OPERATIONS.md para o estado vigente.

# DATA FLOW DIAGNOSTIC

Data da auditoria: 2026-04-24
Host auditado: `debian2-1`
Repo: `/srv/tcp-brain`
Git HEAD local: `39be8a3`
Branch: `main`

## 1. Servicos envolvidos

| Componente | Máquina | Diretório | Serviço | Entrada | Saída | Dados gerados | Quem consome |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Captura bruta | `debian2-1` | `/var/log` | `tcp-sentinel-capture.service` | tráfego IP via `tcpdump -ni any -tt -s 0 -vv -l ip` | `/var/log/tcpdump.log` | linhas brutas de tcpdump | `tcp-sentinel.service` |
| Sentinela principal | `debian2-1` | `/usr/local/bin` + `/var/log` + `/var/lib/tcp-sentinel` | `tcp-sentinel.service` | `tail -F /var/log/tcpdump.log` | POST para `http://127.0.0.1:8091/api/tcp-explain`, logs em `/var/log/tcp-sentinel-alerts.log` e `/var/log/tcp-sentinel-events.log` | eventos textuais e JSON operacionais | operador humano, trilha operacional, `tcp-brain.service` |
| Receiver MikroTik | `debian2-1` | `/usr/local/bin` | `tcp-sentinel-receiver.service` | `tcpdump -i any udp port 37008 -l -nn` | POST para `http://127.0.0.1:8090/api/tcp-explain` | fluxo paralelo vindo de UDP/37008 | `tcp-explainer.service` |
| Explicador FastAPI | `debian2-1` | `/srv/tcp/explainer` -> `/srv/ferramentas/tcp-explainer` | `tcp-explainer.service` | chamadas HTTP em `127.0.0.1:8090` | explicações | respostas de tradução/explicação | `tcp-sentinel-receiver.service`, Apache do host |
| Backend TCP Brain | `debian2-1` | `/srv/tcp/brain` -> `/srv/tcp-brain` | `tcp-brain.service` | chamadas HTTP em `0.0.0.0:8091` | `/api/stats`, `/api/recent`, `/api/detection/latest`, `/api/tcp-explain` | cache semântico, contadores e histórico estruturado | frontend publicado no `agt01`, `tcp-sentinel.service` |
| Histórico estruturado | `debian2-1` | `/srv/tcp/knowledge/events` | writer interno do `tcp-brain` | chamadas em `/api/tcp-explain` | `tcp_brain_history.jsonl` + rotações `.jsonl.gz` em `retention/` | eventos estruturados de processamento | scripts offline como `tcp_detection_engine.py`, `tcp_gap_engine.py`, `analyze/export` |
| Detector offline | `debian2-1` | `/srv/tcp-brain/scripts` + `/srv/tcp/knowledge/detection` | nenhum serviço/timer ativo encontrado | `tcp_brain_history.jsonl` e retenção | `tcp_detection_status.json`, `tcp_detection_summary.json` e diagnósticos | snapshot consolidado do detector | `/api/detection/latest` |
| Frontend publicado | `agt01` | `/srv/escossio-site/public/tcp-brain` | estático via Apache | JS no navegador | fetch para `/tcp-brain/api/stats`, `/tcp-brain/api/recent`, `/tcp-brain/api/detection/latest` | UI renderizada | usuário final |
| Proxy Apache | `agt01` | `/etc/apache2/sites-available/escossio-portal.conf` | `apache2.service` | requisições `/tcp-brain/api/*` | proxy para `http://192.168.0.253:8091/api/*` | roteamento HTTP | frontend publicado |

## 2. Diretórios envolvidos

- Repo real do backend: `/srv/tcp-brain`
- Symlink operacional do backend: `/srv/tcp/brain -> /srv/tcp-brain`
- Front versionado: `/srv/tcp-brain/public/tcp-brain`
- Front publicado no portal: `agt01:/srv/escossio-site/public/tcp-brain`
- Histórico estruturado: `/srv/tcp/knowledge/events`
- Snapshot consolidado do detector: `/srv/tcp/knowledge/detection`
- Retenção do histórico: `/srv/tcp/knowledge/retention`
- Logs operacionais brutos: `/var/log/tcpdump.log`, `/var/log/tcp-sentinel-events.log`, `/var/log/tcp-sentinel-alerts.log`

## 3. Git status do /srv/tcp-brain

- `branch`: `main`
- `HEAD`: `39be8a3 Allow TCP Brain host/port configuration via environment`
- `origin/main`: `44b239b`
- branch local está `ahead` por 1 commit
- pendência atual: `STATUS.md` não rastreado
- `tcp_brain.py` está sem diff pendente nesta auditoria

## 4. Fontes de dados encontradas

### Banco PostgreSQL

Configuração ativa do serviço:
- host: `127.0.0.1`
- port: `5432`
- db: `tcp_brain`
- user: `tcp_brain`

Tabelas reais encontradas:
- `public.tcp_brain_counters`
- `public.tcp_brain_counters_kv`
- `public.tcp_brain_severity`
- `public.tcp_patterns`

Uso real pelo código atual:
- `tcp_patterns`: usado por `/api/recent`, `/api/stats` e `/api/tcp-explain`
- `tcp_brain_counters`: usado por `/api/stats` e `/api/tcp-explain`
- `tcp_brain_counters_kv`: existe, mas não é consultado no código atual
- `tcp_brain_severity`: existe, mas não é consultado no código atual

Evidência de volume real:
- `tcp_patterns` tem `287858` linhas
- amostra recente de `tcp_patterns.last_seen` estava em `2026-04-24 17:12:14-03`
- `tcp_brain_counters` contém contadores altos e cumulativos (`total_requests`, `cache_hits`, `ia_calls`)

### Arquivos persistidos em `/srv/tcp`

- `/srv/tcp/knowledge/events/tcp_brain_history.jsonl`
  - arquivo vivo, atualizado na auditoria
  - alimentado pelo writer interno do `tcp-brain`
- `/srv/tcp/knowledge/retention/tcp_brain_history-*.jsonl.gz`
  - retenção rotacionada do histórico estruturado
- `/srv/tcp/knowledge/detection/tcp_detection_status.json`
  - snapshot consolidado do detector
  - timestamp de conteúdo em `2026-03-28`, portanto antigo

### Logs operacionais fora de `/srv`

- `/var/log/tcpdump.log`
- `/var/log/tcp-sentinel-events.log`
- `/var/log/tcp-sentinel-alerts.log`

Esses logs são ativos e atuais, mas não são lidos diretamente pelos endpoints `stats` e `recent`.

## 5. Tabelas ou arquivos encontrados

### Tabelas relevantes

- `tcp_patterns`
  - guarda cache semântico por `pattern_hash`
  - campos observados: `pattern_hash`, `snippet`, `explanation`, `severity`, `hit_count`, `last_seen`, `created_at`, `upstream_calls`, `cost_brl`
- `tcp_brain_counters`
  - guarda contadores cumulativos do serviço
  - o endpoint atual usa pelo menos `total_requests`, `cache_hits`, `ia_calls`

### Arquivos relevantes

- `tcp_brain_history.jsonl`: histórico estruturado do processamento do endpoint `/api/tcp-explain`
- `tcp_detection_status.json`: estado consolidado do detector usado por `/api/detection/latest`
- `tcpdump.log`: captura bruta em tempo real
- `tcp-sentinel-events.log`: eventos JSON do sentinela
- `tcp-sentinel-alerts.log`: log textual operacional

### SQLite / JSON locais do repo

- não foram encontrados arquivos `.sqlite`, `.sqlite3` ou `.db` relevantes em `/srv/tcp-brain` ou `/srv/tcp`
- o storage real da API hoje é PostgreSQL + JSON/JSONL em `/srv/tcp/knowledge`

## 6. Origem de cada endpoint

### `/api/stats`

Função:
- `get_stats()` em `/srv/tcp-brain/tcp_brain.py`

Fluxo:
1. conecta no PostgreSQL via `db_conn()`
2. lê `tcp_brain_counters` (`SELECT * FROM tcp_brain_counters WHERE id = 1`)
3. conta linhas de `tcp_patterns`
4. agrupa severidades em `tcp_patterns`
5. calcula em memória `cache_misses`, `estimated_spend_brl`, `estimated_savings_brl`, `estimated_without_cache_brl` e `cache_hit_rate`

Leitura objetiva:
- origem: PostgreSQL real
- não lê `/srv/tcp`
- não lê JSON/JSONL
- não é mock
- é cumulativo, não windowed

Campos vistos ao vivo:
- `total_hits`, `total_requests`, `cache_hits`, `cache_misses`, `ia_calls`, `upstream_calls`, `patterns_total`, `new_patterns`, `severity_counts`, `cache_hit_rate`, `estimated_*`

### `/api/recent`

Função:
- `get_recent()` em `/srv/tcp-brain/tcp_brain.py`

Fluxo:
1. conecta no PostgreSQL via `db_conn()`
2. executa `SELECT snippet, explanation, severity, TO_CHAR(last_seen, ...) FROM tcp_patterns ORDER BY last_seen DESC LIMIT 15`
3. retorna lista JSON

Leitura objetiva:
- origem: PostgreSQL real
- não lê `/srv/tcp`
- não lê JSON/JSONL
- não é mock
- mostra padrões mais recentemente tocados (`last_seen`), não um stream bruto de eventos

Campos vistos ao vivo:
- `snippet`, `explanation`, `severity`, `last_seen`

### `/api/detection/latest`

Função:
- `get_detection_latest()` em `/srv/tcp-brain/tcp_brain.py`

Fluxo:
1. chama `load_latest_detection_status()`
2. `load_latest_detection_status()` chama `_choose_latest_detection_source()`
3. se existir `/srv/tcp/knowledge/detection/tcp_detection_status.json`, esse arquivo tem prioridade imediata
4. o endpoint lê esse JSON e devolve o payload
5. se o arquivo não existir, pode tentar derivar de `tcp_detection_summary.json` em `DETECTION_STATUS_DIR` ou em `/codex/diagnostics`
6. se nada existir, devolve `503` com `detector_status=unavailable`

Leitura objetiva:
- origem: snapshot JSON persistido em `/srv/tcp/knowledge/detection/tcp_detection_status.json`
- consulta `/srv/tcp`, não o banco
- não recalcula na hora
- não é mock, mas hoje está stale

Evidência de staleness:
- `detector_timestamp`: `2026-03-28T07:08:04+00:00`
- `generated_at`: `2026-03-28T07:08:11.851972+00:00`
- `source_summary_path`: `/codex/diagnostics/tcp-detection-operational-badge-20260328-040804/tcp_detection_summary.json`

## 7. Origem dos números do frontend

No front publicado em `agt01:/srv/escossio-site/public/tcp-brain/js/`:
- `main.js` chama:
  - `updateStats()` a cada 2s
  - `updateRecent()` a cada 3s
  - `updateDetection()` a cada 15s

As chamadas do browser são:
- `/tcp-brain/api/stats`
- `/tcp-brain/api/recent`
- `/tcp-brain/api/detection/latest`

No `agt01`, o Apache faz:
- `ProxyPass /tcp-brain/api/ http://192.168.0.253:8091/api/`

Portanto:
- o HTML/JS vem do `agt01`
- os números vêm do backend `tcp-brain` no `debian2-1`

Mapeamento visual:
- card de estatísticas: usa `total_hits`, `cache_hit_rate`, `ia_calls`, `estimated_savings_brl`
- live feed recente: usa `severity`, `last_seen`, `snippet`, `explanation`
- card do detector: usa `monitored_host_decision`, `monitored_host_risk_score`, `primary_signal`, `key_reasons`, `candidate_flags`, `top_peers`, `top_ports`, `temporal_summary`

## 8. Diagnóstico do que está pobre

Classificação:
- `B. Coleta existe, mas é rasa`
  - existe captura bruta contínua e há histórico estruturado, mas o caminho consolidado do detector não está ativo em produção
- `C. Dados existem, mas API expõe pouco`
  - `/api/stats` é só cumulativo; não expõe janelas, taxa recente, nem visão por fonte
- `D. API expõe dados, mas frontend mostra pouco`
  - o front consome poucos campos de `stats` e só a parte consolidada de `detection`
- `F. Dados estão antigos`
  - `/api/detection/latest` devolve snapshot de `2026-03-28`, muito anterior ao feed vivo
- `G. Serviço de coleta está parado/falhando`
  - não há serviço/timer ativo encontrado para `tcp_detection_engine.py`; o gerador do snapshot consolidado está ausente do runtime
- `H. Falta integração entre /srv/tcp e /srv/tcp-brain`
  - `/srv/tcp/knowledge/events/tcp_brain_history.jsonl` é atualizado, mas não existe rotina ativa publicando novo `tcp_detection_status.json`

Leitura final do estado atual:
- `stats`: vivo e real
- `recent`: vivo e real
- `detection/latest`: real, porém órfão/antigo

## 9. Próxima proposta de melhoria

Antes de mexer em coleta, a próxima rodada deve focar em:
1. religar de forma controlada a geração do snapshot consolidado do detector a partir de `/srv/tcp/knowledge/events/tcp_brain_history.jsonl`
2. decidir se isso vira `systemd service`, `timer` ou job manual controlado
3. só depois melhorar a profundidade dos campos expostos em `/api/stats` e no front

Diretório-alvo recomendado da próxima rodada:
- código principal: `/srv/tcp-brain/scripts/tcp_detection_engine.py`
- ponto de integração de publicação: `/srv/tcp/knowledge/detection`
- se precisar de runtime: units em `/etc/systemd/system/` para um gerador do detector
