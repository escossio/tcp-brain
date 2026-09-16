# HISTORICAL DOCUMENT

Este documento descreve um estado anterior da infraestrutura e nao representa necessariamente a producao atual. Consulte README.md e docs/OPERATIONS.md para o estado vigente.

# DETECTION_RUNTIME_REENABLE

## 1. Motivo
Religar a geração do snapshot consolidado do detector do TCP Brain a partir do histórico vivo em `/srv/tcp/knowledge/events/tcp_brain_history.jsonl`, sem mexer em frontend, Apache, Cloudflare, DNS ou firewall.

## 2. Fonte de entrada
- histórico vivo: `/srv/tcp/knowledge/events/tcp_brain_history.jsonl`
- repo: `/srv/tcp-brain`
- script base: `/srv/tcp-brain/scripts/tcp_detection_engine.py`
- host monitorado configurado nesta rodada: `192.168.0.253`

## 3. Saída gerada
- snapshot oficial: `/srv/tcp/knowledge/detection/tcp_detection_status.json`
- diagnósticos persistentes por execução: `/srv/tcp/knowledge/detection/runs/tcp-detection-<timestamp>/`
- backup do snapshot anterior: `/root/backups/tcp-brain-detection-20260424-172924/tcp_detection_status.json.before`
- snapshot temporário validado antes da troca: `/tmp/tcp-brain-detection-test-20260424-172833/tcp_detection_status.json`

## 4. Comando e wrapper
Patch mínimo aplicado no detector:
- `--no-default-status-write` para permitir geração isolada sem escrever no caminho oficial
- `--focus-host` para parametrizar o host monitorado em vez de prender o relatório a `10.45.0.2`

Comando de teste validado:
```bash
/srv/vector/app/venv/bin/python /srv/tcp-brain/scripts/tcp_detection_engine.py \
  --source-file /srv/tcp/knowledge/events/tcp_brain_history.jsonl \
  --output-dir /tmp/tcp-brain-detection-test-20260424-172833 \
  --no-default-status-write \
  --focus-host 192.168.0.253
```

Wrapper implantado:
- `/usr/local/bin/tcp-brain-detection-run.sh`

Função do wrapper:
- gera os diagnósticos em `runs/`
- valida o JSON
- publica o snapshot oficial por troca atômica

## 5. Systemd service/timer
Arquivos criados:
- `/etc/systemd/system/tcp-brain-detection.service`
- `/etc/systemd/system/tcp-brain-detection.timer`

Configuração aplicada:
- service oneshot executa o wrapper
- timer com `OnBootSec=45s`
- timer com `OnUnitActiveSec=60s`
- `AccuracySec=10s`
- `Persistent=true`

Validação do timer:
- execução manual concluída com sucesso em `2026-04-24 17:30:06 -03`
- execução automática confirmada em `2026-04-24 17:31:08 -03`
- `generated_at` avançou para `2026-04-24T20:31:08.191769+00:00`

## 6. Validações
Validações de integridade:
- JSON temporário válido antes da troca oficial
- snapshot antigo preservado em backup
- snapshot oficial atualizado sem restart do `tcp-brain.service`

Validação local:
- `http://127.0.0.1:8091/api/detection/latest` retornou `200`
- passou a expor `generated_at` atual
- passou a expor `source_diagnostics_path` persistente em `runs/`

Validação pública:
- `https://www.escossio.com/tcp-brain/api/detection/latest` retornou `200`
- payload público refletiu o novo snapshot consolidado

Resumo do payload atual observado após o runtime:
- `monitored_host=192.168.0.253`
- `decision=monitoramento leve`
- `severity=medium`
- `monitored_host_risk_score=174.95`
- `detector_round_id=tcp-detection-20260424-203107Z`

## 7. Rollback
Se precisar reverter:
```bash
cp /root/backups/tcp-brain-detection-20260424-172924/tcp_detection_status.json.before \
  /srv/tcp/knowledge/detection/tcp_detection_status.json
systemctl disable --now tcp-brain-detection.timer
```

Se precisar reverter o código do detector sem usar reset destrutivo:
- restaurar a partir dos backups em `/root/backups/tcp-brain-detection-code-*`
- ou reverter localmente o commit `0bc19c2` de forma controlada

## 8. Pendências
- `STATUS.md` continua fora do Git por decisão operacional
- `docs/DATA_FLOW_DIAGNOSTIC_20260424-171600.md` continua fora do Git
- próxima rodada pode revisar se `192.168.0.253` deve permanecer fixo ou migrar para configuração explícita em env/systemd
- próxima rodada também pode refinar o detector para reduzir o peso do loopback `127.0.0.1` no ranking global de risco
