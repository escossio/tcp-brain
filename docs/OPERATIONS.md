# OPERATIONS

Runbook operacional atual do `tcp-brain`.

## Topologia efetiva

```text
Cloudflare
-> Apache
-> /tcp-brain/ frontend estatico
-> /tcp-brain/api/ proxy reverso
-> 127.0.0.1:18091
-> tcp-brain.service
```

O backend em producao roda pelo `tcp-brain.service` a partir de:

```text
/srv/migrated-debian2/app-data/tcp-brain
```

O frontend publicado e servido por Apache a partir de:

```text
/srv/escossio-site/public/tcp-brain
```

## Componentes principais

- Source control: GitHub `main`.
- Runtime ativo: `/srv/migrated-debian2/app-data/tcp-brain`.
- Front publicado: `/srv/escossio-site/public/tcp-brain`.
- Service manager: `tcp-brain.service`.
- Backend local: `127.0.0.1:18091`.
- Configuracao de runtime: `/etc/tcp-brain/` e `systemd`.
- Snapshot do detector: diretorio indicado por `TCP_BRAIN_DETECTION_STATUS_DIR`.

## Service health

Service health responde a pergunta: "o backend esta vivo e respondendo HTTP?"

Checagens somente leitura:

```bash
systemctl status tcp-brain.service
ss -lntp | grep 18091
curl -i http://127.0.0.1:18091/api/health
curl -i -H 'Host: www.escossio.com' http://127.0.0.1/tcp-brain/api/health
curl -i https://www.escossio.com/tcp-brain/api/health
```

Um `200` em `/api/health` nao garante que o detector esteja atualizado.

## Detection freshness

Detection freshness responde a pergunta: "o detector produziu snapshot recente?"

Checagens somente leitura:

```bash
curl -sS https://www.escossio.com/tcp-brain/api/detection/latest
stat /srv/migrated-debian2/app-data/tcp-knowledge/detection/tcp_detection_status.json
python3 -m json.tool /srv/migrated-debian2/app-data/tcp-knowledge/detection/tcp_detection_status.json | head
```

Compare o mtime do arquivo e campos como `generated_at`, `detector_timestamp` e `detector_round_id` com a data atual. Nao ha limite universal documentado aqui; a interpretacao depende da cadencia operacional esperada do detector.

Se `/api/health` esta verde mas o snapshot e antigo, o backend esta saudavel e o problema esta na cadeia do detector.

## Frontend publicado

O frontend que o usuario ve nao e servido diretamente do checkout Git. Ele fica em:

```text
/srv/escossio-site/public/tcp-brain
```

Comparacao segura:

```bash
diff -qr public/tcp-brain /srv/escossio-site/public/tcp-brain
```

Nao sincronize automaticamente. Divergencias entre source, runtime e publicacao precisam ser revisadas antes de qualquer deploy.

## Apache

Na topologia observada, Apache atende `www.escossio.com` e publica:

- `/tcp-brain/` como frontend estatico;
- `/tcp-brain/api/` como proxy para `http://127.0.0.1:18091/api/`.

Checagens somente leitura:

```bash
apachectl -S
grep -R "tcp-brain\\|18091" /etc/apache2/sites-enabled /etc/apache2/sites-available
curl -I -H 'Host: www.escossio.com' http://127.0.0.1/tcp-brain/
curl -I -H 'Host: www.escossio.com' http://127.0.0.1/tcp-brain/api/health
```

## Cloudflare

Cloudflare deve ser tratado como camada externa de roteamento. O hostname comprovadamente ativo nesta auditoria documental foi:

```text
https://www.escossio.com/tcp-brain/
```

Foi observada uma rota antiga em configuracao local do Cloudflare para `tcp.escossio.com` apontando para `127.0.0.1:8091`. Como nao ha listener em `8091` na producao atual e o hostname nao resolveu no teste realizado, documente essa rota como `KNOWN STALE/BROKEN ROUTE` ate nova correcao operacional.

## Sequencia segura de diagnostico

1. Verifique `tcp-brain.service` sem reiniciar.
2. Verifique listener local em `18091`.
3. Teste `http://127.0.0.1:18091/api/health`.
4. Teste Apache local com `Host: www.escossio.com`.
5. Teste a rota publica `https://www.escossio.com/tcp-brain/api/health`.
6. Verifique `detection/latest` separadamente de `health`.
7. Verifique mtime e timestamp do snapshot do detector.
8. Compare frontend versionado e publicado se houver sintoma visual.
9. Leia logs recentes antes de qualquer tentativa de correcao.

## Smoke test atual

`scripts/smoke_tcp_brain.py` ainda usa `https://tcp.escossio.dev.br` e assets sem o prefixo `/tcp-brain` como defaults. Portanto:

```text
SMOKE_TEST_CURRENT_TOPOLOGY_COMPATIBLE=PARTIAL
```

Uma etapa futura deve ajustar o smoke test para aceitar a topologia atual como default ou documentar claramente o uso de `--base-url https://www.escossio.com/tcp-brain`.
