# TROUBLESHOOTING

Guia de diagnostico para a topologia atual do `tcp-brain`.

## 1. Backend 18091 indisponivel

Sintomas:

- `/tcp-brain/api/health` retorna `502`, `503` ou timeout;
- Apache responde, mas API falha;
- nao ha listener em `127.0.0.1:18091`.

Checagens somente leitura:

```bash
systemctl status tcp-brain.service
systemctl show tcp-brain.service -p MainPID -p ExecStart -p EnvironmentFiles
ss -lntp | grep 18091
curl -i http://127.0.0.1:18091/api/health
```

Nao reinicie o servico durante diagnostico forense sem autorizacao explicita.

## 2. Apache saudavel, API falhando

Sintomas:

- `/tcp-brain/` carrega;
- `/tcp-brain/api/health` falha;
- backend direto pode ou nao responder.

Checagens:

```bash
curl -I -H 'Host: www.escossio.com' http://127.0.0.1/tcp-brain/
curl -i -H 'Host: www.escossio.com' http://127.0.0.1/tcp-brain/api/health
grep -R "tcp-brain/api\\|18091" /etc/apache2/sites-enabled /etc/apache2/sites-available
```

Se o backend direto responde e a rota Apache falha, o problema esta na publicacao/proxy, nao no detector.

## 3. Frontend antigo ou divergente

Sintomas:

- UI nao reflete o codigo em GitHub `main`;
- navegador carrega assets antigos;
- HTML, JS e CSS parecem fora de sincronia.

Checagens:

```bash
diff -qr public/tcp-brain /srv/escossio-site/public/tcp-brain
find /srv/escossio-site/public/tcp-brain -maxdepth 3 -type f -printf '%p %s %TY-%Tm-%Td %TH:%TM:%TS\n'
curl -I https://www.escossio.com/tcp-brain/
curl -I https://www.escossio.com/tcp-brain/js/main.js
```

GitHub `main`, runtime e frontend publicado sao autoridades diferentes. Merge em `main` nao publica automaticamente assets.

## 4. Detector stale

Sintomas:

- `/tcp-brain/api/health` retorna `200`;
- `/tcp-brain/api/detection/latest` retorna dados antigos;
- `generated_at`, `detector_timestamp` ou mtime do snapshot estao muito atrasados.

Checagens:

```bash
curl -sS https://www.escossio.com/tcp-brain/api/detection/latest
stat /srv/migrated-debian2/app-data/tcp-knowledge/detection/tcp_detection_status.json
python3 -m json.tool /srv/migrated-debian2/app-data/tcp-knowledge/detection/tcp_detection_status.json | head -40
systemctl list-units 'tcp-brain*detection*'
systemctl list-timers 'tcp-brain*detection*'
```

Health verde nao implica detector fresco. Trate o detector como componente separado.

## 5. Ausencia de service/timer do detector

Se nao houver unit/timer ativo para o detector, isso explica snapshots antigos sem indicar falha do backend.

Checagens:

```bash
systemctl list-unit-files 'tcp-brain*detection*'
systemctl list-timers --all | grep -i tcp
find /srv/migrated-debian2/app-data/tcp-knowledge/detection -maxdepth 2 -type f -printf '%p %TY-%Tm-%Td %TH:%TM:%TS\n'
```

Nao reative timer ou service sem uma etapa operacional propria.

## 6. Cloudflare apontando para destino incorreto

Sintomas:

- dominio publico especifico nao resolve;
- rota publica aponta para porta sem listener;
- `www.escossio.com/tcp-brain` funciona, mas `tcp.escossio.com` nao.

Estado observado:

- `www.escossio.com/tcp-brain` esta ativo.
- `tcp.escossio.com` aparece em configuracao local do Cloudflare apontando para `127.0.0.1:8091`, que e rota `KNOWN STALE/BROKEN ROUTE` para a producao atual.
- `tcp.escossio.dev.br` nao deve ser assumido como ativo sem novo teste.

Checagens:

```bash
grep -R "tcp.escossio\\|www.escossio.com\\|8091\\|18091" /etc/cloudflared
curl -I https://www.escossio.com/tcp-brain/
curl -I https://www.escossio.com/tcp-brain/api/health
```

## 7. Erro PostgreSQL

Sintomas:

- `/api/stats` ou `/api/recent` falham;
- logs mostram erro de conexao ou schema;
- `/api/health` ainda pode responder.

Checagens sem imprimir credenciais:

```bash
systemctl show tcp-brain.service -p EnvironmentFiles
grep -E 'TCP_BRAIN_DB_|TCP_BRAIN_DB_DSN' /etc/tcp-brain/tcp-brain.env | sed -E 's/=.*/=SET/'
journalctl -u tcp-brain.service --since '1 hour ago' --no-pager
```

Nao execute migrations, `ensure_schema` manual, backfills ou DDL durante diagnostico.

## 8. Assets com cache antigo

Sintomas:

- navegador continua buscando JS/CSS antigo;
- modulo JS nao bate com `index.html`;
- console mostra import quebrado.

Checagens:

```bash
grep -n "main.js" public/tcp-brain/index.html /srv/escossio-site/public/tcp-brain/index.html
grep -n "modules/" public/tcp-brain/js/main.js /srv/escossio-site/public/tcp-brain/js/main.js
curl -I 'https://www.escossio.com/tcp-brain/js/main.js?v=20260428-2'
```

Cache-busting com querystring so ajuda quando a versao publicada realmente mudou. Ele nao substitui uma publicacao consistente do frontend.

## 9. Referencias legadas

Referencias a `127.0.0.1:8091`, `/srv/tcp-brain` e `/srv/tcp/knowledge/detection` podem aparecer em documentos historicos, defaults de codigo ou backups. Na producao atual observada:

- backend efetivo: `127.0.0.1:18091`;
- runtime efetivo: `/srv/migrated-debian2/app-data/tcp-brain`;
- detector efetivo: path configurado por `TCP_BRAIN_DETECTION_STATUS_DIR`.
