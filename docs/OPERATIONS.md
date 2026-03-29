# OPERACOES

Documento curto para operação do `tcp-brain`.

## Fluxo de publicacao

1. O front canônico fica em `/srv/escossio-site/public/tcp-brain`.
2. O repo versionado fica em `/srv/tcp-brain/public/tcp-brain`.
3. O Apache escuta em `127.0.0.1:8080`.
4. O Apache serve o front estatico e faz proxy de `/api/` para o backend em `127.0.0.1:8091`.
5. O Cloudflare Tunnel aponta para o Apache, nao diretamente para o backend.

## Componentes principais

- Front canônico: `/srv/escossio-site/public/tcp-brain`
- Front versionado: `/srv/tcp-brain/public/tcp-brain`
- Smoke test: `/srv/tcp-brain/scripts/smoke_tcp_brain.py`
- Backend principal: `tcp_brain.py`
- Endpoint de detector consolidado: `/api/detection/latest`

## Validacao minima

Use esta ordem para checagem rapida:

1. `GET /api/health`
2. `GET /api/detection/latest`
3. `GET /dashboard`
4. `GET /css/main.css`
5. `GET /js/main.js`

Se o `dashboard` abrir mas os assets falharem, o problema tende a ser de publicacao do front, nao do backend.

## Smoke test

Execute:

```bash
python3 /srv/tcp-brain/scripts/smoke_tcp_brain.py
```

Opcionalmente:

```bash
python3 /srv/tcp-brain/scripts/smoke_tcp_brain.py --base-url https://tcp.escossio.dev.br --timeout 20
```

O smoke test falha com exit code diferente de zero se qualquer checagem critica falhar.

## Caminhos importantes

- `README.md`: resumo e entrada rapida
- `docs/OPERATIONS.md`: fluxo operacional
- `docs/TROUBLESHOOTING.md`: falhas comuns e checagens
- `scripts/smoke_tcp_brain.py`: validacao operacional
- `public/tcp-brain/index.html`: pagina base do front
- `public/tcp-brain/css/main.css`: estilo principal
- `public/tcp-brain/js/main.js`: boot do front
- `public/tcp-brain/js/modules/`: modulos do dashboard

## Endpoints principais

- `/api/health`
- `/api/stats`
- `/api/recent`
- `/api/detection/latest`
- `/api/tcp-explain`
- `/dashboard`

## Observacao operacional

Se houver divergencia entre o front versionado e o front publicado, o sintoma tipico e o dashboard carregar HTML antigo ou assets inconsistentes mesmo com `/api/health` verde.
