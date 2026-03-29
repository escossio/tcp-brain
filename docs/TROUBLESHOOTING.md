# TROUBLESHOOTING

Guia curto para diagnostico rapido do `tcp-brain`.

## 1. Card do detector preso em "carregando"

Possiveis causas:

- backend fora do ar
- `/api/detection/latest` retornando erro ou payload incompleto
- dashboard apontando para assets antigos

Checagens diretas:

```bash
curl -fsS https://tcp.escossio.dev.br/api/health
curl -fsS https://tcp.escossio.dev.br/api/detection/latest
curl -fsS https://tcp.escossio.dev.br/dashboard | grep -n "Detector consolidado"
```

## 2. `/api/detection/latest` falhando

Possiveis causas:

- banco indisponivel
- dados de detector ausentes
- backend travado em dependencia externa

Checagens diretas:

```bash
curl -i https://tcp.escossio.dev.br/api/detection/latest
curl -i https://tcp.escossio.dev.br/api/health
python3 /srv/tcp-brain/scripts/smoke_tcp_brain.py
```

Se `health` estiver verde e `detection/latest` falhar, o problema costuma estar na consolidacao do detector e nao na publicacao do front.

## 3. Assets do front nao carregando

Sintomas:

- dashboard abre, mas sem estilo
- JS nao inicializa o card
- console do navegador mostra 404 ou MIME type inesperado

Checagens diretas:

```bash
curl -I https://tcp.escossio.dev.br/css/main.css
curl -I https://tcp.escossio.dev.br/js/main.js
python3 /srv/tcp-brain/scripts/smoke_tcp_brain.py
```

O esperado e `HTTP 200` com `Content-Type` plausivel para CSS e JS.

## 4. Divergencia entre front versionado e front publicado

Possiveis causas:

- arquivo atualizado em `/srv/tcp-brain/public/tcp-brain`, mas nao copiado para `/srv/escossio-site/public/tcp-brain`
- Apache servindo uma copia antiga
- cache intermediario segurando asset velho

Checagens diretas:

```bash
diff -qr /srv/tcp-brain/public/tcp-brain /srv/escossio-site/public/tcp-brain
ls -l /srv/tcp-brain/public/tcp-brain/css/main.css /srv/escossio-site/public/tcp-brain/css/main.css
ls -l /srv/tcp-brain/public/tcp-brain/js/main.js /srv/escossio-site/public/tcp-brain/js/main.js
```

## 5. Confusao entre Apache, backend e tunnel

Regra pratica:

- Apache em `127.0.0.1:8080` entrega front e faz proxy de `/api/`
- backend em `127.0.0.1:8091` responde a API
- Cloudflare Tunnel expõe o Apache

Checagens diretas:

```bash
curl -I http://127.0.0.1:8080/dashboard
curl -I http://127.0.0.1:8080/api/health
curl -I http://127.0.0.1:8091/api/health
```

Se o backend local responder e o Apache nao, a falha esta na camada de publicacao, nao no detector.

## Comandos uteis

```bash
python3 /srv/tcp-brain/scripts/smoke_tcp_brain.py
curl -fsS https://tcp.escossio.dev.br/api/detection/latest | jq
curl -I https://tcp.escossio.dev.br/css/main.css
curl -I https://tcp.escossio.dev.br/js/main.js
```

## Quando parar e escalar

Escale se houver:

- `health` verde, mas `detection/latest` quebra de forma persistente
- assets 200 no disco, mas 404/500 no dominio publico
- divergencia repetida entre o front versionado e o front publicado
- Apache ok, backend ok localmente, mas o dominio publico continua errado
