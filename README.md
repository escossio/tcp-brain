# tcp-brain

`tcp-brain` é o backend do detector consolidado de TCP e o front do painel operacional usado para acompanhar o estado do sistema.

## Componentes

- `tcp_brain.py`: API principal em FastAPI.
- `tcp_history.py`: writer estruturado do histórico de eventos.
- `scripts/`: utilitários de backfill, análise, exportação e engine de detecção.
- `public/tcp-brain/`: front estático do dashboard.

## Estrutura

- `tcp_brain.py`
- `tcp_history.py`
- `scripts/`
- `public/tcp-brain/`
- `.gitignore`

## Endpoints principais

- `GET /`: front do painel quando o front está disponível localmente.
- `GET /dashboard`: dashboard consolidado.
- `GET /api/health`: healthcheck da API.
- `GET /api/stats`: métricas agregadas do cache e do uso da IA.
- `GET /api/recent`: últimos padrões observados.
- `GET /api/detection/latest`: leitura consolidada do detector.
- `POST /api/tcp-explain`: explicação de snippets TCP com cache + upstream.

## Relação entre front e backend

- O backend procura primeiro o front local em `public/tcp-brain/`.
- Em produção, o site público é servido por Apache + Cloudflare Tunnel.
- A publicação atual está estabilizada em `Cloudflare Tunnel -> Apache 127.0.0.1:8080 -> front estático + proxy /api/ -> backend 127.0.0.1:8091`.

## Execução local

1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
2. Ajuste as variáveis de ambiente do banco e do upstream, se necessário.
3. Inicie a API:
   ```bash
   uvicorn tcp_brain:app --host 127.0.0.1 --port 8091
   ```

## Observações operacionais

- O detector consolidado pode operar sem payload disponível; nesse caso, `/api/detection/latest` retorna estado `unavailable`.
- O painel foi desenhado para consumir o endpoint consolidado e manter o bloco do detector visível mesmo quando o resumo está indisponível.
- O histórico estruturado é gravado por `tcp_history.py` em diretórios sob `/srv/tcp/knowledge/`.
