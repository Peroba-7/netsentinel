# NetSentinel

Plataforma de análise de incidentes de segurança com IA local. Um analista submete um incidente, um modelo a correr no Ollama classifica o risco e escreve um parecer, e o resultado fica guardado para consulta, relatório e resposta. Os dados dos incidentes não saem da sua infraestrutura.

## Arquitetura

```
Dashboard (Streamlit :8501)
        │  X-API-Key
        ▼
API (FastAPI :8000) ──► LangGraph ──► Ollama (modelo local)
        │
        ├──► PostgreSQL   incidentes e IPs bloqueados
        ├──► Redis        limite de pedidos
        └──► n8n          automações, alertas e bloqueios
             Discord / Telegram   alertas de risco ALTO e CRÍTICO (opcional)
```

## Início rápido com Docker

```bash
cp .env.example .env    # preencha API_KEY e POSTGRES_PASSWORD
docker compose up -d --build
```

| Serviço | Endereço |
|---|---|
| Dashboard | http://localhost:8501 |
| Documentação da API | http://localhost:8000/docs |
| n8n | http://localhost:5678 |

Todas as portas ficam acessíveis apenas nesta máquina (`127.0.0.1`). Na primeira execução, o serviço `ollama-pull` descarrega o modelo definido em `OLLAMA_MODEL`, o que pode demorar vários minutos.

## Desenvolvimento local

Com PostgreSQL e Ollama a correr:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements-dev.txt

uvicorn app.main:app --reload       # API
streamlit run dashboard.py          # dashboard, noutro terminal

pytest                              # testes
ruff check .                        # análise estática
```

## API

Todas as rotas `/threats` exigem o cabeçalho `X-API-Key`.

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/` | Verifica se a API está ativa |
| `GET` | `/health` | Estado da base de dados, Redis e Ollama |
| `POST` | `/threats/analyze` | Analisa e guarda um incidente |
| `GET` | `/threats/` | Lista incidentes (`limit`, `offset`) |
| `GET` | `/threats/blocked` | Lista os IPs com bloqueio pedido |
| `POST` | `/threats/block` | Regista um bloqueio e envia o pedido ao n8n |

## Bloqueio de IPs

**A API não altera nenhuma firewall.** O bloqueio é registado e enviado ao n8n como evento; a alteração na firewall tem de ser feita por um workflow seu.

Crie no n8n um workflow ativo com um webhook no caminho `netsentinel`. Ele recebe dois eventos:

```json
{"event": "threat.analyzed", "id": 1, "ip_address": "203.0.113.7", "risk_level": "ALTO", "...": "..."}
{"event": "ip.block", "ip_address": "203.0.113.7", "reason": null}
```

Se o n8n não aceitar o pedido, o IP fica com `dispatched: false`, o dashboard mostra um aviso e o pedido pode ser repetido.

## Configuração

Todas as variáveis estão documentadas em [.env.example](.env.example). A aplicação não arranca sem `API_KEY` (mínimo de 16 caracteres) e `DATABASE_URL`.

## Antes de expor fora desta máquina

O dashboard não tem login: quem o abrir pode submeter incidentes e pedir bloqueios. Mantenha as portas em `127.0.0.1`, ou coloque-o atrás de um proxy com autenticação e HTTPS.
