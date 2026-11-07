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

**O projeto funciona em modo de simulação: nenhuma firewall é alterada.** A API regista o bloqueio e envia-o ao n8n, que valida o IP, escreve no log e responde `bloqueado (simulado)`. O dashboard mostra esse estado tal como o workflow o devolve.

O workflow está em [n8n/netsentinel-block-simulation.json](n8n/netsentinel-block-simulation.json). Para o instalar num ambiente novo:

```bash
docker cp n8n/netsentinel-block-simulation.json netsentinel-n8n:/tmp/wf.json
docker exec netsentinel-n8n n8n import:workflow --input=/tmp/wf.json
docker exec netsentinel-n8n n8n publish:workflow --id=netsentinelBlockSim
docker compose restart n8n
```

Para ver os bloqueios registados:

```bash
docker logs netsentinel-n8n 2>&1 | grep NETSENTINEL-BLOCK
```

O webhook `netsentinel` recebe dois eventos:

```json
{"event": "threat.analyzed", "id": 1, "ip_address": "203.0.113.7", "risk_level": "ALTO", "...": "..."}
{"event": "ip.block", "ip_address": "203.0.113.7", "reason": null}
```

Se o n8n não aceitar o pedido, o IP fica com `dispatched: false`, o dashboard mostra um aviso e o pedido pode ser repetido.

### Trocar a simulação por uma firewall real

Só o nó **Firewall (SIMULADO)** precisa de mudar; a API e o dashboard ficam iguais.

1. Substitua esse nó por um nó **SSH** ligado ao servidor com a firewall, com um destes comandos:

   ```bash
   sudo ufw deny from {{ $json.ip_address }}
   sudo iptables -I INPUT -s {{ $json.ip_address }} -j DROP
   ```

   O SSH é necessário porque o n8n corre num contentor: um comando local alteraria o contentor, não o servidor.

2. Depois do nó SSH, adicione um nó **Set** que defina `status` como `bloqueado`, `simulated` como `false` e mantenha `ip_address`. Só chegue a este nó se o comando tiver sucesso.
3. Mantenha o nó **Validar IP**: é ele que impede a injeção de comandos.
4. Proteja o webhook com autenticação por cabeçalho, porque passa a poder alterar a firewall. A API tem de enviar o mesmo cabeçalho.
5. Use uma conta SSH só com permissão para estes comandos. Um IP errado pode cortar o seu próprio acesso, por isso teste primeiro com um IP inofensivo.
6. Os IPs bloqueados em simulação não são reenviados. Para os bloquear a sério, apague-os da tabela `blocked_ips` e peça o bloqueio de novo.

## Configuração

Todas as variáveis estão documentadas em [.env.example](.env.example). A aplicação não arranca sem `API_KEY` (mínimo de 16 caracteres) e `DATABASE_URL`.

## Antes de expor fora desta máquina

O dashboard não tem login: quem o abrir pode submeter incidentes e pedir bloqueios. Mantenha as portas em `127.0.0.1`, ou coloque-o atrás de um proxy com autenticação e HTTPS.
