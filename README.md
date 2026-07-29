# Wazuh Servidor MCP

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-2025--11--25-green.svg)](https://modelcontextprotocol.io/)

**Talk to your SIEM.** Query alerts, hunt threats, check vulnerabilities, and trigger active responses across your Wazuh deployment through natural conversation with any AI assistant via Model Context Protocol (MCP).

---

## Features & Capabilities

- **Alert & Event Search**: Query Elasticsearch/Indexer alerts, filter by severity, rule ID, or agent.
- **Agent Management**: Monitor agent statuses, active processes, open ports, and configurations.
- **Vulnerability Management**: Scan unpatched CVEs across agents.
- **Active Response**: Block malicious IPs, isolate compromised hosts, terminate processes, and manage file quarantine.
- **Verification & Rollback**: Check status of active response actions and undo them when needed.
- **Security & RBAC**: Rate limiting, token-based authentication, log sanitization, and audit logging.

---

## Ferramentas de Segurança Disponíveis (56 Ferramentas em Português)

| Categoria | Ferramentas | Descrição |
|-----------|-------------|-----------|
| **Alertas e Eventos** | `obter_alertas_wazuh` `obter_resumo_alertas_wazuh` `analisar_padroes_alertas` `buscar_eventos_seguranca` | Consulta, filtragem e análise comportamental de alertas e eventos |
| **Agentes e Grupos** | `obter_agentes_wazuh` `obter_agentes_ativos_wazuh` `verificar_saude_agente` `obter_processos_agente` `obter_portas_agente` `obter_configuracao_agente` `obter_pacotes_agente` `obter_alteracoes_fim_agente` `gerenciar_grupos_agente` | Monitoramento de agentes, processos, portas, FIM/syscheck, pacotes instalados e gestão/criação/exclusão de grupos |
| **Vulnerabilidades** | `obter_vulnerabilidades_wazuh` `obter_vulnerabilidades_criticas_wazuh` `obter_resumo_vulnerabilidades_wazuh` | Consulta de CVEs e pacotes vulneráveis por severidade |
| **Regras e Testes** | `obter_resumo_regras_wazuh` `obter_detalhes_regra_wazuh` `testar_mensagem_log_wazuh` `criar_regra_customizada_wazuh` `modificar_regra_customizada_wazuh` `excluir_regra_customizada_wazuh` | Inspeção, simulação (`wazuh-logtest`), **criação, modificação e exclusão de regras XML customizadas** |
| **Análise e Relatórios** | `analisar_ameaca_seguranca` `verificar_reputacao_ioc` `executar_avaliacao_risco` `obter_principais_ameacas_seguranca` `gerar_relatorio_seguranca` `executar_teste_conformidade` | Análise de ameaças, reputação de IOCs, cálculo de risco e conformidade (PCI-DSS, CIS, NIST) |
| **Resposta Ativa** | `resposta_ativa_wazuh` `bloquear_ip_wazuh` `isolar_host_wazuh` `encerrar_processo_wazuh` `desabilitar_usuario_wazuh` `quarentena_arquivo_wazuh` `bloquear_firewall_wazuh` `negar_host_wazuh` `reiniciar_servico_wazuh` | Execução de ações defensivas diretas no ambiente |
| **Verificação e Desfazer** | `verificar_ip_bloqueado_wazuh` `verificar_isolamento_agente_wazuh` `verificar_processo_wazuh` `verificar_status_usuario_wazuh` `verificar_quarentena_arquivo_wazuh` `desisolar_host_wazuh` `habilitar_usuario_wazuh` `restaurar_arquivo_wazuh` `permitir_firewall_wazuh` `permitir_host_wazuh` | Confirmação e rollback de remediações defensivas |

---

## Quick Start

### Prerequisites
- Python 3.11+
- Wazuh Manager (v4.8.0+) with API credentials enabled
- Docker & Docker Compose (optional, for containerized run)

### Installation

1. **Clone repository and configure environment**:
   ```bash
   git clone https://github.com/nks1097/Wazuh_Servidor_MCP.git
   cd Wazuh_Servidor_MCP
   cp .env.example .env
   ```

2. **Configure `.env`**:
   ```env
   WAZUH_HOST=https://your-wazuh-manager
   WAZUH_USER=wazuh-api-user
   WAZUH_PASS=wazuh-api-password
   WAZUH_PORT=55000
   MCP_HOST=127.0.0.1
   MCP_PORT=3000
   AUTH_MODE=bearer
   MCP_API_KEY=your-secure-api-key
   ```

3. **Run with Python**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Or `venv\Scripts\activate` on Windows
   pip install -r requirements.txt
   python -m wazuh_mcp_server
   ```

   *Or run via Docker*:
   ```bash
   docker compose up -d
   ```

4. **Verify Health**:
   ```bash
   curl http://localhost:3000/health
   ```

---

## Connecting to MCP Clients

### Claude Desktop
Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["-m", "wazuh_mcp_server"],
      "env": {
        "WAZUH_HOST": "https://your-wazuh-manager",
        "WAZUH_USER": "wazuh-api-user",
        "WAZUH_PASS": "wazuh-api-password"
      }
    }
  }
}
```

### Open WebUI / Remote SSE Endpoint
Endpoint: `http://localhost:3000/mcp` (Streamable HTTP) or `http://localhost:3000/sse`

---

## Key Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_HOST` | Required | Hostname or IP of Wazuh Manager |
| `WAZUH_USER` | Required | API Username |
| `WAZUH_PASS` | Required | API Password |
| `WAZUH_PORT` | `55000` | Wazuh API Port |
| `MCP_HOST` | `127.0.0.1` | MCP Server Bind Host |
| `MCP_PORT` | `3000` | MCP Server Bind Port |
| `AUTH_MODE` | `bearer` | Authentication mode (`bearer`, `oauth`, `none`) |
| `WAZUH_VERIFY_SSL` | `true` | Verify SSL certificates (`true`/`false`) |

---

## API Endpoints

- `/mcp` - MCP Streamable HTTP endpoint
- `/sse` - Legacy Server-Sent Events endpoint
- `/health` - Service health status
- `/metrics` - Prometheus metrics
- `/docs` - OpenAPI documentation

---

## License

[MIT License](LICENSE)
