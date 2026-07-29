# 🤝 Como Contribuir para o Wazuh Servidor MCP

Seja bem-vindo ao projeto **Wazuh Servidor MCP**! Este guia explica a estrutura do repositório, o fluxo de desenvolvimento, os padrões de código e como você pode contribuir.

---

## 📋 Sumário

1. [Visão Geral do Repositório](#-visão-geral-do-repositório)
2. [Estratégia de Branches](#-estratégia-de-branches)
3. [Configuração do Ambiente de Desenvolvimento](#-configuração-do-ambiente-de-desenvolvimento)
4. [Estrutura do Projeto](#-estrutura-do-projeto)
5. [Fluxo de Desenvolvimento](#-fluxo-de-desenvolvimento)
6. [Diretrizes de Testes](#-diretrizes-de-testes)
7. [Padrões de Código](#-padrões-de-código)
8. [Como Solicitar Recursos ou Reportar Bugs](#-como-solicitar-recursos-ou-reportar-bugs)

---

## 🏗️ Visão Geral do Repositório

Este repositório fornece uma implementação de produção do protocolo **MCP (Model Context Protocol)** para integração direta com a plataforma **Wazuh SIEM**:

- **78 Ferramentas MCP em Português** para consulta de alertas, agentes, FIM, vulnerabilidades (CVEs), regras XML, decodificadores, conformidade (SCA), inteligência MITRE ATT&CK, SOAR e relatórios regulatórios (LGPD, NIST SP 800-53, CIS Benchmark).
- Suporte nativo para **HTTP (FastAPI / SSE)** e **Stdio Proxy (`wazuh-mcp-bridge.py`)** para integração transparente com a Antigravity IDE, LM Studio, Claude Desktop e VS Code.

---

## 🌳 Estratégia de Branches

### Branch Principal
- **`main`**: Código estável e pronto para produção.

### Fluxo de Branches
- Novas funcionalidades: `feature/nome-da-feature`
- Correções de bugs: `fix/descricao-do-bug`
- Correções urgentes: `hotfix/correcao-urgente`

---

## 🛠️ Configuração do Ambiente de Desenvolvimento

### Pré-requisitos
- **Python 3.11+**
- **Git**
- **Wazuh Manager (v4.8.0+)** com API habilitada
- **Wazuh Indexer (OpenSearch)** na porta 9200

### Configuração Inicial

1. **Clonar o repositório**:
   ```bash
   git clone https://github.com/nks1097/Wazuh_Servidor_MCP.git
   cd Wazuh_Servidor_MCP
   ```

2. **Criar e ativar o ambiente virtual (venv)**:
   ```bash
   python -m venv venv
   # No Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # No Linux/macOS:
   source venv/bin/activate
   ```

3. **Instalar dependências de desenvolvimento**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configurar o arquivo `.env`**:
   Copie o modelo de ambiente e ajuste com os dados do seu ambiente Wazuh:
   ```bash
   cp .env.example .env
   ```

---

## 📂 Estrutura do Projeto

```
Wazuh_Servidor_MCP/
├── src/wazuh_mcp_server/      # Código-fonte principal
│   ├── api/                   # Clientes de API (Wazuh Manager REST + OpenSearch Indexer)
│   ├── tools/                 # Implementação das 78 ferramentas MCP
│   ├── config.py              # Gerenciador de configurações e variáveis de ambiente
│   ├── server.py              # Servidor FastMCP e rotas HTTP/SSE
│   └── main.py                # Ponto de entrada da aplicação
├── wazuh-mcp-bridge.py        # Ponte stdio <-> HTTP para clientes MCP
├── Start-WazuhMCP.ps1         # Script PowerShell de inicialização rápida
├── start-wazuh-mcp.bat        # Script BAT de inicialização rápida
├── README.md                  # Documentação principal em Português
├── pyproject.toml             # Configurações do pacote Python
├── Dockerfile                 # Configuração de container Docker
└── compose.yml                # Configuração do Docker Compose
```

---

## 🔄 Fluxo de Desenvolvimento

1. Crie uma branch para a sua alteração:
   ```bash
   git checkout -b feature/minha-nova-funcionalidade
   ```
2. Realize as edições necessárias mantendo os comentários e nomes de funções padronizados.
3. Teste a execução do servidor localmente:
   ```bash
   python -m wazuh_mcp_server
   ```
4. Verifique a integração com a ponte stdio:
   ```bash
   python wazuh-mcp-bridge.py
   ```
5. Faça o commit das suas alterações com mensagens claras (ex: `feat: adicionar suporte a nova API do Wazuh`).

---

## 📐 Padrões de Código

- **Linguagem dos Nomes das Ferramentas MCP**: Todas as 78 ferramentas expostas ao protocolo MCP devem ser mantidas em Português no formato `snake_case` (ex: `obter_alertas_wazuh`, `investigar_incidente_wazuh`).
- **PEP 8**: Siga as diretrizes padrão de estilo do Python.
- **Tratamento de Erros**: Utilize exceções personalizadas definidas no projeto (`WazuhAPIError`, `IndexerNotConfiguredError`).
- **Segurança**: Nunca inclua senhas, tokens ou IPs internos fixos nos arquivos commitados.

---

## 💡 Como Solicitar Recursos ou Reportar Bugs

Caso encontre um bug ou queira sugerir uma nova ferramenta de segurança:
1. Abra uma **Issue** no repositório do GitHub: [https://github.com/nks1097/Wazuh_Servidor_MCP/issues](https://github.com/nks1097/Wazuh_Servidor_MCP/issues).
2. Descreva detalhadamente o comportamento esperado e o comportamento observado.