@echo off
:: Script de inicialização do Wazuh Servidor MCP
:: Carrega variáveis do .env e inicia o servidor Python

cd /d "%~dp0"

:: Carregar .env
for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
    if not "%%A"=="" if not "%%A:~0,1%"=="#" (
        set "%%A=%%B"
    )
)

:: Iniciar servidor
python -m wazuh_mcp_server
