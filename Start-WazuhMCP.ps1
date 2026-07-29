# Script PowerShell para iniciar o Wazuh Servidor MCP
# Execute este script para ligar o servidor antes de usar

$ServerPath = $PSScriptRoot

# Verificar se já está rodando
$existing = Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "✅ Wazuh Servidor MCP já está rodando na porta 3000" -ForegroundColor Green
    exit 0
}

# Carregar arquivo .env se existir
$envFile = Join-Path $ServerPath ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $key, $val = $line.Split("=", 2)
            [System.Environment]::SetEnvironmentVariable($key.Trim(), $val.Trim(), [System.EnvironmentVariableTarget]::Process)
        }
    }
}

Write-Host "🚀 Iniciando Wazuh Servidor MCP..." -ForegroundColor Cyan
Start-Process python -ArgumentList "-m", "wazuh_mcp_server" `
    -WorkingDirectory $ServerPath `
    -WindowStyle Hidden

Start-Sleep 3

# Testar health
try {
    $health = Invoke-RestMethod "http://127.0.0.1:3000/health" -ErrorAction Stop
    Write-Host "✅ Servidor iniciado com sucesso!" -ForegroundColor Green
    Write-Host "   MCP Status: $($health.services.mcp)" -ForegroundColor White
    Write-Host "   Wazuh Status: $($health.services.wazuh_manager)" -ForegroundColor White
    Write-Host "   Endpoint MCP: http://127.0.0.1:3000/sse" -ForegroundColor Yellow
} catch {
    Write-Host "⚠️ Servidor iniciado mas health check falhou: $_" -ForegroundColor Yellow
}
