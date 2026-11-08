# Instala no n8n do Docker Compose o workflow de bloqueio e o segredo do webhook.
# O segredo vem de N8N_WEBHOOK_SECRET no .env e nunca é gravado no repositório.
# Uso (na raiz do projeto): .\n8n\install-workflow.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$container = "netsentinel-n8n"

$line = Select-String -Path (Join-Path $root ".env") -Pattern '^N8N_WEBHOOK_SECRET=(.+)$' |
    Select-Object -First 1
if (-not $line) { throw "Defina N8N_WEBHOOK_SECRET no .env antes de instalar o workflow." }
$secret = $line.Matches[0].Groups[1].Value.Trim()
if ($secret.Length -lt 16) { throw "N8N_WEBHOOK_SECRET deve ter pelo menos 16 caracteres." }

function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw "Falhou: docker $($args -join ' ')" }
}

$credential = ConvertTo-Json -Depth 5 -InputObject @(@{
    id   = "netsentinelWebhookAuth"
    name = "NetSentinel webhook"
    type = "httpHeaderAuth"
    data = @{ name = "X-NetSentinel-Secret"; value = $secret }
})
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "netsentinel-cred.json"
[System.IO.File]::WriteAllText($tmp, $credential, (New-Object System.Text.UTF8Encoding $false))

try {
    Invoke-Docker cp $tmp "${container}:/tmp/cred.json"
    Invoke-Docker exec $container n8n import:credentials --input=/tmp/cred.json
    Invoke-Docker cp (Join-Path $PSScriptRoot "netsentinel-block-simulation.json") "${container}:/tmp/wf.json"
    Invoke-Docker exec $container n8n import:workflow --input=/tmp/wf.json
    Invoke-Docker exec $container n8n publish:workflow --id=netsentinelBlockSim
}
finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    # O docker cp cria os ficheiros como root; o n8n corre como node e não os pode apagar.
    try { & docker exec -u root $container rm -f /tmp/cred.json /tmp/wf.json 2>$null } catch {}
}

Invoke-Docker compose -f (Join-Path $root "docker-compose.yml") restart n8n
Write-Host "Workflow instalado. O webhook agora exige o cabeçalho X-NetSentinel-Secret."
