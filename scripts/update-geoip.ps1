# Descarrega as bases DB-IP Lite (país e ASN) para data/geoip/.
# Uso: powershell -ExecutionPolicy Bypass -File .\scripts\update-geoip.ps1
#
# O DB-IP publica uma versão nova no dia 1 de cada mês; se a do mês ainda não existir,
# usa a do mês anterior. O único contacto externo é a descarga em download.db-ip.com:
# nenhum IP de incidente sai da máquina. A API recarrega as bases sozinha quando mudam.
# Licença dos dados: CC BY 4.0, "IP Geolocation by DB-IP" (https://db-ip.com).

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $root "data\geoip"
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# Marcador de metadados que todos os ficheiros .mmdb têm perto do fim.
$marker = [byte[]](0xAB, 0xCD, 0xEF) + [Text.Encoding]::ASCII.GetBytes("MaxMind.com")

function Test-Mmdb([string]$path) {
    $bytes = [IO.File]::ReadAllBytes($path)
    $start = [Math]::Max(0, $bytes.Length - 131072)
    for ($i = $bytes.Length - $marker.Length; $i -ge $start; $i--) {
        $match = $true
        for ($j = 0; $j -lt $marker.Length; $j++) {
            if ($bytes[$i + $j] -ne $marker[$j]) { $match = $false; break }
        }
        if ($match) { return $true }
    }
    return $false
}

function Expand-Gzip([string]$source, [string]$target) {
    $in = [IO.File]::OpenRead($source)
    try {
        $gzip = New-Object IO.Compression.GZipStream($in, [IO.Compression.CompressionMode]::Decompress)
        $out = [IO.File]::Create($target)
        try { $gzip.CopyTo($out) } finally { $out.Dispose(); $gzip.Dispose() }
    } finally { $in.Dispose() }
}

$now = (Get-Date).ToUniversalTime()
$months = @($now.ToString("yyyy-MM"), $now.AddMonths(-1).ToString("yyyy-MM"))

foreach ($name in "dbip-country-lite", "dbip-asn-lite") {
    $gz = Join-Path $dir "$name.mmdb.gz.tmp"
    $tmp = Join-Path $dir "$name.mmdb.tmp"
    $final = Join-Path $dir "$name.mmdb"
    $downloaded = $null
    try {
        foreach ($month in $months) {
            try {
                Invoke-WebRequest -UseBasicParsing -Uri "https://download.db-ip.com/free/$name-$month.mmdb.gz" -OutFile $gz
                $downloaded = $month
                break
            } catch {
                if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { continue }
                throw
            }
        }
        if (-not $downloaded) { throw "Nenhuma versão de $name encontrada para $($months -join ' ou ')." }

        Expand-Gzip $gz $tmp
        if (-not (Test-Mmdb $tmp)) { throw "$name-$downloaded não parece um ficheiro .mmdb válido." }

        # Troca o ficheiro antigo pelo novo só depois de validado.
        if (Test-Path $final) { [IO.File]::Replace($tmp, $final, $null) } else { Move-Item $tmp $final }
        $size = [Math]::Round((Get-Item $final).Length / 1MB, 1)
        "{0}: versão {1}, {2} MB" -f $name, $downloaded, $size
    } finally {
        Remove-Item $gz, $tmp -Force -ErrorAction SilentlyContinue
    }
}
