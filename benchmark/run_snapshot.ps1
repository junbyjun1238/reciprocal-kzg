$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$pocRoot = Join-Path $repoRoot "poc"

Push-Location $pocRoot
try {
    cargo test -p sonobe-ivc benchmark_nova_nova_snapshot -- --ignored --nocapture
}
finally {
    Pop-Location
}
