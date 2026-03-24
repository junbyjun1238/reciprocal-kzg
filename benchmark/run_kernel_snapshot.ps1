$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$pocRoot = Join-Path $repoRoot "poc"

Push-Location $pocRoot
try {
    cargo run -p sonobe-primitives --example reciprocal_kernel_bench --release
}
finally {
    Pop-Location
}
