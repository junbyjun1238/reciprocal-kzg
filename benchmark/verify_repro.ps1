$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$pocRoot = Join-Path $repoRoot "poc"
$expectedSnapshotPath = Join-Path $PSScriptRoot "reciprocal_snapshot.csv"
$expectedKernelPath = Join-Path $PSScriptRoot "reciprocal_kernel_snapshot.csv"

function Get-CapturedOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $env:ComSpec
    $startInfo.Arguments = "/d /c $Command"
    $startInfo.WorkingDirectory = $pocRoot
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $null = $process.Start()

    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    if ($process.ExitCode -ne 0) {
        throw "Command failed: $Command"
    }

    $combined = @()
    if ($stdout) {
        $combined += ($stdout -split "\r?\n")
    }
    if ($stderr) {
        $combined += ($stderr -split "\r?\n")
    }

    return $combined | Where-Object { $_ -ne "" }
}

function Convert-LinesToCsvRows {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Lines,
        [Parameter(Mandatory = $true)]
        [string]$HeaderPattern,
        [Parameter(Mandatory = $true)]
        [string]$RowPattern
    )

    $headerIndex = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match $HeaderPattern) {
            $headerIndex = $i
            break
        }
    }

    if ($headerIndex -lt 0) {
        throw "Could not find CSV header matching pattern: $HeaderPattern"
    }

    $csvLines = New-Object System.Collections.Generic.List[string]
    $csvLines.Add($Lines[$headerIndex])

    for ($i = $headerIndex + 1; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match $RowPattern) {
            $csvLines.Add($Lines[$i])
        }
    }

    $csvText = [string]::Join([Environment]::NewLine, $csvLines)
    return $csvText | ConvertFrom-Csv
}

function Select-Columns {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Rows,
        [Parameter(Mandatory = $true)]
        [string[]]$Columns
    )

    return $Rows | Select-Object -Property $Columns
}

function Assert-CsvMatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [object[]]$ExpectedRows,
        [Parameter(Mandatory = $true)]
        [object[]]$ActualRows,
        [Parameter(Mandatory = $true)]
        [string[]]$Columns
    )

    $expectedJson = Select-Columns -Rows $ExpectedRows -Columns $Columns | ConvertTo-Json -Depth 5
    $actualJson = Select-Columns -Rows $ActualRows -Columns $Columns | ConvertTo-Json -Depth 5

    if ($expectedJson -ne $actualJson) {
        Write-Host ""
        Write-Host "[$Name] structural mismatch detected." -ForegroundColor Red
        Write-Host ""
        Write-Host "Expected:"
        Write-Host $expectedJson
        Write-Host ""
        Write-Host "Actual:"
        Write-Host $actualJson
        throw "$Name reproducibility check failed"
    }

    Write-Host "[$Name] structural metrics match the checked-in CSV." -ForegroundColor Green
}

$snapshotColumns = @(
    "name",
    "steps",
    "state_width",
    "step_constraints",
    "step_public_inputs",
    "step_witnesses",
    "primary_constraints",
    "secondary_constraints",
    "external_output_width",
    "q_len",
    "adapter_public_inputs"
)

$kernelColumns = @(
    "depth",
    "leaves",
    "reduced_descriptor_words",
    "explicit_row_words",
    "descriptor_word_ratio",
    "specialized_mults",
    "direct_mults",
    "mult_ratio"
)

Push-Location $pocRoot
try {
    Write-Host "# verifying reciprocal reproducibility"
    Write-Host "# note: runtime columns are intentionally ignored; only structural metrics are compared"
    Write-Host ""

    $snapshotOutput = Get-CapturedOutput -Command "cargo test -p sonobe-ivc benchmark_nova_nova_snapshot -- --ignored --nocapture"
    $actualSnapshotRows = Convert-LinesToCsvRows `
        -Lines $snapshotOutput `
        -HeaderPattern '^name,steps,state_width,' `
        -RowPattern '^[A-Za-z0-9_]+,'
    $expectedSnapshotRows = Import-Csv $expectedSnapshotPath
    Assert-CsvMatch `
        -Name "sonobe_snapshot" `
        -ExpectedRows $expectedSnapshotRows `
        -ActualRows $actualSnapshotRows `
        -Columns $snapshotColumns

    $kernelOutput = Get-CapturedOutput -Command "cargo run -p sonobe-primitives --example reciprocal_kernel_bench --release"
    $actualKernelRows = Convert-LinesToCsvRows `
        -Lines $kernelOutput `
        -HeaderPattern '^depth,leaves,' `
        -RowPattern '^\d+,'
    $expectedKernelRows = Import-Csv $expectedKernelPath
    Assert-CsvMatch `
        -Name "kernel_snapshot" `
        -ExpectedRows $expectedKernelRows `
        -ActualRows $actualKernelRows `
        -Columns $kernelColumns

    Write-Host ""
    Write-Host "All structural benchmark conclusions reproduce successfully." -ForegroundColor Green
}
finally {
    Pop-Location
}
