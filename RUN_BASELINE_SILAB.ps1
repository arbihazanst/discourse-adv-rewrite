[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:11435',
    [string]$InputCsv = 'data/phishrewrite/label1.csv',
    [string[]]$Victims = @('pplx_decider'),
    # [string]$ChatModel, # Legacy chat-victim selection disabled.
    [int]$Limit = 10,
    [string]$OutputDirectory = 'outputs/phishrewrite_silab_test',
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$BaselinePython = if (Test-Path -LiteralPath '.venv/Scripts/python.exe') { '.venv/Scripts/python.exe' } else { 'python' }
if ($Limit -lt 0) { throw 'Limit must be 0 (all) or positive.' }
$RunArguments = @('scripts/run_baseline.py', '--input', $InputCsv, '--label', '1',
    '--base-url', $BaseUrl, '--decision-base-url', $BaseUrl,
    '--limit', "$Limit", '--checkpoint-every', '1', '--output-dir', $OutputDirectory)
# Legacy chat-victim branch retained as comments.
# if ($ChatModel) {
#     $ModelTags = @($ChatModel)
#     $RunArguments += @('--chat-model', $ChatModel)
# } else {
#     ... configured victim selection ...
# }
$Configuration = Get-Content -LiteralPath 'config/models.json' -Raw | ConvertFrom-Json
$KnownIds = @($Configuration.victims | ForEach-Object { $_.id })
foreach ($VictimId in $Victims) {
    if ($VictimId -notin $KnownIds) { throw "Unknown configured victim: $VictimId" }
    $Victim = $Configuration.victims | Where-Object { $_.id -eq $VictimId }
    if ($Victim.kind -ne 'decision') { throw "Only decision-model victims are supported: $VictimId is disabled." }
}
if (-not $Victims.Count) { throw 'Select at least one decision-model victim.' }
$ModelTags = @($Configuration.victims | Where-Object { $_.id -in $Victims } | ForEach-Object { $_.tag })
$RunArguments += @('--victims') + $Victims
if ($DryRun) {
    $RunArguments += '--dry-run'
} else {
    & $BaselinePython scripts/check_ollama.py --base-url $BaseUrl --model @ModelTags
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
& $BaselinePython @RunArguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (-not $DryRun) {
    $MetricsInput = if ($Limit -gt 0) { Join-Path $OutputDirectory 'selected_input.csv' } else { $InputCsv }
    & $BaselinePython scripts/baseline_metrics.py --dataset $MetricsInput --dir $OutputDirectory --output (Join-Path $OutputDirectory 'metrics.csv')
    exit $LASTEXITCODE
}
