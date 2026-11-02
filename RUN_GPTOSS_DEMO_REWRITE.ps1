param(
    [int]$Limit = 3,
    [string]$OutputDirectory = 'outputs/phishrewrite_gptoss_demo',
    [string]$PromptFile = 'templates/gptoss_demo_rewrite_prompt.txt'
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$RewritePython = if (Test-Path -LiteralPath '.venv/Scripts/python.exe') { '.venv/Scripts/python.exe' } else { 'python' }
$PreviousKey = $env:OPENWEBUI_API_KEY
try {
    if (-not $PreviousKey) {
        $SecureKey = Read-Host 'Open WebUI API key (hidden input)' -AsSecureString
        $KeyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
        try { $env:OPENWEBUI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($KeyPointer) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($KeyPointer); $SecureKey.Dispose() }
    }
    & $RewritePython scripts/rewrite_gptoss_demo.py --limit $Limit --prompt-file $PromptFile --output-dir $OutputDirectory
    $RewriteExitCode = $LASTEXITCODE
}
finally {
    if (-not $PreviousKey) { Remove-Item Env:OPENWEBUI_API_KEY -ErrorAction SilentlyContinue }
}
exit $RewriteExitCode
