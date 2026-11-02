param(
    [ValidateSet('openwebui', 'direct')][string]$Transport = 'openwebui',
    [string]$BaseUrl = 'https://llms.si-lab.org',
    [string]$EndpointUrl = $env:PPLX_SYSTEMONE_URL,
    [string]$Model = $env:PPLX_MODEL_ID,
    [int]$Limit = 10,
    [string]$OutputDirectory = 'outputs/phishrewrite_pplx_test'
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$TestPython = if (Test-Path -LiteralPath '.venv/Scripts/python.exe') { '.venv/Scripts/python.exe' } else { 'python' }
$KeyName = if ($Transport -eq 'openwebui') { 'OPENWEBUI_API_KEY' } else { 'PPLX_API_KEY' }
$PreviousKey = [Environment]::GetEnvironmentVariable($KeyName, 'Process')
$PromptedKey = -not $PreviousKey
try {
    if ($PromptedKey) {
        $SecureKey = Read-Host "$KeyName (hidden input; do not paste into chat)" -AsSecureString
        $KeyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
        try { [Environment]::SetEnvironmentVariable($KeyName, [Runtime.InteropServices.Marshal]::PtrToStringBSTR($KeyPointer), 'Process') }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($KeyPointer); $SecureKey.Dispose() }
    }
    $TestArguments = @('scripts/test_phishrewrite_decider.py', '--transport', $Transport,
        '--limit', "$Limit", '--output-dir', $OutputDirectory)
    if ($Transport -eq 'openwebui') { $TestArguments += @('--webui-url', $BaseUrl) }
    else {
        if (-not $EndpointUrl) { $EndpointUrl = Read-Host 'Full SGLang /systemone URL' }
        if (-not $Model) { $Model = Read-Host 'Exact Decider model ID' }
        $TestArguments += @('--endpoint-url', $EndpointUrl, '--model', $Model)
    }
    & $TestPython @TestArguments
    $TestExitCode = $LASTEXITCODE
}
finally {
    if ($PromptedKey) { [Environment]::SetEnvironmentVariable($KeyName, $PreviousKey, 'Process') }
}
exit $TestExitCode
