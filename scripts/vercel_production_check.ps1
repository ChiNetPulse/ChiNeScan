[CmdletBinding()]
param(
    [string]$ApiBaseUrl = "/api"
)

$ErrorActionPreference = "Stop"
$branch = (git branch --show-current).Trim()
if ($branch -ne "main") {
    throw "Production Vercel checks must run from main; current branch is '$branch'."
}
if ([string]::IsNullOrWhiteSpace($ApiBaseUrl)) {
    throw "Provide the reviewed same-origin API path or HTTPS API origin."
}

$env:VITE_API_BASE_URL = $ApiBaseUrl
Push-Location (Join-Path $PSScriptRoot "..\frontend")
try {
    npm ci
    npm run build
    npm run test -- --run
} finally {
    Pop-Location
}
Write-Output "Vercel production build and frontend tests passed on main. Deployment remains an explicit operator action."
