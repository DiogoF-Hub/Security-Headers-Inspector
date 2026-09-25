# Build the Chrome Web Store zip: sets the version in manifest.json and package.json,
# then zips only the files the extension uses, with manifest.json at the top level.
#
#   .\package.ps1           asks for the version
#   .\package.ps1 2.0.1     uses the given version
#
# Output: dist\security-headers-inspector-<version>.zip
# If scripts are blocked: powershell -ExecutionPolicy Bypass -File .\package.ps1

param([string]$Version)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

# Files the extension loads (manifest, pages, scripts, styles, icons)
$Files = @(
  "manifest.json", "background.js", "analysis.js",
  "popup.html", "popup.css", "popup.js",
  "options.html", "options.css", "options.js",
  "welcome.html", "welcome.css",
  "icons/icon16.png", "icons/icon48.png", "icons/icon128.png"
)

$manifestText = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot "manifest.json"))
$current = [regex]::Match($manifestText, '(?m)^  "version": "([^"]*)"').Groups[1].Value

if (-not $Version) {
  $Version = Read-Host "Version (current $current)"
}
$Version = $Version.Trim()

# Chrome accepts 1 to 4 dot-separated integers between 0 and 65535, without leading zeros
if ($Version -notmatch '^(0|[1-9][0-9]{0,4})(\.(0|[1-9][0-9]{0,4})){0,3}$') {
  Write-Error "Invalid version `"$Version`": use 1 to 4 numbers separated by dots, like 2.0.1"
}
foreach ($part in $Version.Split(".")) {
  if ([int]$part -gt 65535) { Write-Error "Invalid version `"$Version`": each number must be 65535 or lower" }
}

foreach ($file in $Files) {
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { Write-Error "Missing file: $file" }
}

# Set the version (the only top-level "version" line in each file), keeping the
# files as UTF-8 without a byte order mark and with their original line endings
$utf8 = New-Object System.Text.UTF8Encoding($false)
foreach ($json in @("manifest.json", "package.json")) {
  $path = Join-Path $PSScriptRoot $json
  if (Test-Path -LiteralPath $path) {
    $text = [System.IO.File]::ReadAllText($path)
    $text = [regex]::Replace($text, '(?m)^  "version": "[^"]*"', "  `"version`": `"$Version`"")
    [System.IO.File]::WriteAllText($path, $text, $utf8)
  }
}
if ($Version -ne $current) {
  Write-Host "Version changed from $current to $Version in manifest.json and package.json"
}

$dist = Join-Path $PSScriptRoot "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$out = Join-Path $dist "security-headers-inspector-$Version.zip"
if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out }

# Built entry by entry instead of Compress-Archive: Windows PowerShell 5.1's
# Compress-Archive writes backslashes in paths, which the Chrome Web Store rejects.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($out, [System.IO.Compression.ZipArchiveMode]::Create)
try {
  foreach ($file in $Files) {
    $source = Join-Path $PSScriptRoot $file
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $source, $file, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
  }
} finally {
  $zip.Dispose()
}

Write-Host "Created dist\security-headers-inspector-$Version.zip:"
$Files | ForEach-Object { Write-Host "  $_" }
