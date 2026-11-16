@echo off
cd /d "%~dp0"
powershell -NoProfile -Command "$node=(Get-Command node -ErrorAction SilentlyContinue).Source; if(!$node){Write-Host 'Install Node.js 22 or newer first: https://nodejs.org'; exit 1}; $s=Read-Host 'Gemini API key (hidden, Enter = skip)' -AsSecureString; $env:GEMINI_API_KEY=[Net.NetworkCredential]::new('', $s).Password; $v=Read-Host 'VirusTotal API key (hidden, Enter = skip)' -AsSecureString; $env:VIRUSTOTAL_API_KEY=[Net.NetworkCredential]::new('', $v).Password; & $node server.mjs"
pause
