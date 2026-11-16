#!/usr/bin/env bash
cd "$(dirname "$0")"
command -v node >/dev/null || { echo "Сначала установите Node.js 22 или новее: https://nodejs.org"; exit 1; }
read -rsp "Ключ Gemini (ввод скрыт, Enter - пропустить): " GEMINI_API_KEY; echo
read -rsp "Ключ VirusTotal (ввод скрыт, Enter - пропустить): " VIRUSTOTAL_API_KEY; echo
export GEMINI_API_KEY VIRUSTOTAL_API_KEY
node server.mjs
