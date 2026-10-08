@echo off
rem Qalqon Antivirus — Windows uchun yig'ish (Go 1.22+ kerak: https://go.dev/dl/)
go test ./... || exit /b 1
go build -trimpath -ldflags="-s -w" -o qalqon.exe . || exit /b 1
echo Tayyor: qalqon.exe
