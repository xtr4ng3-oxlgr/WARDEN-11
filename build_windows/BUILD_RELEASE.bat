@echo off
title WARDEN-11 - Build Release
color 0C
cd /d "%~dp0\.."

echo ============================================================
echo WARDEN-11 - BUILD RELEASE
echo xtr4ng3
echo ============================================================
echo.

where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo No se encontro Cargo/Rust.
    echo Instala Rust desde rustup.rs
    pause
    exit /b
)

cargo build --release

if %errorlevel% neq 0 (
    echo Fallo compilacion.
    pause
    exit /b
)

rmdir /s /q CLIENTE_PORTABLE 2>nul
mkdir CLIENTE_PORTABLE
copy /Y target\release\warden11.exe CLIENTE_PORTABLE\warden11.exe
copy /Y README.md CLIENTE_PORTABLE\README.txt
xcopy /E /I /Y dashboard CLIENTE_PORTABLE\dashboard
xcopy /E /I /Y rules CLIENTE_PORTABLE\rules
xcopy /E /I /Y docs CLIENTE_PORTABLE\docs
xcopy /E /I /Y examples CLIENTE_PORTABLE\examples

echo.
echo Build listo:
echo CLIENTE_PORTABLE\warden11.exe
pause
