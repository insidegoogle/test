@echo off
setlocal

echo [1/2] Склеиваю OpenCL ядра...

set CL_DIR=cl
set OUTPUT=%CL_DIR%\bitcrack_combined.cl

if exist %OUTPUT% del %OUTPUT%

:: Правильный порядок склейки
type %CL_DIR%\ripemd160.cl > %OUTPUT%
type %CL_DIR%\sha256.cl >> %OUTPUT%
type %CL_DIR%\secp256k1.cl >> %OUTPUT%
type %CL_DIR%\keysearch.cl >> %OUTPUT%

echo Готово: %OUTPUT%
echo.

echo [2/2] Теперь нужно прогнать через embedcl
echo.
echo Пример команды:
echo tools\embedcl.exe %OUTPUT% src\bitcrack_cl.cpp _bitcrack_cl
echo.

pause