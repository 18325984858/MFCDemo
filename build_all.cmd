@echo off
setlocal
echo ============================================
echo  Build All: NetDrv + ArkApp + QtApp
echo ============================================

:: Setup MSVC environment
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to setup MSVC environment.
    exit /b 1
)

set ROOT=%~dp0
set FAIL=0

:: ---- Build NetDrv.sys ----
echo.
echo [1/3] Building NetDrv.sys ...
cd /d "%ROOT%NetDrv"
msbuild NetDrv.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SpectreMitigation=false /p:SignMode=Off /p:InfVerif_NoError=true /t:Rebuild /v:m
if errorlevel 1 (
    echo [WARN] NetDrv link OK but inf2cat failed (expected for testsigning)
)
if exist "%ROOT%NetDrv\x64\Release\NetDrv.sys" (
    copy /y "%ROOT%NetDrv\x64\Release\NetDrv.sys" "%ROOT%NetDrv.sys" >nul
    echo [OK] NetDrv.sys
) else (
    echo [FAIL] NetDrv.sys not found
    set FAIL=1
)

:: ---- Build ArkApp.exe ----
echo.
echo [2/3] Building ArkApp.exe ...
cd /d "%ROOT%ArkApp"
msbuild ArkApp.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Build /v:m
if errorlevel 1 (
    echo [FAIL] ArkApp build failed
    set FAIL=1
) else (
    copy /y "%ROOT%ArkApp\x64\Release\ArkApp.exe" "%ROOT%ArkApp.exe" >nul
    echo [OK] ArkApp.exe
)

:: ---- Build QtApp (ArkQt.exe) ----
echo.
echo [3/3] Building ArkQt.exe ...
cd /d "%ROOT%QtApp"
if not exist build mkdir build
cd build
cmake .. -G "Ninja" -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=C:/Qt/6.8.2/msvc2022_64 >nul 2>&1
cmake --build . --config Release
if errorlevel 1 (
    echo [FAIL] QtApp build failed
    set FAIL=1
) else (
    copy /y "%ROOT%QtApp\build\ArkQt.exe" "%ROOT%deploy\ArkQt.exe" >nul
    echo [OK] ArkQt.exe -> deploy/
)

:: ---- Summary ----
echo.
echo ============================================
if %FAIL%==0 (
    echo  All builds succeeded.
) else (
    echo  Some builds failed. Check output above.
)
echo  Outputs:
echo    NetDrv.sys  (root)
echo    ArkApp.exe  (root)
echo    ArkQt.exe   (deploy/)
echo ============================================

cd /d "%ROOT%"
endlocal
