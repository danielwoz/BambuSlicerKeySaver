@echo off
setlocal EnableExtensions
REM Build helper for the MAIN tree. Usage: build_main.bat [configure|build|full] [builddir]
REM Discovers the latest VS install with vswhere, sources MSVC vcvars64, strips perl/bin from path to avoid conflicts

set "VSINSTALL_FALLBACK=C:\Program Files\Microsoft Visual Studio\18\Community"

set "VSINSTALL="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto fallback

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -prerelease -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%i"
if not defined VSINSTALL goto fallback
if not exist "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" goto fallback
goto have_vs

:fallback
echo vswhere lookup failed; falling back to legacy path "%VSINSTALL_FALLBACK%".
set "VSINSTALL=%VSINSTALL_FALLBACK%"
if not exist "%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat" goto no_vs

:have_vs
set "VCVARS=%VSINSTALL%\VC\Auxiliary\Build\vcvars64.bat"
echo Starting with VS tools from: %VSINSTALL%
call "%VCVARS%" >nul 2>nul

REM CMake and Ninja ship with the VS "CMake for Windows" component; prefer those.
set "NINJA=%VSINSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
set "CMAKE=%VSINSTALL%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if not exist "%CMAKE%" set "CMAKE=cmake"
if not exist "%NINJA%" set "NINJA=ninja"

REM technically these should end up at the end of the path but strip them anyway
set "PATH=%PATH:C:\Strawberry\c\bin;=%"
set "PATH=%PATH:C:\Strawberry\perl\bin;=%"
set "PATH=%PATH:C:\Strawberry\perl\site\bin;=%"

REM 
set "TOOLCHAIN_ARG="
if not defined VCPKG_ROOT goto no_toolchain
if not exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" goto no_toolchain
set TOOLCHAIN_ARG=-DCMAKE_TOOLCHAIN_FILE="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
:no_toolchain

set "SRCDIR=%~dp0."
set "BUILDDIR=%~2"
if "%BUILDDIR%"=="" set "BUILDDIR=%~dp0build_main"

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=full"
if /I "%ACTION%"=="configure" goto configure
if /I "%ACTION%"=="build" goto build
if /I "%ACTION%"=="make" goto build
if /I "%ACTION%"=="full" goto full
echo Usage: build_main.bat [configure^|build^|full] [builddir]
exit /b 2

:full
call :configure || exit /b %errorlevel%
goto build

:configure
"%CMAKE%" -G Ninja -S "%SRCDIR%" -B "%BUILDDIR%" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl %TOOLCHAIN_ARG%
exit /b %errorlevel%

:build
"%CMAKE%" --build "%BUILDDIR%"
exit /b %errorlevel%

:no_vs
echo ERROR: no usable Visual Studio C++ toolset found ^(vswhere and legacy path both failed^).
exit /b 3
