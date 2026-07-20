@echo off
setlocal EnableExtensions
REM Build helper for the MAIN tree. Usage: build_main.bat [configure|build] [builddir]
REM Sources MSVC vcvars64, strips Strawberry Perl/ninja from PATH, uses VS ninja.
REM Uses the default vswhere location; VS 18 Community paths are a fallback only.

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VCVARS=%%I\VC\Auxiliary\Build\vcvars64.bat"
        set "NINJA=%%I\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
        set "CMAKE=%%I\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    )
    if not defined VCVARS (
        echo Unable to locate a Visual Studio installation with C++ build tools.
        exit /b 1
    )
) else (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
    set "NINJA=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
    set "CMAKE=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
)
call "%VCVARS%" >nul 2>nul

REM Strip Strawberry (its ld.exe/ninja shadow MSVC and break the link).
set "PATH=%PATH:C:\Strawberry\c\bin;=%"
set "PATH=%PATH:C:\Strawberry\perl\bin;=%"
set "PATH=%PATH:C:\Strawberry\perl\site\bin;=%"

set "SRCDIR=%~dp0."
set "BUILDDIR=%~2"
if "%BUILDDIR%"=="" set "BUILDDIR=%~dp0build_main"

if /I "%~1"=="configure" goto configure
if /I "%~1"=="build" goto build
echo Usage: build_main.bat [configure^|build] [builddir]
exit /b 2

:configure
"%CMAKE%" -G Ninja -S "%SRCDIR%" -B "%BUILDDIR%" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl -DCMAKE_MAKE_PROGRAM="%NINJA%"
exit /b %errorlevel%

:build
"%CMAKE%" --build "%BUILDDIR%"
exit /b %errorlevel%
