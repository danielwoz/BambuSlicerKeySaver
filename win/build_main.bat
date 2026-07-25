@echo off
setlocal EnableExtensions
REM Build helper for the MAIN tree. Usage: build_main.bat [configure|build] [builddir]
REM Sources MSVC vcvars64, strips Strawberry Perl/ninja from PATH, uses VS ninja.

set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
set "NINJA=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
set "CMAKE=C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

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
