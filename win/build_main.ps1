param (
	[ValidateSet("configure","make","full")]	
	[string] $action="full",
	[string] $BuildDir="build",
	[ValidateSet("amd64","arm64")]	
	[string] $host_arch="amd64",
	[ValidateSet("amd64","arm64","x86")]
	[string] $arch=$host_arch
)
# https://github.com/mitchcapper/WIN64LinuxBuild/blob/master/vs_msys_shell_launch.ps1
Set-StrictMode -version latest;
$ErrorActionPreference = "Stop";
$PSNativeCommandUseErrorActionPreference = $true;


$ScriptDir = split-path -parent $MyInvocation.MyCommand.Definition;
$SourceDir = $ScriptDir
# $BuildDir = Resolve-Path -Path $BuildDir -Force #wont work if it doesn't exist
$BuildDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BuildDir)
# Set-Location -Path $ScriptDir

if (! $env:VS_ENV_INITIALIZED) {
    $instances=Get-CimInstance MSFT_VSInstance -Namespace root/cimv2/vs;
    $VS_INSTANCE = $instances[0]
    foreach ($instance in $instances) {
        if ( [System.Version]$VS_INSTANCE.Version -lt [System.Version]$instance.Version ) {
            $VS_INSTANCE=$instance;
        }
    }
    $VS_DEV_SHELL_PATH="$($VS_INSTANCE.InstallLocation)/Common7/Tools/Microsoft.VisualStudio.DevShell.dll";
    $VS_INSTANCE_ID=$VS_INSTANCE.IdentifyingNumber;
    $env:VS_ENV_INITIALIZED=1;
    Write-Host "Starting with VS tools from: $($VS_INSTANCE.ProductLocation)"
    Import-Module $VS_DEV_SHELL_PATH;
    Enter-VsDevShell $VS_INSTANCE_ID -SkipAutomaticLocation -DevCmdArguments "-arch=$arch -host_arch=$host_arch";
}

if ($action -eq "configure" -or $action -eq "full"){
	cmake -G Ninja -S $SourceDir -B $BuildDir -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
}
if ($action -eq "make" -or $action -eq "full"){
	cmake --build $BuildDir
}

Write-Host "Build complete. Output in: $BuildDir"