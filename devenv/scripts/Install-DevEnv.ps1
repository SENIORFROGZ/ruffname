# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog
# (https://www.datadoghq.com/).
# Copyright 2019-present Datadog, Inc.

Write-Host
'=======================================================
         ____        __        ____
        / __ \____ _/ /_____ _/ __ \____  ____ _
       / / / / __ `/ __/ __ `/ / / / __ \/ __ `/
      / /_/ / /_/ / /_/ /_/ / /_/ / /_/ / /_/ /
     /_____/\__,_/\__/\__,_/_____/\____/\__, /
                                       /____/
=======================================================
                    * WinDog Setup *'

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Getting Chocolatey'
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Imports 'Update-SessionEnvironment' so we can reload env variables without restarting the process
Import-Module "$env:ChocolateyInstall\helpers\chocolateyInstaller.psm1" -Force;

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Getting git'
cinst -y git

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Getting 7zip'
cinst -y 7zip

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installing Visual Studio build tools'
cinst -y visualstudio2017buildtools --params "--add Microsoft.VisualStudio.ComponentGroup.NativeDesktop.Win81"

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installing Visual C++ Workload'
cinst -y visualstudio2017-workload-vctools

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installinc VC Tools for Python 2.7'l
cinst -y vcpython27

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installing Wix'
cinst -y wixtoolset --version 3.11
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine) + ";${env:ProgramFiles}\WiX Toolset v3.11\bin",
    [System.EnvironmentVariableTarget]::Machine)

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installing CMake'
cinst -y cmake
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine) + ";${env:ProgramFiles}\CMake\bin",
    [System.EnvironmentVariableTarget]::Machine)

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installing Golang'

# TODO: Enable this when we can use Chocolatey again
#cinst -y golang --version 1.15.13

# Workaround for go 1.15.13 since it does not exist in Chocolatey
# taken from https://github.com/DataDog/datadog-agent-buildimages/blob/master/windows/install_go.ps1
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

Write-Host -ForegroundColor Green "Installing go 1.15.13"

$gozip = "https://dl.google.com/go/go1.15.13.windows-amd64.zip"
if ($Env:TARGET_ARCH -eq "x86") {
    $gozip = "https://dl.google.com/go/go1.15.13.windows-386.zip"
}

$out = 'c:\go.zip'
Write-Host -ForegroundColor Green "Downloading $gozip to $out"
(New-Object System.Net.WebClient).DownloadFile($gozip, $out)
Write-Host -ForegroundColor Green "Extracting $out to c:\"
Start-Process "7z" -ArgumentList 'x -oc:\ c:\go.zip' -Wait
Write-Host -ForegroundColor Green "Removing temporary file $out"
Remove-Item 'c:\go.zip'

setx GOROOT c:\go
$Env:GOROOT="c:\go"
setx PATH "$Env:Path;c:\go\bin;"
$Env:Path="$Env:Path;c:\go\bin;"
# End Go workaround

Write-Host -ForegroundColor Green "Installed go $ENV:GO_VERSION"

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installing Python 2'
cinst -y python2

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installing Ruby'
cinst -y ruby --version 2.4.3.1

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installing MSYS'
cinst -y msys2 --params "/NoUpdate" # install msys2 without system update

# Reload environment to get ruby in path
Update-SessionEnvironment

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installing Toolchain'
ridk install 2 3 # use ruby's ridk to update the system and install development toolchain

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen '- Installing Bundler'
gem install bundler

Write-Host -ForegroundColor Yellow -BackgroundColor DarkGreen ' * DONE *'
