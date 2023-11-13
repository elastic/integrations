# Install gcc TODO: Move to the VM image
choco install mingw
Import-Module $env:ChocolateyInstall\helpers\chocolateyProfile.psm1
refreshenv

$ErrorActionPreference = "Stop"

# $env:GvmVersion = "0.5.2"
# [Net.ServicePointManager]::SecurityProtocol = "tls12"
# $env:GoVersion = Get-Content -Path .go-version
# Invoke-WebRequest -URI https://github.com/andrewkroh/gvm/releases/download/v$env:GvmVersion/gvm-windows-amd64.exe -Outfile C:\Windows\System32\gvm.exe
# gvm --format=powershell $env:GoVersion | Invoke-Expression
# go version

# $GOPATH = $(go env GOPATH)
# $env:Path = "$GOPATH\bin;" + $env:Path
# [Environment]::SetEnvironmentVariable("GOPATH", "$GOPATH", [EnvironmentVariableTarget]::Machine)
# [Environment]::SetEnvironmentVariable("Path", "$GOPATH\bin;$env:Path", [EnvironmentVariableTarget]::Machine)

# Install tools
# go install github.com/magefile/mage
# go install github.com/elastic/go-licenser
# go install golang.org/x/tools/cmd/goimports
# go install github.com/jstemmer/go-junit-report
# go install gotest.tools/gotestsum
# go install github.com/elastic/elastic-package

choco install docker-compose

# Enable-WindowsOptionalFeature -Online -FeatureName Containers -All

# docker run hello-world

wsl --install
wsl bash -c "sudo apt install docker-ce docker-ce-cli containerd.io; sudo docker run hello-world"

# elastic-package stack up -d -v

# cd packages/windows

# elastic-package test system -v