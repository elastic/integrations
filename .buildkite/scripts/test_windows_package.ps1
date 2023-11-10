# Install the current Go release
$file = 'go1.21.3.windows-amd64.msi'
$workDir = 'Documents\go'
$url = 'https://storage.googleapis.com/golang/' + $file
$dest = Join-Path $Home "Downloads"
$dest = Join-Path $dest $file
$gopath = Join-Path $Home $workDir
If (!(Test-Path $gopath)) {
    New-Item -path $gopath -type directory
}
$gopathbin = Join-Path $gopath "bin"
[Environment]::SetEnvironmentVariable( "GOPATH", $gopath, [System.EnvironmentVariableTarget]::User )
[Environment]::SetEnvironmentVariable( "GOBIN", $gopathbin, [System.EnvironmentVariableTarget]::User )
Write-Output "downloading $url"
$wc = New-Object System.Net.WebClient
$wc.UseDefaultCredentials = $true
$wc.Headers.Add("X-FORMS_BASED_AUTH_ACCEPTED", "f")
$wc.DownloadFile($url, $dest)
Write-Output "$url downloaded as $dest"
Write-Output "installing $v..."
Start-Process $dest
Write-Output "done"
