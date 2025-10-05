# Install Git if not already installed
$gitInstalled = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitInstalled) {
    Write-Host "Git is not installed. Installing Git..."
        # Get latest Git for Windows release info from GitHub API
        $releaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest"
        $asset = $releaseInfo.assets | Where-Object { $_.name -match "64-bit.exe$" } | Select-Object -First 1
        if (-not $asset) {
            Write-Host "Could not find a 64-bit Git installer in the latest release."
            exit 1
        }
        $installerUrl = $asset.browser_download_url
        $installerPath = "$env:TEMP\$($asset.name)"
        Write-Host "Downloading Git installer from $installerUrl ..."
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
        Write-Host "Running Git installer..."
        Start-Process -FilePath $installerPath -ArgumentList "/VERYSILENT /NORESTART" -Wait
        Remove-Item $installerPath
        Write-Host "Git installation completed."
        # Refresh environment so git is available
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
} else {
    Write-Host "Git is already installed."
}

# Prompt user for Git config
$userName = Read-Host "Enter your Git user.name (e.g., John Doe)"
$userEmail = Read-Host "Enter your Git user.email (e.g., johndoe@example.com)"

# Set Git config
if ($userName -and $userEmail) {
    Write-Host "Setting Git global config..."
    & git config --global user.name "$userName"
    & git config --global user.email "$userEmail"
    Write-Host "Git global config set: user.name = $userName, user.email = $userEmail"
} else {
    Write-Host "Git config not set. Both name and email are required."
}
