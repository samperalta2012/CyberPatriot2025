
param(
    [string]$Username,
    [string]$Password
)

# Check for Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator. Exiting."
    exit 1
}

# Set defaults if not provided
if (-not $Username) { $Username = "RemoteAdmin" }
if (-not $Password) { $Password = "P@ssw0rd123!" }

 # Create a secure password object
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

# Create the user account if it doesn't exist
if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $Username -Password $SecurePassword -FullName "Remote Admin User" -Description "Account for remote PowerShell access" -PasswordNeverExpires -AccountNeverExpires
    Write-Host "User $Username created."
} else {
    Write-Host "User $Username already exists."
}

# Add user to Administrators group if not already a member
if (-not (Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -eq "$env:COMPUTERNAME\$Username" })) {
    Add-LocalGroupMember -Group "Administrators" -Member $Username
    Write-Host "$Username added to Administrators group."
} else {
    Write-Host "$Username is already a member of Administrators group."
}


# Prompt user to enable or disable remote management
$remoteMgmt = Read-Host "Do you want to ENABLE or DISABLE remote management? (Enter 'enable' or 'disable')"

if ($remoteMgmt -eq 'enable') {
    # Enable PowerShell Remoting
    Enable-PSRemoting -Force

    # Set up WinRM to allow remote access for all users in Administrators group
    Set-Item -Path "WSMan:\localhost\Service\AllowUnencrypted" -Value $true
    Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true

    # Configure firewall to allow WinRM
    Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"

    # Allow all hosts in TrustedHosts for WinRM connections
    try {
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
        Write-Host "TrustedHosts set to '*' (all hosts allowed)."
    } catch {
        Write-Warning "Failed to set TrustedHosts: $_"
    }
    Write-Host "Remote management ENABLED."
} elseif ($remoteMgmt -eq 'disable') {
    # Disable PowerShell Remoting
    Disable-PSRemoting -Force

    # Remove firewall rule for WinRM
    Disable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"

    # Clear TrustedHosts
    try {
        Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "" -Force
        Write-Host "TrustedHosts cleared."
    } catch {
        Write-Warning "Failed to clear TrustedHosts: $_"
    }
    Write-Host "Remote management DISABLED."
} else {
    Write-Warning "Invalid input. No changes made to remote management."
}


# Get local IPv4 addresses (excluding loopback and APIPA)
$ipList = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.InterfaceAlias -notlike 'Loopback*'
}).IPAddress

Write-Host "User $Username created and added to Administrators."
if ($remoteMgmt -eq 'enable') {
    Write-Host "PowerShell Remoting ENABLED."
    Write-Host "Connect to this machine using IP: $($ipList -join ', ')"
} elseif ($remoteMgmt -eq 'disable') {
    # Remove the admin user
    try {
        Remove-LocalUser -Name $Username -ErrorAction Stop
        Write-Host "User $Username has been removed."
    } catch {
    Write-Warning "Failed to remove user $Username: ${_}"
    }
    Write-Host "PowerShell Remoting DISABLED. Remote connection is not available."
} else {
    Write-Host "No changes made to remote management."
}
