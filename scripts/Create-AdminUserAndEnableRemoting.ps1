
param(
    [string]$Username,
    [SecureString]$Password
)

# Require Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run as Administrator. Exiting."
    exit 1
}

# Prompt user to enable or disable remote management first
$remoteMgmt = Read-Host "Remote management: Enter 1 to ENABLE or 2 to DISABLE"

# Set defaults if not provided (after prompt)
if (-not $Username) { $Username = "RemoteAdmin" }
if (-not $Password) { $Password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force }
$SecurePassword = $Password

switch ($remoteMgmt) {
    '1' {
        # Create the user account if it doesn't exist, or offer to reset the password
        try {
            if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
                New-LocalUser -Name $Username -Password $SecurePassword -FullName "Remote Admin User" -Description "Account for remote PowerShell access" -PasswordNeverExpires -AccountNeverExpires
                Write-Host "User $Username created."
            } else {
                Write-Host "User $Username already exists."
                $reset = Read-Host "Do you want to reset the password for $Username to the configured value? (y/N)"
                if ($reset -match '^[Yy]') {
                    try {
                        Set-LocalUser -Name $Username -Password $SecurePassword -ErrorAction Stop
                        Write-Host "Password for $Username has been reset."
                    } catch {
                        Write-Warning ("Failed to reset password for {0}: {1}" -f $Username, $_)
                    }
                }
            }
        } catch {
            Write-Warning ("Failed to create or update user {0}: {1}" -f $Username, $_)
            break
        }

        # Add user to Administrators group if not already a member
        try {
            $accountName = "$($env:COMPUTERNAME)\$Username"
            $inAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $accountName -or $_.Name -eq $Username }
            if (-not $inAdmins) {
                Add-LocalGroupMember -Group "Administrators" -Member $Username
                Write-Host "$Username added to Administrators group."
            } else {
                Write-Host "$Username is already a member of Administrators group."
            }
        } catch {
            Write-Warning ("Failed to add user {0} to Administrators: {1}" -f $Username, $_)
        }

        # Ask which transport(s) to enable
    $transportChoice = Read-Host "Choose transport to enable: W=WinRM, S=SSH, B=Both (default S)"
    if (-not $transportChoice) { $transportChoice = 'S' }

        # Enable PowerShell Remoting
        try {
            Enable-PSRemoting -Force
        } catch {
            Write-Warning ("Enable-PSRemoting reported: {0}" -f $_)
        }

        # Ensure WinRM service is running and configured
        try {
            Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name WinRM -ErrorAction SilentlyContinue
            # Run winrm quickconfig to make sure listeners and firewall rules are present
            Start-Process -FilePath winrm -ArgumentList 'quickconfig -quiet' -NoNewWindow -Wait -ErrorAction SilentlyContinue
        } catch {
            Write-Warning ("Failed to ensure WinRM service or quickconfig: {0}" -f $_)
        }

        # Create a listener for all IPs if one does not exist
        try {
            $listeners = Get-ChildItem -Path WSMan:\Localhost\Listener -ErrorAction SilentlyContinue
            if (-not $listeners) {
                New-Item -Path WSMan:\Localhost\Listener -Transport HTTP -Address * -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {
            # ignore if it already exists or cannot be created
        }

        # Allow local accounts to authenticate over the network by adjusting LocalAccountTokenFilterPolicy
        try {
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            New-ItemProperty -Path $regPath -Name 'LocalAccountTokenFilterPolicy' -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host "LocalAccountTokenFilterPolicy set to 1 (local accounts allowed remote admin access)."
        } catch {
            Write-Warning ("Failed to set LocalAccountTokenFilterPolicy: {0}" -f $_)
        }

        # Configure WinRM
        try {
            Set-Item -Path "WSMan:\localhost\Service\AllowUnencrypted" -Value $true -Force
            Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true -Force
            # Also enable Basic auth and allow unencrypted traffic for the WSMan client on this machine (useful for testing)
            Set-Item -Path "WSMan:\localhost\Client\Auth\Basic" -Value $true -Force
            Set-Item -Path "WSMan:\localhost\Client\AllowUnencrypted" -Value $true -Force
        } catch {
            Write-Warning ("Failed to configure WinRM settings: {0}" -f $_)
        }

        # Configure firewall to allow WinRM (if rule exists)
        try {
            if (-not (Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -ErrorAction SilentlyContinue)) {
                # Create a permissive rule for WinRM over HTTP
                New-NetFirewallRule -DisplayName "WinRM HTTP-In" -Name "WINRM-HTTP-In-TCP" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any -ErrorAction SilentlyContinue
            } else {
                Enable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"
            }
        } catch {
            Write-Warning ("Failed to enable firewall rule for WinRM: {0}" -f $_)
        }

        # Allow all hosts in TrustedHosts for WinRM connections
        try {
            Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
            Write-Host "TrustedHosts set to '*' (all hosts allowed)."
        } catch {
            Write-Warning ("Failed to set TrustedHosts: {0}" -f $_)
        }

        # Also ensure Windows PowerShell (WindowsPS) remoting endpoints and WSMan settings are configured
        try {
            $winpsCommand = {
                Enable-PSRemoting -Force
                Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true -Force
                Set-Item -Path WSMan:\localhost\Client\Auth\Basic -Value $true -Force
                Set-Item -Path WSMan:\localhost\Client\AllowUnencrypted -Value $true -Force
                Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
            }
            # Run the above block in Windows PowerShell to ensure Windows PowerShell endpoints are configured
            $scriptBlock = $winpsCommand.ToString()
            Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-Command', $scriptBlock -Wait -NoNewWindow -ErrorAction SilentlyContinue
        } catch {
            Write-Warning ("Failed to configure Windows PowerShell remoting settings: {0}" -f $_)
        }

        # Get local IPv4 addresses (excluding loopback and APIPA)
        $ipList = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.InterfaceAlias -notlike 'Loopback*'
        }).IPAddress

        Write-Host "Remote management ENABLED."
        Write-Host "Connect to this machine using IP: $($ipList -join ', ')"

        # SSH installation/configuration if requested
        if ($transportChoice -match '^[SsB]') {
            try {
                Write-Host "Configuring OpenSSH Server..."
                $cap = Get-WindowsCapability -Online -Name OpenSSH.Server* -ErrorAction SilentlyContinue
                if ($cap -and $cap.State -ne 'Installed') {
                    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop
                }
                if (Get-Service -Name sshd -ErrorAction SilentlyContinue) {
                    Set-Service -Name sshd -StartupType Automatic
                    Start-Service -Name sshd -ErrorAction SilentlyContinue
                }
                if (-not (Get-NetFirewallRule -Name "SSHD-In-TCP" -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName "OpenSSH SSH Server (sshd)" -Name "SSHD-In-TCP" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any -ErrorAction SilentlyContinue
                } else {
                    Enable-NetFirewallRule -Name "SSHD-In-TCP"
                }

                $sshdConfig = "$env:ProgramData\ssh\sshd_config"
                if (Test-Path $sshdConfig) {
                    $cfg = Get-Content $sshdConfig -ErrorAction SilentlyContinue
                    $cfg = $cfg -replace '^(#\s*)?PasswordAuthentication\s+.*', 'PasswordAuthentication yes'
                    $cfg = $cfg -replace '^(#\s*)?PubkeyAuthentication\s+.*', 'PubkeyAuthentication yes'
                    $cfg | Set-Content -Path $sshdConfig -Force
                    Restart-Service -Name sshd -ErrorAction SilentlyContinue
                }

                # Optionally create a default .ssh directory and warn about key-based auth
                # Generate SSH keypair for client and install public key for the created user
                try {
                    $credDir = Join-Path $env:USERPROFILE '.cyberpatriot'
                    if (-not (Test-Path $credDir)) { New-Item -Path $credDir -ItemType Directory -Force | Out-Null }
                    $privateKey = Join-Path $credDir 'id_rsa'
                    $publicKey = "$privateKey.pub"
                    if (-not (Test-Path $privateKey)) {
                        if (Get-Command ssh-keygen -ErrorAction SilentlyContinue) {
                            & ssh-keygen -t rsa -b 4096 -f $privateKey -N "" | Out-Null
                            Write-Host "SSH keypair generated at $privateKey"
                        } else {
                            Write-Warning "ssh-keygen not available; skipping key generation."
                        }
                    }

                    if (Test-Path $publicKey) {
                        $userProfilePath = Join-Path 'C:\Users' $Username
                        $sshDir = Join-Path $userProfilePath '.ssh'
                        if (-not (Test-Path $sshDir)) { New-Item -Path $sshDir -ItemType Directory -Force | Out-Null }
                        $authFile = Join-Path $sshDir 'authorized_keys'
                        Get-Content $publicKey | Add-Content -Path $authFile -Force
                        try {
                            icacls $sshDir /inheritance:r | Out-Null
                            icacls $sshDir /grant "$($Username):(F)" | Out-Null
                        } catch {
                            # best effort
                        }
                        Write-Host "Public key installed for $Username."
                    }

                    # Offer to save credentials and connection metadata for reuse by client scripts
                    $save = Read-Host "Save connection metadata and credentials for reuse on this machine? (y/N)"
                    if ($save -match '^[Yy]') {
                        $pscred = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)
                        $credFile = Join-Path $credDir 'creds.xml'
                        try {
                            $pscred | Export-Clixml -Path $credFile -Force
                            Write-Host "Credentials saved to $credFile (encrypted for this user)."
                        } catch {
                            Write-Warning "Failed to save credentials: $_"
                        }

                        $config = @{ DefaultTransport = 'SSH'; Username = $Username; KeyPath = $privateKey; CredFile = $credFile }
                        $configFile = Join-Path $credDir 'connection.json'
                        $config | ConvertTo-Json | Set-Content -Path $configFile -Force
                        Write-Host "Connection metadata saved to $configFile"
                    }
                } catch {
                    Write-Warning ("Failed to generate/install SSH keys or save metadata: {0}" -f $_)
                }
                Write-Host "OpenSSH Server installed and configured (password authentication enabled for testing)."
            } catch {
                Write-Warning ("Failed to install/configure OpenSSH Server: {0}" -f $_)
            }
        }
    }
    '2' {
        # Disable PowerShell Remoting
        try {
            Disable-PSRemoting -Force
        } catch {
            Write-Warning ("Disable-PSRemoting reported: {0}" -f $_)
        }

        # Remove firewall rule for WinRM
        try {
            if (Get-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -ErrorAction SilentlyContinue) {
                Disable-NetFirewallRule -Name "WINRM-HTTP-In-TCP"
            }
        } catch {
            Write-Warning ("Failed to disable firewall rule for WinRM: {0}" -f $_)
        }

        # Clear TrustedHosts
        try {
            Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "" -Force
            Write-Host "TrustedHosts cleared."
        } catch {
            Write-Warning ("Failed to clear TrustedHosts: {0}" -f $_)
        }

        # Remove the admin user if it exists
        try {
            if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
                # Remove from Administrators group if present
                try {
                    if (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "$($env:COMPUTERNAME)\$Username" -or $_.Name -eq $Username }) {
                        Remove-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue
                    }
                } catch {
                    Write-Warning ("Failed to remove {0} from Administrators: {1}" -f $Username, $_)
                }

                Remove-LocalUser -Name $Username -ErrorAction Stop
                Write-Host "User $Username has been removed."
            } else {
                Write-Host "User $Username does not exist. No user removed."
            }
        } catch {
            Write-Warning ("Failed to remove user {0}: {1}" -f $Username, $_)
        }

        Write-Host "Remote management DISABLED."
    }
    Default {
        Write-Warning "Invalid input. No changes made to remote management."
    }
}
