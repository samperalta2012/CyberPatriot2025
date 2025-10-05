# Simple helper: create a persistent WinRM PSSession using the repo test defaults
# Prompts for target IP/hostname, creates a PSCredential from the known default account,
# creates a New-PSSession, stores it in $Global:PersistentPSSession and saves metadata to
# %UserProfile%\.cyberpatriot\session.json and credentials to creds.xml (encrypted for this user).

param(
    [string]$ComputerName
)

# Embedded credentials region (for lab/testing only).
# The script will replace the content between these markers when you choose to save credentials into the script.
# <EMBEDDED_CREDENTIALS_START>
$EmbeddedUsername = 'RemoteAdmin'
$EmbeddedPlainPassword = 'P@ssw0rd123!'
# <EMBEDDED_CREDENTIALS_END>

if (-not $ComputerName) {
    $ComputerName = Read-Host "Enter the IP address or hostname of the remote host"
}
if (-not $ComputerName) { Write-Error "No target supplied. Aborting."; exit 1 }

# Determine username/password to use. Prefer embedded credentials if present in this script.
if ($EmbeddedPlainPassword -and $EmbeddedPlainPassword.Trim() -ne '') {
    try {
        $Username = if ($EmbeddedUsername -and $EmbeddedUsername.Trim() -ne '') { $EmbeddedUsername } else { 'RemoteAdmin' }
        # Embedded plaintext password (lab use only)
        $SecurePassword = ConvertTo-SecureString $EmbeddedPlainPassword -AsPlainText -Force
        Write-Host "Using embedded plaintext credentials from this script for user '$Username'."
    } catch {
        Write-Warning "Failed to convert embedded plaintext password: $_. Falling back to default plaintext password."
        $Username = 'RemoteAdmin'
        $PlainPassword = 'P@ssw0rd123!'
        $SecurePassword = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
    }
} else {
    $Username = 'RemoteAdmin'
    $PlainPassword = 'P@ssw0rd123!'
    $SecurePassword = ConvertTo-SecureString $PlainPassword -AsPlainText -Force
}
$Cred = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)

Write-Host "Creating persistent WinRM session to $ComputerName as $Username..."
try {
    $session = New-PSSession -ComputerName $ComputerName -Credential $Cred -Authentication Default -ErrorAction Stop
} catch {
    Write-Error "Failed to create PSSession: $_"
    exit 2
}

# assign global variable for current shell
$Global:PersistentPSSession = $session

# ensure .cyberpatriot dir exists and save metadata + creds
$credDir = Join-Path $env:USERPROFILE '.cyberpatriot'
if (-not (Test-Path $credDir)) { New-Item -Path $credDir -ItemType Directory -Force | Out-Null }

$sessionMeta = @{ ComputerName = $ComputerName; Transport = 'WinRM'; Username = $Username; SessionId = $session.Id; Created = (Get-Date); CredFile = '' }
    try {
        # Always embed plaintext credentials into the script for lab testing
        $plain = if ($PlainPassword) { $PlainPassword } else { $EmbeddedPlainPassword }
        # Escape single quotes so the embedded literal does not break the script
        $plainForEmbed = $plain -replace "'", "''"
        $userForEmbed  = $Username -replace "'", "''"
        $scriptPath = $MyInvocation.MyCommand.Definition
        $raw = Get-Content -Path $scriptPath -Raw
        $start = '# <EMBEDDED_CREDENTIALS_START>'
        $end   = '# <EMBEDDED_CREDENTIALS_END>'
        $replacement = "$start`n`$EmbeddedUsername = '$userForEmbed'`n`$EmbeddedPlainPassword = '$plainForEmbed'`n$end"
        if ($raw -match [regex]::Escape($start)) {
            $pattern = [regex]::Escape($start) + '.*?' + [regex]::Escape($end)
            $new = [regex]::Replace($raw, $pattern, $replacement, [System.Text.RegularExpressions.RegexOptions]::Singleline)
            Set-Content -Path $scriptPath -Value $new -Force
            Write-Host "Embedded plaintext credentials written into script: $scriptPath"
            $sessionMeta.CredFile = ''
        } else {
            Write-Warning "Could not find embedded credentials markers in the script to update."
        }
    } catch {
        Write-Warning "Failed to embed credentials into script: $_"
    }
$sessionFile = Join-Path $credDir 'session.json'
$sessionMeta | ConvertTo-Json | Set-Content -Path $sessionFile -Force
Write-Host "Session metadata saved to: $sessionFile"

Write-Host "Persistent PSSession created (Id=$($session.Id)). Stored in \$Global:PersistentPSSession."
Write-Host "Example: Enter-PSSession -Session \$Global:PersistentPSSession"
Write-Host "Example: Invoke-Command -Session \$Global:PersistentPSSession -ScriptBlock { Get-Process | Select-Object -First 5 }"

$enterNow = Read-Host "Enter the remote interactive shell now? (y/N)"
if ($enterNow -match '^[Yy]') {
    try {
        Enter-PSSession -Session $Global:PersistentPSSession -ErrorAction Stop
    } catch {
        Write-Error "Failed to enter remote session: $_"
        exit 3
    }
}

Write-Host "Done."
