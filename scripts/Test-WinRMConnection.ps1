<#
.SYNOPSIS
	Test WinRM connectivity and optionally create a persistent PSSession for interactive use.

.DESCRIPTION
	Performs network and port checks, attempts to create a PSSession using stored credentials
	or sensible defaults, and optionally creates and saves a persistent session to
	%UserProfile%\.cyberpatriot\session.json. When a session is created the script
	prints connection details and example commands to interact with the persistent session.

.PARAMETER ComputerName
	Target host to test. If omitted the script will default to the first non-loopback IPv4
	on this machine (useful for local testing).

.PARAMETER Persist
	If specified the script will create and save a persistent session automatically.

.PARAMETER UseStored
	If specified the script will attempt to use stored credentials and metadata from
	%UserProfile%\.cyberpatriot. If not present the script will fall back to the
	Create-script defaults for lab testing (RemoteAdmin / P@ssw0rd123!).

.EXAMPLE
	pwsh -File .\scripts\Test-WinRMConnection.ps1 -ComputerName 192.168.5.10 -Persist

	Tests connectivity to 192.168.5.10 and creates a persistent session saved to disk.
#>

param(
	[string]$ComputerName,
	[switch]$Persist,
	[switch]$UseStored,
	[switch]$RunNow
)

function Write-Status($level, $message) {
	switch ($level) {
		'OK' { Write-Host "[ OK ] $message" -ForegroundColor Green }
		'WARN' { Write-Host "[WARN] $message" -ForegroundColor Yellow }
		'ERR' { Write-Host "[ERR] $message" -ForegroundColor Red }
		Default { Write-Host "[INFO] $message" }
	}
}

# Determine target
if (-not $ComputerName) {
	$ComputerName = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.InterfaceAlias -notmatch 'Loopback' } | Select-Object -First 1).IPAddress
	if (-not $ComputerName) {
		Write-Status 'ERR' 'Could not determine a default local IP to test. Provide -ComputerName.'
		exit 2
	}
	Write-Host "No -ComputerName supplied; using local IP $ComputerName for testing."
}

# Load stored config/credentials if requested
$cred = $null
$config = $null
$credDir = Join-Path $env:USERPROFILE '.cyberpatriot'
$configFile = Join-Path $credDir 'connection.json'
if ($UseStored -and (Test-Path $configFile)) {
	try {
		$config = Get-Content $configFile | ConvertFrom-Json
		Write-Status 'OK' "Loaded stored connection metadata from $configFile"
		if ($config.CredFile -and (Test-Path $config.CredFile)) {
			try {
				$cred = Import-Clixml -Path $config.CredFile
				Write-Status 'OK' "Imported credentials from stored file"
			} catch {
				Write-Status 'WARN' ("Failed to import stored credentials: {0}. Will fall back to defaults." -f $_)
				$cred = $null
			}
		}
	} catch {
		Write-Status 'WARN' ("Failed to read stored connection metadata: {0}. Will fall back to defaults." -f $_)
	}
} elseif ($UseStored) {
	Write-Status 'WARN' "UseStored specified but no stored metadata found at $configFile. Falling back to defaults."
}

# If no credential yet, use Create script defaults for lab testing
if (-not $cred) {
	if ($config -and $config.Username) { $user = $config.Username } else { $user = 'RemoteAdmin' }
	$plain = 'P@ssw0rd123!'
	$secureDefault = ConvertTo-SecureString $plain -AsPlainText -Force
	try { $cred = New-Object System.Management.Automation.PSCredential($user, $secureDefault); Write-Status 'WARN' "Using test default credentials for user '$user'." } catch { Write-Status 'ERR' ("Failed to construct default credential: {0}" -f $_); exit 2 }
}

# Network checks
Write-Host "\n== Network checks =="
try {
	$ping = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet
	if ($ping) { Write-Status 'OK' "ICMP ping to $ComputerName succeeded." } else { Write-Status 'WARN' "ICMP ping to $ComputerName failed or blocked." }
} catch { Write-Status 'WARN' ("Ping test failed with error: {0}" -f $_) }

# Port checks
Write-Host "\n== Port checks =="
try {
	$p1 = Test-NetConnection -ComputerName $ComputerName -Port 5985 -WarningAction SilentlyContinue
	if ($p1.TcpTestSucceeded) { Write-Status 'OK' "TCP 5985 (WinRM HTTP) is reachable on $ComputerName." } else { Write-Status 'WARN' "TCP 5985 is not reachable on $ComputerName." }
} catch { Write-Status 'WARN' ("Port test 5985 failed: {0}" -f $_) }
try {
	$p2 = Test-NetConnection -ComputerName $ComputerName -Port 5986 -WarningAction SilentlyContinue
	if ($p2.TcpTestSucceeded) { Write-Status 'OK' "TCP 5986 (WinRM HTTPS) is reachable on $ComputerName." } else { Write-Status 'WARN' "TCP 5986 is not reachable on $ComputerName." }
} catch { Write-Status 'WARN' ("Port test 5986 failed: {0}" -f $_) }

# Attempt to create a PSSession
Write-Host "\n== WinRM session test =="
$session = $null
function Test-NewPSSession([string]$auth) {
	try {
		Write-Host "Trying New-PSSession to $ComputerName with Authentication=$auth..."
		if ($auth -eq 'Default') { $s = New-PSSession -ComputerName $ComputerName -Credential $cred -ErrorAction Stop } else { $s = New-PSSession -ComputerName $ComputerName -Credential $cred -Authentication $auth -ErrorAction Stop }
		Write-Status 'OK' ("New-PSSession created (Authentication={0})." -f $auth)
		return $s
	} catch { Write-Status 'WARN' ("New-PSSession failed for Authentication={0}: {1}" -f $auth, $_); return $null }
}

$authMethods = @('Default','Negotiate','Basic')
foreach ($a in $authMethods) { $s = Test-NewPSSession -auth $a; if ($s) { $session = $s; break } }

if (-not $session) { Write-Status 'ERR' "Unable to create a PSSession to $ComputerName with provided credentials/authentication methods."; exit 3 }

# If we reach here we have a working session. Run basic commands to validate
try {
	$results = Invoke-Command -Session $session -ScriptBlock { [PSCustomObject]@{ HostName = (hostname); User = (whoami); WinRMService = (Get-Service -Name WinRM -ErrorAction SilentlyContinue).Status } } -ErrorAction Stop
	Write-Status 'OK' "Invoke-Command returned results."
	$results | Format-List
} catch { Write-Status 'ERR' ("Invoke-Command failed: {0}" -f $_); Remove-PSSession -Session $session -ErrorAction SilentlyContinue; exit 4 }

# Optionally create a persistent session
if ($Persist -or (Read-Host "Create and save a persistent session for easier interaction? (y/N)" -match '^[Yy]')) {
	try {
		# Save session to global var for current shell
		$Global:PersistentPSSession = $session
		$sessionMeta = @{ ComputerName = $ComputerName; Transport = 'WinRM'; Username = $cred.UserName; SessionId = $session.Id; Created = (Get-Date) }
		if (-not (Test-Path $credDir)) { New-Item -Path $credDir -ItemType Directory -Force | Out-Null }
		$sessionFile = Join-Path $credDir 'session.json'
		$sessionMeta | ConvertTo-Json | Set-Content -Path $sessionFile -Force
	Write-Status 'OK' "Persistent session created (Id=$($session.Id)) and metadata saved to $sessionFile"

		# Show example commands and details
		Write-Host "\nPersistent session details:" -ForegroundColor Cyan
		Write-Host "  ComputerName: $($sessionMeta.ComputerName)"
		Write-Host "  Transport:    $($sessionMeta.Transport)"
		Write-Host "  Username:     $($sessionMeta.Username)"
		Write-Host "  SessionId:    $($sessionMeta.SessionId)"
		Write-Host "\nExample commands you can run now:" -ForegroundColor Cyan
		Write-Host "  # Enter interactive remote prompt using saved session"
		Write-Host "  Enter-PSSession -Session `$Global:PersistentPSSession"
		Write-Host "\n  # Run a command using the persistent session"
		Write-Host "  Invoke-Command -Session `$Global:PersistentPSSession -ScriptBlock { Get-Process | Select-Object -First 5 }"
	Write-Host "\n  # Close and remove the session"
	Write-Host "  Remove-PSSession -Session `$Global:PersistentPSSession; Remove-Variable PersistentPSSession -Scope Global"
		Write-Host "\n  # Recreate in a new shell (if you saved creds/metadata)"
		Write-Host "  # (See scripts/Reconnect-PersistentSession.ps1 in the repo)"
	} catch { Write-Status 'WARN' ("Failed to create/save persistent session: {0}" -f $_) }

	# Optionally run a set of sample commands against the persistent session
	$runSample = $false
	if ($RunNow) { $runSample = $true } else {
		$choice = Read-Host "Run a set of sample commands against the persistent session now? (y/N)"
		if ($choice -match '^[Yy]') { $runSample = $true }
	}
	if ($runSample) {
		try {
			Write-Host "\nRunning sample commands against persistent session..." -ForegroundColor Cyan
			$res1 = Invoke-Command -Session $Global:PersistentPSSession -ScriptBlock { Get-Process | Select-Object -First 5 } -ErrorAction Stop
			Write-Host "\nTop processes:" -ForegroundColor Cyan; $res1 | Format-Table -AutoSize

			$res2 = Invoke-Command -Session $Global:PersistentPSSession -ScriptBlock { Get-Service -Name WinRM -ErrorAction SilentlyContinue } -ErrorAction Stop
			Write-Host "\nWinRM service status:" -ForegroundColor Cyan; $res2 | Format-List

			$res3 = Invoke-Command -Session $Global:PersistentPSSession -ScriptBlock { Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } } -ErrorAction Stop
			Write-Host "\nRemote IPv4 addresses:" -ForegroundColor Cyan; $res3 | Format-Table -AutoSize

			$res4 = Invoke-Command -Session $Global:PersistentPSSession -ScriptBlock { Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object CSName, LastBootUpTime } -ErrorAction Stop
			Write-Host "\nRemote OS info:" -ForegroundColor Cyan; $res4 | Format-List
		} catch {
			Write-Status 'WARN' ("One or more sample commands failed: {0}" -f $_)
		}

		# (Samples finished) -- persistent session will be entered after this block
	}
	# Enter the persistent remote shell so the user is left in an interactive session
	try {
		Write-Host "\nEntering interactive remote session using persistent session (Exit-PSSession to return)..." -ForegroundColor Cyan
		Enter-PSSession -Session $Global:PersistentPSSession -ErrorAction Stop
		Write-Host "Returned from remote session. Persistent session remains available and metadata saved to $sessionFile" -ForegroundColor Green
	} catch {
		Write-Status 'WARN' ("Failed to enter persistent remote session interactively: {0}" -f $_)
	}
} else {
	# Enter a temporary interactive remote shell and then clean up the session after the user exits
	try {
		Write-Host "\nEntering temporary interactive remote session (Exit-PSSession to return)..." -ForegroundColor Cyan
		Enter-PSSession -Session $session -ErrorAction Stop
	} catch {
		Write-Status 'WARN' ("Failed to enter temporary remote session interactively: {0}" -f $_)
	} finally {
		try { Remove-PSSession -Session $session -ErrorAction SilentlyContinue } catch {}
		Write-Host "Temporary test session closed."
	}
}

Write-Host "\nWinRM remote command test completed."
exit 0

