
# Prompt for VM IP address
$VMIP = Read-Host "Enter the IP address of the remote VM"

# Use fixed credentials
$Username = "RemoteAdmin"
$Password = "P@ssw0rd123!"
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential($Username, $SecurePassword)

# Connect to remote PowerShell session
Enter-PSSession -ComputerName $VMIP -Credential $Cred
