### **CyberPatriot Competition Start-Up Checklist**

This document provides a systematic approach to the initial phase of any CyberPatriot competition round. By following these steps, our team can ensure a consistent and effective start, allowing us to maximize our time and points.

#### **1\. Pre-Competition Preparation**

Before the six-hour competition period begins, there are critical steps to take.

* **Download and Verify Images:** Your coach will receive an email with links to download the virtual machine (VM) images. These files are large, so download them well in advance.  
  * **Action:** Download all provided VM images.  
  * **Verification:** Use a tool like WinMD5 to verify the checksum of each image. This confirms that the file was downloaded without any corruption.  
  * **Command Prompt (Windows):** certutil \-hashfile "C:\\path\\to\\your\\image.zip" MD5  
  * **Terminal (Linux):** md5sum /path/to/your/image.zip  
* **Acquire the Unique Identifier:** The unique identifier (Team ID) is a 12-digit alphanumeric code assigned to your team for the round. This is essential for scoring. Your coach will have this on their dashboard.  
  * **Action:** Ensure the coach has the unique identifier and shares it with the team. Do not open the images or enter the ID until the competition period begins.

#### **2\. The First Five Minutes of Competition**

The clock starts ticking as soon as the first VM image is launched. These first few minutes are crucial for setting the stage for the rest of the round.

* **Read the Scenario File:** Every image has a README or scenario file on the desktop. **Read this first\!** It provides crucial information about the network, the vulnerabilities to look for, and the services that must remain functional. Ignoring this can lead to major point deductions.  
* **Establish a Game Plan:** As a team, quickly discuss and assign roles. A common strategy is to have specialists for different operating systems (e.g., one person for Windows, one for Linux) and a team member for the networking challenges.  
  * **Windows Specialist:** Focus on user accounts, local security policies, firewalls, and malicious software.  
  * **Linux Specialist:** Focus on user permissions, services, and package management.  
  * **Networking Specialist:** Focus on the Cisco Networking Challenge (Packet Tracer and quiz).  
  * **Forensics/Research:** A team member can be dedicated to answering forensic questions and researching unfamiliar vulnerabilities.  
* **Enter the Unique Identifier:** The very first action on each VM should be to enter the unique identifier.  
  * **Action:** Once the VM is loaded, enter the Team ID in the designated box. This starts the scoring process for that image.

#### **3\. General Hardening and Initial Sweeps**

Once the game plan is established, begin with a systematic "initial sweep" to address the most common vulnerabilities across all operating systems. This helps to secure easy points quickly and provides a solid foundation for the more complex tasks.

* **Account Management:**  
  * **Remove unauthorized users.** Look for any accounts that seem out of place.  
  * **Change or secure passwords** for known administrative accounts and any vulnerable users.  
  * **Check for unauthorized sudo or administrator privileges.**  
* **Services:**  
  * **Disable unnecessary services.** Turn off any services that are not required for the scenario. For example, if the scenario doesn't mention a web server, disable the web server service.  
  * **Windows:** Open the services.msc console.  
  * **Linux:** Use commands like systemctl list-units \--type=service to see what is running.  
* **Malicious Files:**  
  * **Windows:** Check the Program Files, ProgramData, and C:\\Users\\username\\Downloads directories for suspicious files.  
  * **Linux:** Look in /home, /tmp, and /var/www/html for any unexpected files.  
* **Firewall:**  
  * **Windows:** Enable and configure the Windows Defender Firewall to block all unnecessary inbound traffic.  
  * **Linux:** Use ufw (Uncomplicated Firewall) or iptables to configure a firewall.

#### **4\. Scripting for Efficiency (Beginner-Friendly)**

While a team should never rely solely on scripts, using simple scripts for repetitive tasks can be a massive time-saver. Here are some beginner-friendly examples.

**Disclaimer:** These scripts are for educational purposes within the competition environment. **Do not run them on a personal computer or in any environment without explicit permission.**

##### **Windows (PowerShell)**

You can save these commands in a .ps1 file and run them.

* **Getting a List of Users:** This helps you quickly see all the users on the system.  
  PowerShell  
  Get-LocalUser | Format-Table Name, Enabled, PasswordRequired

* **Finding Files by Extension:** This can help you quickly find potentially malicious files like .exe or .vbs in specific directories.  
  PowerShell  
  \# Finds all .exe files in the C:\\ directory and subdirectories  
  Get-ChildItem \-Path C:\\ \-Recurse \-Include \*.exe | Select-Object FullName

* **Disabling a User Account:**  
  PowerShell  
  \# Replace 'UnauthorizedUser' with the actual username  
  Disable-LocalUser \-Name "UnauthorizedUser"

##### **Linux (Bash)**

You can save these commands in a .sh file and run them.

* **Listing Users and Their Home Directories:** This helps identify any accounts that don't belong.  
  Bash  
  cat /etc/passwd | awk \-F: '{print $1, $6}'

* **Finding Files with Root Permissions:** Look for files that have special permissions that could be a vulnerability.  
  Bash  
  \# Finds files in the /home directory that have SUID permissions  
  find /home \-perm \-4000

* **Disabling a User's Shell Access:** This prevents a user from logging in without removing their account entirely, which is sometimes a requirement.  
  Bash  
  \# Replace 'unauthorizeduser' with the actual username  
  usermod \-s /sbin/nologin unauthorizeduser

**To run a script:**

1. **Save the file** with the correct extension (.ps1 for PowerShell, .sh for Bash).  
2. **Windows (PowerShell):** Open PowerShell as an administrator, navigate to the directory where you saved the file, and run .\\your\_script\_name.ps1. You may need to change the execution policy first by running Set-ExecutionPolicy RemoteSigned.  
3. **Linux (Bash):** Open a terminal, navigate to the directory, make the script executable with chmod \+x your\_script\_name.sh, and then run it with ./your\_script\_name.sh.

#### **5\. After the Initial Sweeps**

Once the initial checklist is complete, the team can dive deeper into the specific tasks outlined in the scenario file. This is where advanced knowledge and research skills come into play. Always be checking the scoring report to confirm that your fixes are earning points.

This guide provides a solid framework. As your team gains experience, you can customize and expand it with more specific commands and strategies tailored to your strengths. Good luck\!