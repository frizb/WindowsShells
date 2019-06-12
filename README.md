# WindowsShells
Today, there are several methods that can be utilized to gain shell access on a Windows Machine once you have verified credentials.
Here I will document the various tools, methods and commands that can be used:


## PSEXEC

PSEXEC allows for remote command execution or a remote shell.

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


## PowerShell Remoting
PowerShell only works if the remote machine already has PowerShell installed and if PowerShell remoting is configured to allow remote access. 
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


# REFERENCES:  
*  https://blog.quickbreach.io/ps-remote-from-linux-to-windows/
*  https://4sysops.com/archives/enable-powershell-remoting-on-a-standalone-workgroup-computer/
*  
