# Credit for several of the commands used https://github.com/xFaraday/EzScript/blob/master/ezscript.ps1
# Credit for several of the commands used https://github.com/ponkio/CyberPatriot/blob/master/Windows.bat

#Requires -RunAsAdministrator
param ($userfile="users.txt", $adminfile="admins.txt", $secfile="secconfig.cfg")


#============================================
# Clear Unapproved Users
#============================================
# Checks list of "approved" users vs users
#  on the system and removes unapproved users
#============================================
function Clear-UnapprovedUsers {
    Write-Host "`n--- Removing Unapproved Users ---" -ForegroundColor Blue -BackgroundColor White
    [String[]] $allowedUsers = Get-Content -Path $userfile
    $badUsers = New-Object System.Collections.Generic.List[System.Object]
    foreach ($user in (Get-LocalUser)) {
        if ( -not ($allowedUsers.Contains($user.Name)) -and ($user.Enabled)) {
            $badUsers.Add($user.Name)
        }
    }

    if ( -not ($badUsers.count -eq 0)) {
        Write-Host "--- USER TO BE REMOVED ---" -ForegroundColor Yellow
        $i = 0
        foreach ($person in $badUsers) {
            Write-Host ($i.ToString() + ") " + $person)
            $i += 1
        }

        $confirmation = Read-Host "Confirm? [y/n]"
        [string[]] $SaveList= @()
        if ( -not ($confirmation -eq "y")) {
            $SaveList = Read-Host "User to skip: [E.g: 0, 2, 3]"
            $SaveList = $SaveList.Split(',').Split(' ')
        }

        if ( -not ($badUsers.count -eq 0)) {
            $i = 0
            foreach ($person in $badUsers) {
                if ( -not ($SaveList.Contains($i.ToString()))) {
                    Remove-LocalUser -Name $badUsers.ToArray()[$i]
                    Write-Host ("Removed: " + $person)  -ForegroundColor Red 
                } else {
                    Write-Host ("Skipped: " + $person) -ForegroundColor Green
                }
                $i += 1
            }
        }
        Write-Host "--- SUCCESFULLY REMOVED USERS ---" -ForegroundColor Yellow
    } else {
        Write-Host "--- NO USERS TO BE REMOVED ---" -ForegroundColor Yellow
    }
}

#============================================
# Add Missing Users
#============================================
# Checks the list of "approved" users and 
#  adds any user who is missing
#============================================
function Add-MissingUsers {
    Write-Host "`n--- Adding Missing User ---" -ForegroundColor Blue -BackgroundColor White
    [String[]] $allowedUsers = Get-Content -Path $userfile
    $missingUsers = New-Object System.Collections.Generic.List[System.Object]
    foreach ($user in $allowedUsers) {
        if ( -not ($(Get-LocalUser).Name.Contains($user))) {
            $missingUsers.Add($user)
        }
    }

    if ( -not ($missingUsers.count -eq 0)) {
        Write-Host "--- USER TO BE ADDED ---" -ForegroundColor Yellow
        $i = 0
        foreach ($person in $missingUsers) {
            Write-Host ($i.ToString() + ") " + $person)
            $i += 1
        }

        $confirmation = Read-Host "Confirm? [y/n]"
        [string[]] $SaveList= @()
        if ( -not ($confirmation -eq "y")) {
            $SaveList = Read-Host "User to skip: [E.g: 0, 2, 3]"
            $SaveList = $SaveList.Split(',').Split(' ')
        }

        if ( -not ($missingUsers.count -eq 0)) {
            $i = 0
            foreach ($person in $missingUsers) {
                if ( -not ($SaveList.Contains($i.ToString()))) {
                    New-LocalUser -Name $missingUsers.ToArray()[$i] -Password (ConvertTo-SecureString "SecurePassword123!" -AsPlainText -Force)
                    Write-Host ("Added: " + $person)  -ForegroundColor Green 
                } else {
                    Write-Host ("Skipped: " + $person) -ForegroundColor Red
                }
                $i += 1
            }
        }
        Write-Host "`n--- SUCCESFULLY ADDED USERS ---" -ForegroundColor Yellow
    } else {
        Write-Host "--- NO USERS TO BE ADDED ---" -ForegroundColor Yellow
    }
}

#============================================
# Clear Unapproved Admins
#============================================
# Comapres list of "approved" admins vs 
#  privileged users on the system.
#============================================
function Clear-UnapprovedAdmins {
    Write-Host "`n--- Checking Admin List ---" -ForegroundColor Blue -BackgroundColor White
    [String[]] $allowedAdmins = Get-Content -Path $adminfile
    $badPrivilegedUsers = New-Object System.Collections.Generic.List[System.Object]
    foreach ($user in (Get-LocalGroupMember -Group "Administrators")) {
        $tempName = $user.Name.replace((HOSTNAME.EXE).ToString().ToUpper() + "\", '')
        if ( -not ($allowedAdmins.Contains($tempName)) -and ((Get-LocalUser -Name $tempName).Enabled)) {
            $badPrivilegedUsers.Add($user.Name)
        }
    }

    if ( -not ($badPrivilegedUsers.count -eq 0)) {
        Write-Host "--- USER TO BE REMOVED FROM ADMIN GROUP ---" -ForegroundColor Yellow
        $i = 0
        foreach ($person in $badPrivilegedUsers) {
            Write-Host ($i.ToString() + ") " + $person)
            $i += 1
        }

        $confirmation = Read-Host "Confirm? [y/n]"
        [string[]] $SaveList= @()
        if ( -not ($confirmation -eq "y")) {
            $SaveList = Read-Host "User to skip: [E.g: 0, 2, 3]"
            $SaveList = $SaveList.Split(',').Split(' ')
        }

        if ( -not ($badPrivilegedUsers.count -eq 0)) {
            $i = 0
            foreach ($person in $badPrivilegedUsers) {
                if ( -not ($SaveList.Contains($i.ToString()))) {
                    Remove-LocalGroupMember -Group "Administrators" -Member $badPrivilegedUsers.ToArray()[$i]
                    Write-Host ("Unprivileged: " + $person) -ForegroundColor Red 
                } else {
                    Write-Host ("Skipped: " + $person) -ForegroundColor Green
                }
                $i += 1
            }
        }
        Write-Host "--- SUCCESFULLY REMOVED AMDINS ---" -ForegroundColor Yellow
    } else {
        Write-Host "--- NO ADMINS TO BE REMOVED ---" -ForegroundColor Yellow
    }    
}


#============================================
# Add Missing Admins
#============================================
# Checks the list of "approved" admins and 
#  adds any who are missing
#============================================
function Add-MissingAdmins {
    Write-Host "`n--- Adding Missing Admins ---" -ForegroundColor Blue -BackgroundColor White
    [String[]] $allowedAdmins = Get-Content -Path $adminfile
    $missingAdmins = New-Object System.Collections.Generic.List[System.Object]
    foreach ($user in $allowedAdmins) {
        if ( -not ($(Get-LocalGroupMember -Group "Administrators").Name.replace((HOSTNAME.EXE).ToString().ToUpper() + "\", '').Contains($user))) {
            $missingAdmins.Add($user)
        }
    }

    if ( -not ($missingAdmins.count -eq 0)) {
        Write-Host "--- ADMINS TO BE ADDED ---" -ForegroundColor Yellow
        $i = 0
        foreach ($person in $missingAdmins) {
            Write-Host ($i.ToString() + ") " + $person)
            $i += 1
        }

        $confirmation = Read-Host "Confirm? [y/n]"
        [string[]] $SaveList= @()
        if ( -not ($confirmation -eq "y")) {
            $SaveList = Read-Host "User to skip: [E.g: 0, 2, 3]"
            $SaveList = $SaveList.Split(',').Split(' ')
        }

        if ( -not ($missingAdmins.count -eq 0)) {
            $i = 0
            foreach ($person in $missingAdmins) {
                if ( -not ($SaveList.Contains($i.ToString()))) {
                    Add-LocalGroupMember -Group "Administrators" -Member ($missingAdmins.ToArray()[$i])
                    Write-Host ("Added: " + $person)  -ForegroundColor Green 
                } else {
                    Write-Host ("Skipped: " + $person) -ForegroundColor Red
                }
                $i += 1
            }
        }
        Write-Host "`n--- SUCCESFULLY ADDED ADMINS ---" -ForegroundColor Yellow
    } else {
        Write-Host "--- NO ADMINS TO BE ADDED ---" -ForegroundColor Yellow
    }
}


#============================================
# Disable Default Accounts
#============================================
# Disables the default Guest and Admin
#  account and renmaes them
#============================================
function Disable-DefaultAccounts {
    Write-Host "`n--- Disabling Default Accounts ---" -ForegroundColor Blue -BackgroundColor White
    Get-LocalUser Guest | Disable-LocalUser
    Get-LocalUser Administrator | Disable-LocalUser
    (Get-WMIObject Win32_UserAccount -Filter "Name='Administrator'").Rename("DisAd")
    (Get-WMIObject Win32_UserAccount -Filter "Name='Guest'").Rename("DisGu")
    Write-Host "`nAdmin Account has been renamed to 'DisAd'" -ForegroundColor Yellow
    Write-Host "Guest Account has been renamed to 'DisGu'" -ForegroundColor Yellow

    reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

}


#============================================
# Enable Password Policy 
#============================================
# Enables basic password policy using 
#  secedit.exe for users
#============================================
function Enable-PasswordPolicy {
    Write-Host "`n--- Enforcing Password Policy ---" -ForegroundColor Blue -BackgroundColor White
    secedit.exe /configure /db C:\Windows\securitynew.sdb /cfg $secfile /areas SECURITYPOLICY

    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f


    Write-Host "`n--- Disabling Anonymous Users ---" -ForegroundColor Yellow
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f

    Write-Output (net.exe accounts)
}

#============================================
# Update Passwords 
#============================================
# Updates the password for all Users
#  secedit.exe for users
#============================================
function Update-Passwords {
    Write-Host "`n--- Updating Passwords for ALL Users ---" -ForegroundColor Blue -BackgroundColor White
    Get-WmiObject win32_useraccount | Foreach-object {
        ([adsi]("WinNT://"+$_.caption).replace("\","/")).SetPassword("SecurePassword123!")
    }
    Write-Host "`nAll passwords are now 'SecurePassword123!'" -ForegroundColor Yellow
}

#============================================
# Enable Audit Policy 
#============================================
# Enable audits for every attempted
#  action by users
#============================================
function Enable-AuditPolicy {
    Write-Host "`n--- Enabling Audit Policy ---" -ForegroundColor Blue -BackgroundColor White

    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f

    auditpol /set /category:"Account Logon" /success:enable
    auditpol /set /category:"Account Logon" /failure:enable
    auditpol /set /category:"Account Management" /success:enable
    auditpol /set /category:"Account Management" /failure:enable
    auditpol /set /category:"DS Access" /success:enable
    auditpol /set /category:"DS Access" /failure:enable
    auditpol /set /category:"Logon/Logoff" /success:enable
    auditpol /set /category:"Logon/Logoff" /failure:enable
    auditpol /set /category:"Object Access" /success:enable
    auditpol /set /category:"Object Access" /failure:enable
    auditpol /set /category:"Policy Change" /success:enable
    auditpol /set /category:"Policy Change" /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable
    auditpol /set /category:"Privilege Use" /failure:enable
    auditpol /set /category:"Detailed Tracking" /success:enable
    auditpol /set /category:"Detailed Tracking" /failure:enable
    auditpol /set /category:"System" /success:enable 
    auditpol /set /category:"System" /failure:enable

    Write-Host "`Succesfully enabled audit for all categories" -ForegroundColor Yellow
}

#============================================
# Enable Firewall
#============================================
# Enables the firewall on the system,
#  set to default levels
#============================================
function Enable-Firewall {
    Write-Host "`n--- Enabling All Firewalls ---" -ForegroundColor Blue -BackgroundColor White
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
    Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log
    
    #netsh advfirewall import "C:\Users\$user\Desktop\Win10Firewall.wfw"

    # NetCat
    $confirmation = Read-Host "Disable Netcat? [y/n]"
    if ($confirmation -eq "y") {
        netsh advfirewall firewall set rule name="netcat" new enable=no
    } else {
        netsh advfirewall firewall set rule name="netcat" new enable=yes
    }

    # Network Discovery
    $confirmation = Read-Host "Disable Network Discovery? [y/n]"
    if ($confirmation -eq "y") {
        netsh advfirewall firewall set rule group="Network Discovery" new enable=No
    } else {
        netsh advfirewall firewall set rule group="Network Discovery" new enable=yes
    }

    # File and Printer Sharing
    $confirmation = Read-Host "Disable File and Printer Sharing? [y/n]"
    if ($confirmation -eq "y") {
        netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No
    } else {
        netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes
    }
    
    netsh advfirewall firewall add rule name="block_RemoteRegistry_in" dir=in service="RemoteRegistry" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RemoteRegistry_out" dir=out service="RemoteRegistry" action=block enable=yes

    # FTP
    $confirmation = Read-Host "Disable FTP? [y/n]"
    if ($confirmation -eq "y") {
        New-NetFirewallRule -DisplayName "ftpTCP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block
        dism /online /disable-feature /featurename:IIS-FTPServer
	    dism /online /disable-feature /featurename:IIS-FTPSvc
	    dism /online /disable-feature /featurename:IIS-FTPExtensibility
	    dism /online /disable-feature /featurename:TFTP    
    } else {
        New-NetFirewallRule -DisplayName "ftpTCP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Allow
        dism /online /enable-feature /featurename:IIS-FTPServer
	    dism /online /enable-feature /featurename:IIS-FTPSvc
	    dism /online /enable-feature /featurename:IIS-FTPExtensibility
	    dism /online /enable-feature /featurename:TFTP
    }
    
    # SSH
    $confirmation = Read-Host "Disable SSH? [y/n]"
    if ($confirmation -eq "y") {
        New-NetFirewallRule -DisplayName "sshTCP" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block
    } else {
        New-NetFirewallRule -DisplayName "sshTCP" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Allow
    }

    # Telnet
    $confirmation = Read-Host "Disable Telnet? [y/n]"
    if ($confirmation -eq "y") {
        New-NetFirewallRule -DisplayName "telnetTCP" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block
        netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
        dism /online /disable-feature /featurename:TelnetClient
	    dism /online /disable-feature /featurename:TelnetServer
    } else {
        New-NetFirewallRule -DisplayName "telnetTCP" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Allow
        netsh advfirewall firewall set rule name="Telnet Server" new enable=yes
        dism /online /enable-feature /featurename:TelnetClient
	    dism /online /enable-feature /featurename:TelnetServer
    }

    # SMTP
    $confirmation = Read-Host "Disable SMTP? [y/n]"
    if ($confirmation -eq "y") {
        New-NetFirewallRule -DisplayName "SMTPTCP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block
    } else {
        New-NetFirewallRule -DisplayName "SMTPTCP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Allow
    }
    
    # SMTP
    $confirmation = Read-Host "Disable POP3? [y/n]"
    if ($confirmation -eq "y") {
        New-NetFirewallRule -DisplayName "POP3TCP" -Direction Inbound -LocalPort 110 -Protocol TCP -Action Block
    } else {
        New-NetFirewallRule -DisplayName "POP3TCP" -Direction Inbound -LocalPort 110 -Protocol TCP -Action Allow
    }

    # SNMP
    $confirmation = Read-Host "Disable SNMP? [y/n]"
    if ($confirmation -eq "y") {
        New-NetFirewallRule -DisplayName "SNMPTCP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block
    } else {
        New-NetFirewallRule -DisplayName "SNMPTCP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Allow
    }

    $confirmation = Read-Host "Disable RDP? [y/n]"
    if ($confirmation -eq "y") {
        New-NetFirewallRule -DisplayName "RDPTCP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
    } else {
        New-NetFirewallRule -DisplayName "RDPTCP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow
    }

    Set-NetConnectionProfile -NetworkCategory Public
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue

    Write-Output (Get-NetFirewallProfile | Format-Table Name, Enabled)
}

#============================================
# Disable Remote Desktop
#============================================
# Disables remote desktop on the system,
#  some Server may need this service on
#============================================
function Disable-RemoteDesktop {
    Write-Host "`n--- Disabling Remote Desktop ---" -ForegroundColor Blue -BackgroundColor White
    # Remote Assistance
    $confirmation = Read-Host "Disable Remote Assistance? [y/n]"
    if ($confirmation -eq "y") {
        netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
        netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
        netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
        netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
        netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
        netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
        reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Conferencing" /v "NoRDS" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d 80 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d 1 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\RemoteAdminSettings" /v "Enabled" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\RemoteDesktop" /v "Enabled" /t REG_DWORD /d 0 /f
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\UPnPFramework" /v "Enabled" /t REG_DWORD /d 0 /f
    }
}

#============================================
# Disable Internet Information Services
#============================================
# Disable IIS services that other scripts
#  have deemed disable-able
#============================================
function Disable-IIS {
    Write-Host "`n--- Disabling IIS Services ---" -ForegroundColor Blue -BackgroundColor White

    dism /online /disable-feature /featurename:IIS-WebServerRole
	dism /online /disable-feature /featurename:IIS-WebServer
	dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
	dism /online /disable-feature /featurename:IIS-HttpErrors
	dism /online /disable-feature /featurename:IIS-HttpRedirect
	dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility
	dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
	dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
	dism /online /disable-feature /featurename:IIS-HttpLogging
	dism /online /disable-feature /featurename:IIS-LoggingLibraries
	dism /online /disable-feature /featurename:IIS-RequestMonitor
	dism /online /disable-feature /featurename:IIS-HttpTracing
	dism /online /disable-feature /featurename:IIS-Security
	dism /online /disable-feature /featurename:IIS-URLAuthorization
	dism /online /disable-feature /featurename:IIS-RequestFiltering
	dism /online /disable-feature /featurename:IIS-IPSecurity
	dism /online /disable-feature /featurename:IIS-Performance
	dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
	dism /online /disable-feature /featurename:IIS-WebServerManagementTools
	dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
	dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
	dism /online /disable-feature /featurename:IIS-Metabase
	dism /online /disable-feature /featurename:IIS-HostableWebCore
	dism /online /disable-feature /featurename:IIS-StaticContent
	dism /online /disable-feature /featurename:IIS-DefaultDocument
	dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
	dism /online /disable-feature /featurename:IIS-WebDAV
	dism /online /disable-feature /featurename:IIS-WebSockets
	dism /online /disable-feature /featurename:IIS-ApplicationInit
	dism /online /disable-feature /featurename:IIS-ASPNET
	dism /online /disable-feature /featurename:IIS-ASPNET45
	dism /online /disable-feature /featurename:IIS-ASP
	dism /online /disable-feature /featurename:IIS-CGI 
	dism /online /disable-feature /featurename:IIS-ISAPIExtensions
	dism /online /disable-feature /featurename:IIS-ISAPIFilter
	dism /online /disable-feature /featurename:IIS-ServerSideIncludes
	dism /online /disable-feature /featurename:IIS-CustomLogging
	dism /online /disable-feature /featurename:IIS-BasicAuthentication
	dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
	dism /online /disable-feature /featurename:IIS-ManagementConsole
	dism /online /disable-feature /featurename:IIS-ManagementService
	dism /online /disable-feature /featurename:IIS-WMICompatibility
	dism /online /disable-feature /featurename:IIS-LegacyScripts
	dism /online /disable-feature /featurename:IIS-LegacySnapIn

    dism /online /disable-feature /featurename:"SMB1Protocol"
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

#============================================
# Enable Windows Defender
#============================================
# Enables Windows Defender and then checks
#  for update
#============================================
function Enable-Defender {    
    Write-Host "`n--- Enabling Windows Defender ---" -ForegroundColor Blue -BackgroundColor White

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force

    start-service WinDefend
    start-service WdNisSvc

    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -PUAProtection enable

    Write-Host "--- Checking for Windows Defender updates ---" -ForegroundColor Red
    Write-Host "This may take a little bit" -ForegroundColor Yellow
    Update-MpSignature

    Write-Output (Get-MpComputerStatus | Select-Object -Property Antivirusenabled,
                            AMServiceEnabled, AntispywareEnabled, BehaviorMonitorEnabled,
                            IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled,
                            RealTimeProtectionEnabled, AntivirusSignatureLastUpdated)
}


#============================================
# Start Virus Scan
#============================================
# Runs a Windows Defender scan of the
#  computer and removes threats
#============================================
function Start-VirusScan {
    Write-Host "`n--- Running Virus QuickScan ---" -ForegroundColor Blue -BackgroundColor White
    $confirmation = Read-Host "Run QuickScan? [y/n]"
    if ($confirmation -eq "y") {
        Start-MpScan -ScanType QuickScan
        Remove-MpThreat
        Write-Host "--- QuickScan Complete (run FullScan for complete search) ---" -ForegroundColor Green    
    }
    
    Write-Host "`n--- Running Virus FullScan ---" -ForegroundColor Blue -BackgroundColor White
    $confirmation = Read-Host "Run FullScan? [y/n]"
    if ($confirmation -eq "y") {
        Start-MpScan -ScanType FullScan
        Remove-MpThreat
        Write-Host "--- FullScan Complete ---" -ForegroundColor Green    
    }    
}

#============================================
# Exit
#============================================
function Exit-Script {
    Write-Host "`n`n --- GOOD LUCK --- GOOD LUCK ---`n" -ForegroundColor Red -BackgroundColor White
    exit
}

#============================================
# Start
#============================================
function Start-Script {
    Clear-Host
    Write-Host "
____    __    ____  __  .__   __.  _______   ______   ____    __    ____   _______.
\   \  /  \  /   / |  | |  \ |  | |       \ /  __  \  \   \  /  \  /   /  /       |
 \   \/    \/   /  |  | |   \|  | |  .--.  |  |  |  |  \   \/    \/   /  |   (----`
  \            /   |  | |  . `  | |  |  |  |  |  |  |   \            /    \   \    
   \    /\    /    |  | |  |\   | |  '--'  |  `--'  |    \    /\    / .----)   |   
    \__/  \__/     |__| |__| \__| |_______/ \______/      \__/  \__/  |_______/    
                                                                                   
    "
    $option = Read-Host '
    1. Run All              
    2. Remove Unapproved Users          3. Add Missing Users
    4. Remove Unapproved Admins         5. Add Missing Admins
    6. Disabled Default Accounts        7. Enabled Password Policy
    8. Update Passwords                 9. Enable Audit Policy
    10. Enable Firewall                 11. Disable Remote Desktop
    12. Disable IIS                     13. Enable Windows Defender
    14. Run Vius Scan
                                        15. Exit'

    if ($option -eq 1) {
        Clear-UnapprovedUsers
        Add-MissingUsers
        Clear-UnapprovedAdmins
        Add-MissingAdmins
        Enable-PasswordPolicy
        Disable-DefaultAccounts
        Update-Passwords
        Enable-AuditPolicy
        Enable-Firewall
        Disable-RemoteDesktop
        Disable-IIS
        Enable-Defender
        Start-VirusScan
    }
    if ($option -eq 2) {
        Clear-UnapprovedUsers
    }
    if ($option -eq 3) {
        Add-MissingUsers
    }
    if ($option -eq 4) {
        Clear-UnapprovedAdmins
    }
    if ($option -eq 5) {
        Add-MissingAdmins
    }
    if ($option -eq 6) {
        Disable-DefaultAccounts
    }
    if ($option -eq 7) {
        Enable-PasswordPolicy
    }
    if ($option -eq 8) {
        Update-Passwords
    }
    if ($option -eq 9) {
        Enable-AuditPolicy
    }
    if ($option -eq 10) {
        Enable-Firewall
    }
    if ($option -eq 11) {
        Disable-RemoteDesktop
    }
    if ($option -eq 12) {
        Disable-IIS
    }
    if ($option -eq 13) {
        Enable-Defender
    }
    if ($option -eq 14) {
        Start-VirusScan
    }
    if ($option -eq 15) {
        Exit-Script
    }
}

Write-Host "`n`n --- DO THE FORENSIC QUESTIONS FIRST --- DO THE FORENSIC QUESTIONS FIRST ---`n" -ForegroundColor Red -BackgroundColor White
Start-Sleep -s 2
while ($true) {
    Start-Script
}
