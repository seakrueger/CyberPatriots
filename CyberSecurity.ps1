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
    Write-Host "`nAdmin Account has been renamed to 'DisAd'" -ForegroundColor Blue -BackgroundColor White
    Write-Host "Guest Account has been renamed to 'DisGu'" -ForegroundColor Blue -BackgroundColor White
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
    netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
    netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
    netsh advfirewall firewall set rule name="netcat" new enable=no
    netsh advfirewall firewall set rule group="Network Discovery" new enable=No
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No
    
    netsh advfirewall firewall add rule name="block_RemoteRegistry_in" dir=in service="RemoteRegistry" action=block enable=yes
    netsh advfirewall firewall add rule name="block_RemoteRegistry_out" dir=out service="RemoteRegistry" action=block enable=yes

    New-NetFirewallRule -DisplayName "sshTCP" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block #ssh
    New-NetFirewallRule -DisplayName "ftpTCP" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Block #ftp
    New-NetFirewallRule -DisplayName "telnetTCP" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block #telnet
    New-NetFirewallRule -DisplayName "SMTPTCP" -Direction Inbound -LocalPort 25 -Protocol TCP -Action Block #SMTP
    New-NetFirewallRule -DisplayName "POP3TCP" -Direction Inbound -LocalPort 110 -Protocol TCP -Action Block #POP3
    New-NetFirewallRule -DisplayName "SNMPTCP" -Direction Inbound -LocalPort 161 -Protocol TCP -Action Block #SNMP
    New-NetFirewallRule -DisplayName "RDPTCP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block #RDP

    Set-NetConnectionProfile -NetworkCategory Public
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue

    Write-Output (Get-NetFirewallProfile | Format-Table Name, Enabled)
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
    Write-Host "`n`n --- SOME OF THIS MAY NEED A RESTART TO TAKE AFFECT --- SAME OF THIS MAY NEED A RESTART TO TAKE AFFECT ---`n" -ForegroundColor Red -BackgroundColor White
    exit
}