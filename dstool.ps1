$version = "v1.20220825.4"
<#
ECCC Deskside Tool
Author: Hugo Kwan
Last Updated: August 25, 2022

.SYNOPSIS 
This script assembles and automates common tools/tasks for deskside support into an all-in-one tool for easy access 
USAGE: Run Powershell as admin > Enter "powershell path\to\dstool.ps1" 


.DESCRIPTION
Includes the following functionality:

    Machine Setup
        - Andy's Initial Machine Setup Script v. 01.20210225.01
            - Set departmentNumber to 007 in AD
            - Set timezone for PYR machines to Pacific Standard Time
            - McAfee Status Monitor Actions: collect and send props, send events, enforce policies, and check new policies
            - Configuration Manager Actions: MachinePolicy, HardwareInventory, UpdateDeployment, UpdateScan, and SoftwareInventory
            - Power settings, sleep to never when plugged in and on battery
            - GPUpdate
            - MSTeams install (removed for now)
                - this should be ez to add back if required
                    - if installer is global and applies to all users: transfer exe, run with silent switch, remove exe
                    - if not: transfer exe, set scheduled task to install when new user logon detected, remove exe
            - Installs DisplayLink Graphics Software
            - Installs KB5005412 & KB5005031 updates if Windows version is below 1909 18363.1734 
        - Rename Computer

    Active Directory User
        - can enter name in format such as 'Hugo Kwan' or 'KwanH' or 'Hugo.Kwan@ec.gc.ca'
        - User Information
            - Get User's Name, Title, Description, SamAccountName, SID, PrimaryGroup, EmailAddress, TargetAddress, StreetAddress, City, State, Manager from AD
        - Group Membership
            - Returns the name and description of all groups the user is a member of in AD
        - Reset Password
        - Unlock Account
    
    Find Computer Name
        - Finds Computer Name that has the primary user as the given name
        - can enter exact name such as 'KwanH'
        - can enter part of a name like 'Kwan' and itll return matches such as KwanH, KwanR, KwanJ, etc
        - can also enter full name or email like AD User Info from above
        - can enter IPv4 address

    Remote Machine
        - System Info (Boot Info, Machine info/specs, OS info, Hard drive info)
        - Installed Programs
        - Open c$
        - Transfer file
        - Map Network drive (currently using Method 2)
            - Method 1, maps through adding necessary registry keys
            - Method 2, maps through a scheduled task as the user
        - Map network printer
            - adds printer through a scheduled task as the user
        - GPUpdate
        - Clear CCM cache
        - Clear MSTeams cache/temp files
        - Run McAfee Actions
        - Run Configuration Manager Actions
        - Connect via Remote Connection Viewer
        - Deploy DisplayLink
        - Deploy McAfee File and Removable Media Protection
        - Lock Workstation

    Password Recovery
        - Get Bitlocker Recovery Password (with computer name or first 8 characters of password ID)
        - Get Local Administrator Password

    Azure AD
        - Azure AD Role Elevation script by Patrick Carrier
            - Authentication Admin (MFA), Reports Reader, Security Reader
        - Link to Azure AD Portal

    Generate Reports
        - Machine Data (SCCM)
            - returns a report of machines and its system info (comp name, last logon user, SCCM version, manufacturer/model/SN)
        - Machines Active Monitor Info
        - Machines with Specified Software Installed (SCCM)
        - Machines without Specified Software Installed (SCCM)
        - Client Status Check (SCCM)
            - returns a report of machines and their SCCM health / client status check / evaluation status
        - SCCM Health Check
            - remotely checks for SCCM's Health from report result in C:\Windows\CCM\CcmEvalReport.xml
        - BitLocker Status Check
            - remotely checks for BitLocker Protection Status
        - SCCM and SAP Comparison Report
            - Queries SCCM and compares it with given SAP report and returns a report of dissimilarities


Untested:
    - Clear MSTeams cache


.NOTES
    - Run script as admin or most functionality will not work


#>





# -----------------------------------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------------------------------
# Modify the following variables if they are changed

# Paths
$scriptNetworkPath = ""
$changeLog = ""
$accessedLogNetworkPath = ""
$InitialMachineSetupScriptPath = ""
$ECCCApprovedSoftwareListPath = ""
$SolutionGuidePath =  ""
$McAfeeFRPMSIPath = ""
$displayLinkMsiPath = ""


$AzureADPortalLink = "https://aad.portal.azure.com/"

# Default path to save reports in
$pathToReports = "C:\temp\DSTool_Reports"
$allCompsFile = "$pathToReports\computers.txt"

# SCCM / Configuration Manager site stuff (can get this info at the top of the window on SCCM)
$SiteCode=""
$ServerName=""

# AD Server for global catalog querying
$server = ""
$userSearchBase = ""

# Computer name region for querying SCCM Reports
$regionLetters = ""

# Tells PowerShell how many script blocks it is allowed to run at once/ in parallel for reports
$ThrottleLimit = 250

# Whitelist for SCCM reports
$whitelist = $true
$whitelistUsers = @()


# dont change these thx
$accentColour = "Cyan"
$WinRMPort = 5985
$RDPPort = 3389
$executedScriptPath = $MyInvocation.MyCommand.Path
$showReadHostAnyKey = $true
$connect = $null
$remoteCompName = $null
$ADUserObjectGlobal = $null

# -----------------------------------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------------------------------

function Version-Checker {
    ########## Checks if the script is on the newest version ##########
    try {
        $newestVersion = (Get-Content -Path $scriptNetworkPath -ErrorAction SilentlyContinue)[0].split("`"")[1]
     
        if ($newestVersion -gt $version) {
            Write-Host "New version ($newestVersion) detected!" -ForegroundColor "Green"
            Write-Host
            Write-Host "[U] " -ForegroundColor $accentColour -NoNewLine; Write-Host Update DSTool
        }
    } catch {
        Write-Host "Unable to retrieve latest version" -ForegroundColor "Red"
    }

}


function Update-LatestVersion {
    ########## Updates script to newest version by overwriting local script or rerunning it ##########

    # get changelog content and split by newline
    $content = Get-Content $changeLog | Out-String
    $nl = [System.Environment]::NewLine
    $items = ($content -split "$nl$nl")

    $networkDriveVersion = (Get-Content -Path $scriptNetworkPath -ErrorAction SilentlyContinue)[0].split("`"")[1]
    if ($networkDriveVersion -eq $version) {
        Write-Host "DSTool $version is up to date" -ForegroundColor "Green"
        Write-Host
        foreach ($item in $items) {
            if ($item -match "$version*") {
                Write-Host $item
            }
        }
        Write-Host
        Read-HostESCKey
        return
    } elseif ($networkDriveVersion -gt $version) {

        Write-Host "Current Version: $version"
        Write-Host "Update  Version: $networkDriveVersion"
        Write-Host
        Write-Host "Changelog:"
        Write-Host "-------------------------------------------------------------------------"
        # display last 3 changes
        try {
            $items[0]
            Write-Host
            $items[1]
            Write-Host
            $items[2]
        } catch {}
        Write-Host "-------------------------------------------------------------------------"
        Write-Host
        Write-Host "Update DSTool?"
        $result = Read-YNKeyPrompt
        if (!$result) {
            Write-Host -NoNewLine "Action cancelled." -ForegroundColor "red"
            return
        }

        $local = $executedScriptPath -ne $scriptNetworkPath
        $updatedScript = $scriptNetworkPath
        if ($local) {
            Write-Host "Updating local file $executedScriptPath"
            Copy-Item $scriptNetworkPath $executedScriptPath
            Start-Sleep 3
            $updatedScript = $executedScriptPath
        }
    } elseif ($networkDriveVersion -lt $version) {
        Write-Host "DSTool version ($version) is ahead of network drive version ($networkDriveVersion)" -ForegroundColor "Yellow"
        Write-Host "You shouldn't be seeing this!!!"
        Write-Host
        Read-HostESCKey
        return
    }

    try {
        exit
    } finally {
        & powershell $updatedScript
    }
    
}


function Check-AdminPriv {
    ########## Checks if powershell was ran as admin ##########

    return [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")
}


function Read-HostAnyKey {
    Write-Host ""
    Read-Host "Press Enter to return to menu"
}

function Read-HostESCKey {
    Write-Host
    # Write-Host "Press ESC to return" -NoNewLine
    Write-Host "[ESC] " -ForegroundColor $accentColour -NoNewLine; Write-Host "Return" -NoNewLine


    do {

        $KeyPress = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown');

        $VKC = $KeyPress.VirtualKeyCode

        # 27 = ESC, 13 = "Enter"
        $validVKCInputs = @("27", "13")

    } until ($VKC -in $validVKCInputs)

}

# function Read-HostCustom {
#     # Custom Read-Host that adds functionality where pressing ESC exits the input

#     Write-Host ">> " -NoNewLine

#     $input = ""
#     do {
#         $prevInput = $input
#         $key = [Console]::ReadKey("NoEcho, IncludeKeyDown")
#         $value = $key.KeyChar
#         $detect = $key.Key
        
#         if ($detect -eq "Enter") {
#             if ($input -eq "") {
#                 return ""
#             }
#             Write-Host
#             return $input.trim()
#         } elseif ($detect -eq "Backspace") {
#             $input = $input -replace ".$"
#         } elseif ($detect -eq "Escape") {
#             return ""
#         } else {
#             $input += $value
#         }
#         $input | ForEach-Object { Write-Host -NoNewline ("`r{0,-$([console]::BufferWidth)}" -f ">> $_") }
#     }
#     while (69)
    
# }

function Read-HostCustom {
    # Custom Read-Host that adds functionality where pressing ESC exits the input
    param ($prompt=">> ")

    Set-PSReadLineKeyHandler -Key Escape -ScriptBlock {
        [Microsoft.PowerShell.PSConsoleReadLine]::DeleteLine()
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
    }
    Set-PSReadLineOption -Colors @{ Command = "White" }

    try {
        Write-Host -NoNewline $prompt
        $input = PSConsoleHostReadLine

    } finally {
        # Remove the custom Escape key handler.
        Remove-PSReadlineKeyHandler -Key Escape
    }

    return $input
}

function Read-YNKeyPrompt {
    # reads whether user presses Y or N and returns true or false accordingly

    function print-options {
        param ($selected, $replace="")

        $yesColour = "White"
        $noColour = "White"

        if ($selected -eq "Yes") {
            $yesColour = "Green"
            $noColour = "DarkGray"
        } elseif ($selected -eq "No") {
            $yesColour = "DarkGray"
            $noColour = "Red"
        }
    
        Write-Host "$replace[Y] " -ForegroundColor $accentColour -NoNewLine; Write-Host "Yes" -ForegroundColor $yesColour -NoNewLine
        Write-Host "  " -NoNewLine
        Write-Host "[N] " -ForegroundColor $accentColour -NoNewLine; Write-Host "No" -ForegroundColor $noColour -NoNewLine
    }

    print-options

    # 89 = Y, 78 = N, 27 = ESC, 13 = Enter
    $validVKCInputs = @(89, 78, 27, 13)

    do {
        $KeyPress = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown');
        $VKC = $KeyPress.VirtualKeyCode

        $result = Switch ($VKC) {
            "89" {$true}
            "13" {$true}
            "78" {$false}
            "27" {$false}
        }

    } until ($VKC -in $validVKCInputs)

    $selected = switch ($result) {
        $true  { "Yes" }
        $false { "No" }
    }

    print-options -selected $selected -replace "`r"
    Write-Host

    return $result

}


function Get-AuthCredential {
    ########## Prompt and authenticate admin credentials ##########

    do {
        Write-Host
        Write-Host "Please enter your admin credentials..."
        $credential = Get-Credential "$env:USERDOMAIN\$env:USERNAME"

        $username = $credential.username
        $password = $credential.GetNetworkCredential().password

        # Get current domain using logged-on user's credentials
        $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
        $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$username,$password)


        if ($isAuthenticated = $domain.name -eq $null)
        {
            write-host "Authentication failed - please verify your username and password." -ForegroundColor "Red"
        }

    } while ($isAuthenticated)

    write-host "Successfully authenticated $username" -ForeGroundColor "Green"
    Write-Host ""

    return $credential
}


function Display-Title {
    param($title)

    Write-Host "================" -NoNewLine -ForegroundColor $accentColour; Write-Host " $title " -NoNewLine; Write-Host "================" -ForegroundColor $accentColour;
    Write-Host
}


function inWhiteList {
    if ($whitelist) {
        if ($env:username -in $whitelistUsers) {
            return $true
        }
        return $false
    }
    return $true
}


function Clear-GlobalVariables {
    $global:ADUserObjectGlobal = $null
    $global:remoteCompName = $null
}



function Query-SCCMWmiObject {
    ########## Runs query on SCCM and returns WMI object ##########

    param($query)

    return Get-WmiObject -ComputerName "$($ServerName)" -Namespace "root\sms\site_$SiteCode" -Query $query
}


function Check-CompExistence {
    ########## test if machine exists in SCCM ##########
    param($compName)

    $query = "
        SELECT SMS_R_SYSTEM.Name
        FROM SMS_R_System
        WHERE SMS_R_SYSTEM.Name=""$($compName)""
    "

    $object = Query-SCCMWmiObject -query $query

    if (!$object) {
        # write-host "$compName does not seem to exist; please check for any typos" -ForegroundColor "red"
        return $false
    }
    return $true
}


function Check-OnlineStatusSCCM {
    ########## Checks online status by querying SCCM and returning CNIsOnline value ##########

    param($compName)

    $query = "
        SELECT 
            SMS_CombinedDeviceResources.CNIsOnline
        FROM SMS_CombinedDeviceResources
        WHERE SMS_CombinedDeviceResources.Name=""$($compName)""
    "

    $onlineStatus = (Query-SCCMWmiObject -query $query | Select CNIsOnline).CNIsOnline
    # true = online, false = offline, or null = does not exist in sccm
    
    return $onlineStatus
}


function Check-TestConnection {
    ########## Get computer name and test connection ##########

    param($compName)

    $isOnline = Test-Connection $compName -Count 1 -Quiet -ErrorAction SilentlyContinue

    return $isOnline

}


function Test-TCPPort { 
    ########## Test if port is enabled on comp. Similar to Test-NetConnection but this has a timeout ##########

    param($address, $port, $timeout=2000)
    $socket=New-Object System.Net.Sockets.TcpClient
    try {
        $result=$socket.BeginConnect($address, $port, $NULL, $NULL)
        if (!$result.AsyncWaitHandle.WaitOne($timeout, $False)) {
            # throw [System.Exception]::new('Connection Timeout')
            return $false
        }
        $socket.EndConnect($result) | Out-Null
        $socket.Connected
    }
    finally {
        $socket.Close()
    }
}


function IsValidIPv4Address ($ip) {
    return ($ip -match "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$" -and [bool]($ip -as [ipaddress]))
}


function Connect-RemoteComp {
    ########## Creates a new pssession to connect to client's computer ##########
    param ($compName)


    Write-Host "Attempting to connect to $compName..."
    $pso = New-PSSessionOption -OperationTimeout 0
    $session = New-PSSession -ComputerName $compName -SessionOption $pso

    Write-Host "Established a connection with $compName" -ForeGroundColor "Green"

    return $session

}


function Disconnect-RemoteComp {
    ########## Disconnects from remote session ##########
    param ($session)

    Write-Host "Disconnecting from session..."
    Remove-PSSession $session
}


function Open-SolutionGuide {

    explorer $SolutionGuidePath

}


function ExitMonke {
    write-host "
          __
     o  c(..)o   (
      \__(-)    __)
          /\   (
         /(_)___)
         o /|
          | \
          m  m
    "
    exit
}


function Get-ADUserByFullName {
    # Returns user Object from AD by searching with full name
    param ($givenName, $surname)

    return Get-ADUser -Filter {(GivenName -eq $givenName) -and (Surname -eq $surname)} -SearchBase $userSearchBase -Server "$($server):3268" -Properties * | Where { $_.DistinguishedName -notmatch 'OU=EC Admins' }
}


function Test-UserProfile {
    ########## Checks if user has a profile on the machine ##########

    param ($compName)
    
    # Check C:\Users for the target user's profile folder
    $PathTest = Invoke-Command -Computer $compName -ScriptBlock {Test-Path "C:\Users\$Using:Username"}
    
    if (!$PathTest) {
        Write-Host "User does not have a profile on this computer. Cannot complete this action" -ForegroundColor "Red"
        Write-Host
    }
    return $PathTest
}


function Get-MappedDrives {
    ########## Displays all currently mapped network drives ##########
    param($compName, $sid)

    $now = (Get-Date).datetime
    Write-Host "Network drives found as of $($now):"
    $results = Invoke-Command -Computer $compName -scriptblock {
        set-location registry::\HKEY_USERS
        New-PSDrive HKU Registry HKEY_USERS | Out-Null
        Set-Location HKU:

        $drives = (gci -Path Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($args[0])\Network -recurse)

        # Read the RemotePath key from each mapped drive
        $driveresults = foreach ($d in $drives){$q = ("Microsoft.PowerShell.Core\Registry::HKEY_USERS\$($args[0])\Network\" + $d.pschildname);get-itemproperty -Path $q;}

        $driveresults 
    } -ArgumentList $sid

    if ($results -eq $null) {
        Write-Host "User currently has no mapped drives."
        Write-Host
    } else {
        $results | Format-Table PSChildName,RemotePath 
    }
}


function Test-DriveLetter {
    ########## Checks if the given drive letter is already assigned ##########

    param ($compName)
    
    # Set the registry path where network drive mappings are stored
    $RegPathHKU = "HKU:\$SID\Network\$NetworkDriveLetter"

    # Run script on target computer
    $RegPathTest = Invoke-Command -Computer $compName -ScriptBlock {

    # Map HKEY_USERS so that PowerShell can access it
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null

    # Test the registry path to see if a mapping for the provided network drive letter exists
    Test-Path "$Using:RegPathHKU"

    # Unmap HKEY_Users from PowerShell
    Remove-PSDrive HKU
    }

    # If the drive letter doesn't exist, continue
    if ($RegPathTest -eq $False)
    {
        return $false
    }

    # Otherwise, pause
    else
    {
        Write-Host ""
        Write-Host "User already has this drive letter mapped. Please choose another letter"
        Write-Host ""

        return $true
    }

}

function Create-NetworkShare {
    ########## Creates a drive mapping by adding path into registry ##########

    param ($compName)

    # Run script on target computer
    Invoke-Command -Computer $compName -ScriptBlock {

        # Create the registry key for the network share
        Echo n | Reg Add $Using:RegistryPath

        # Set the network path value
        Echo n | Reg Add $Using:RegistryPath /v RemotePath /t REG_SZ /d $Using:NetworkPath | Out-Null

        # Set the remaining values
        Echo n | Reg Add $Using:RegistryPath /v ConnectFlags /t REG_DWORD /d 0 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ConnectionType /t REG_DWORD /d 1 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v DeferFlags /t REG_DWORD /d 4 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ProviderFlags /t REG_DWORD /d 1 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ProviderName /t REG_SZ /d "Microsoft Windows Network" | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ProviderType /t REG_DWORD /d 131072 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v UserName /t REG_DWORD /d 0 | Out-Null
    }

}


function Get-UserNetworkPrinters {
    ########## Returns all network printer found for all users. function was retrieved from reddit, dont rmb where ##########

    param ($compName)

    #Open the old remote registry
    $reglm = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.Registryhive]::LocalMachine, $compName)
    $regu = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.Registryhive]::Users, $compName)
    #Grab the USER SIDS, try and ignore service accounts and stuff
    $sids = ($regu.GetSubKeyNames() | ?{($_ -notlike '*.DEFAULT*')-and($_ -notlike "*classes*")-and($_.length -ge 9)})
    $sid = (Get-ADUser -Filter "SamAccountName -eq '$Username'" -SearchBase $userSearchBase -Server "$($server):3268" | Select SID).SID.Value
    # foreach($sid in $sids) {
        $printersReg = $regu.OpenSubKey("$sid\printers\connections")
        Write-Host
        if(($printersReg -ne $null) -and($printersReg.length -gt 0))
        {
            $printers = $printersReg.getsubkeynames()
            #Try and get the username from the SID - Need to be the same domain
            #Should change to a try-catch for different domains
            # $user = $($(New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value)
    
    
            foreach($printer in $printers)
            {
                #Need to split the regkey name to get proper values
                #Split 2 = Print server
                #Split 3 = printer name
                #Never seen a value in the 0 or 1 spots
                $split = $printer.split(",")
                $printerDetails = $regu.openSubKey("$SID\Printers\Connections\$printer")
                $printerGUID = $printerDetails.getValue("GuidPrinter")
                $spoolerPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Providers\Client Side Rendering Print Provider\Servers\$($split[2])\Printers\$printerGUID\DsSpooler"
                $printSpooler = $reglm.OpenSubKey("$spoolerPath")

                #Make an object to store in the array
                $pdetails = [pscustomobject]@{
                    # computer = $compName
                    # user = $user
                    printerUNC = $($printSpooler.getValue("uNCName"))
                    printServer = $split[2]
                    printer = $split[3]
                    # pringerGUID = $printerGUID
                    printerDesc = $($printSpooler.getValue("description"))
                    printerDriver = $($printSpooler.getValue("DriverName"))
                    printerLocation = $($printSpooler.getValue("Location"))
                    printerPortName = $($printSpooler.getValue("PortName"))
                    # printerShareName = $($printSpooler.getValue("printShareName"))
                    # printerSpooling = $($printSpooler.getValue("printSpooling"))
                    # printerPriority = $($printSpooler.getValue("priority"))

                }
                #Add the object to the array
                
                $pdetails 
            }
    
        } else {
            Write-host "No printers found" -ForegroundColor "Red"
        }

    # }
            
}


function checkLock {
    Param(
        [parameter(Mandatory=$true)]
        $filename
    )
    $file = gi (Resolve-Path $filename) -Force
    if ($file -is [IO.FileInfo]) {
        trap {
            return $true
            continue
        }
        $stream = New-Object system.IO.StreamReader $file
        if ($stream) {$stream.Close()}
    }
    return $false
}



function RunSCCMClientAction {
    ########## runs Configuration Manager Actions against the remote machine ##########
    # retrieved from https://www.powershellbros.com/sccm-client-actions-remote-machines-powershell-script/

    [CmdletBinding()]
            
    # Parameters used in this function
    param
    ( 
        [Parameter(Position=0, Mandatory = $True, HelpMessage="Provide server names", ValueFromPipeline = $true)] 
        [string[]]$Computername,

        [ValidateSet('MachinePolicy', 
                    'DiscoveryData', 
                    'ComplianceEvaluation', 
                    'AppDeployment',  
                    'HardwareInventory', 
                    'UpdateDeployment', 
                    'UpdateScan', 
                    'SoftwareInventory')] 
        [string[]]$ClientAction

    ) 
    $ActionResults = @()
    Try { 

        $ActionResults = Invoke-Command -ComputerName $Computername {
            
            param($ClientAction)

                Foreach ($Item in $ClientAction) {
                    $Object = @{} | select "Action name",Status
                    Try{
                        $ScheduleIDMappings = @{ 
                            'MachinePolicy'        = '{00000000-0000-0000-0000-000000000021}'; 
                            'DiscoveryData'        = '{00000000-0000-0000-0000-000000000003}'; 
                            'ComplianceEvaluation' = '{00000000-0000-0000-0000-000000000071}'; 
                            'AppDeployment'        = '{00000000-0000-0000-0000-000000000121}'; 
                            'HardwareInventory'    = '{00000000-0000-0000-0000-000000000001}'; 
                            'UpdateDeployment'     = '{00000000-0000-0000-0000-000000000108}'; 
                            'UpdateScan'           = '{00000000-0000-0000-0000-000000000113}'; 
                            'SoftwareInventory'    = '{00000000-0000-0000-0000-000000000002}'; 
                        }
                        $ScheduleID = $ScheduleIDMappings[$item]
                        Write-Verbose "Processing $Item - $ScheduleID"
                        [void]([wmiclass] "root\ccm:SMS_Client").TriggerSchedule($ScheduleID);
                        $Status = "Success"
                        Write-Verbose "Operation status - $status"
                    }
                    Catch{
                        $Status = "Failed"
                        Write-Verbose "Operation status - $status"
                    }
                    $Object."Action name" = $item
                    $Object.Status = $Status
                    $Object
                }

        } -ArgumentList $ClientAction -ErrorAction Stop | Select-Object @{n='ServerName';e={$_.pscomputername}},"Action name",Status
    }  
    Catch {
        Write-Error $_.Exception.Message 
    }   
    Return $ActionResults           
}


function RunMcAfeeActions {
    ########## Runs the McAfee actions to Collect & Send Props, Send events, Check new policies, Enforce policies ##########
    # have to run it as a scheduled task as either user or current user or it will return errors

    # param ($compName)
    param( $checkLockDef )
    . ([ScriptBlock]::Create($checkLockDef))

    $logFilePath = "C:\temp\cmdagentlog.txt"
    Remove-Item $logFilePath -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $command = "& 'C:\Program Files\McAfee\Agent\cmdagent.exe' /c >> $($logFilePath); 
                & 'C:\Program Files\McAfee\Agent\cmdagent.exe' /e >> $($logFilePath); 
                & 'C:\Program Files\McAfee\Agent\cmdagent.exe' /p >> $($logFilePath); 
                & 'C:\Program Files\McAfee\Agent\cmdagent.exe' /f >> $($logFilePath)"
    $action = (New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -NoProfile -command $command")
    $trigger = New-ScheduledTaskTrigger -Once -At (get-date).AddSeconds(2)
    $trigger.EndBoundary = (get-date).AddSeconds(3).ToString('s')
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DeleteExpiredTaskAfter 00:00:02
    Register-ScheduledTask -TaskName "Run-McAfeeActions" -Action $action -Trigger $trigger -Principal $principal -Settings $Settings | Out-Null

    Start-Sleep -Seconds 2

    # Waits until the log file is created before proceeding
    while (!(Test-Path $logFilePath)) {
        Start-Sleep -seconds 1
    }

    $timeoutCount
    # Waits until all 4 commands have executed before proceeding
    while ((Get-Content $logFilePath | Measure-Object -Line).lines -lt 4) {
        Start-Sleep -seconds 1
        $timeoutCount ++

        # timeout after 10 seconds so it doesnt get stuck
        if ($timeoutCount -eq 10) {
            Write-Host "Timed out while waiting for all actions to complete." -ForegroundColor "Red"
            break
        }
    }

    
    # Waits until the log file is unlocked
    $timeoutCount = 0
    while ($True) {
        Start-Sleep -seconds 1

        if($timeoutCount -eq 10) {
            Write-Host "Failed to run McAfee Actions" -ForegroundColor "Red"
            Write-Host
            break
        }
        if ((checkLock $logFilePath)) {
            $timeoutCount ++
            continue
        }
        else {
            # Read contents of log file and display to console
            gc $logFilePath | more

            Start-Sleep -seconds 2

            Remove-Item $logFilePath -ErrorAction SilentlyContinue
            break
        }

    }
}


function RunConfigManagerActions {
    ########## Runs Configuration Manager Actions ##########
 
    param ($compName)

    # theoretically it works by having all actions passed to ClientAction but it doesnt display the result for some reason
    RunSCCMClientAction -Computername $compName -ClientAction MachinePolicy
    RunSCCMClientAction -Computername $compName -ClientAction AppDeployment
    RunSCCMClientAction -Computername $compName -ClientAction HardwareInventory
    RunSCCMClientAction -Computername $compName -ClientAction UpdateDeployment
    RunSCCMClientAction -Computername $compName -ClientAction UpdateScan

}


function RestartWinlogon {
    ########## Restarts Winlogon.exe to refresh lockscreen page ##########

    [String]$QUserPath = "C:\Windows\System32\quser.exe"

    # Check if there are any current user sessions
    $result = & $QUserPath 2>&1 | Out-String
    if ($result -like '*No User exists for*') {
        Terminate winlogon.exe if no users
        Get-Process -Name "winlogon" | Stop-Process -Force
    } else {
        Write-Host "User session found."
    }
}




function Convert-CSVToExcel {
    ########## Convert CSV to Excel and formats ##########

    param($csvFile)

    Write-Host
    Write-Host "Converting csv to xlsx"

    $fileName = $csvFile.split("\")[-1].split(".")[0]
    $dateNow = get-date -f "yyyy-MM-dd@HHmm"
    New-Item -ItemType Directory -Force -Path $pathToReports | Out-Null
    $xlFile = "$pathToReports\$fileName$dateNow.xlsx"

    Remove-Item $xlFile -ErrorAction SilentlyContinue

    # Sorts and removes all duplicate row entries
    $inputCsv = Import-Csv $csvFile | Sort-Object * -Unique
    $inputCsv | Export-Csv $csvFile -NoTypeInformation
    
    $csvContent = Get-Content $csvFile 
    $data = ConvertFrom-csv -InputObject $csvContent

    Export-Excel -InputObject $data -Path $xlFile -TableName Status -WorksheetName "Results" -AutoSize
    Remove-Item $csvFile -ErrorAction SilentlyContinue

    $xl = Open-ExcelPackage -Path $xlFile

    Write-Host "Report saved to $($xlFile)" -ForegroundColor "Green"

}



function Get-AllCompsFromAD {
    # Grabs all machines with specific region letters in its name and outputs it into a text file

    # Remove-Item $allCompsFile -ErrorAction SilentlyContinue 
    # Write-Host "Getting machines from AD..."
    # $compRegion = "W$($regionLetters)*"
    # Get-ADComputer -Filter {(Name -like $compRegion) -and (Name -notlike "*LAB*") -and (Name -notlike "*TEST*") -and (Name -notlike "*VM*")} | Select -ExpandProperty Name | Out-File -filepath $allCompsFile


    # Excludes computers that have not been logged in for 1 year or more
    $DaysInactive = 365  #define days 
    $time = (Get-Date).Adddays(-($DaysInactive)) 
    Remove-Item $allCompsFile -ErrorAction SilentlyContinue 
    Write-Host "Getting machines from AD..."
    $compRegion = "W$($regionLetters)*"
    $compNames = Get-ADComputer -Filter {(Name -like $compRegion) -and (Name -notlike "*LAB*") -and (Name -notlike "*TEST*") -and (Name -notlike "*VM*") -and (LastLogon -gt $time)} 
    $compNames | Select -ExpandProperty Name | Out-File -filepath $allCompsFile

}



function Check-ImportExcelInstall {
    # Checks to see if ImportExcel Module is installed; if not, install it
    if (-Not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-Host "ImportExcel Module not found. Downloading & installing before running script..." -ForegroundColor "Green"
        Install-Module ImportExcel -Force -Verbose -Scope CurrentUser
    }
    Import-Module ImportExcel
}


function Send-ToastMessage {
    param ($compName, $app, $title, $message, $img)
    $toast = @"
function Show-Toast {
    param (
        `$title,
        `$message,
        `$img
    )
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
`$app = '$app'
`$template = @'
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text id="1">$title</text>
            <text id="2">$message</text>
            <image placement="appLogoOverride" src="$img"/>
        </binding>
    </visual>
</toast>
'@
`$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
`$xml.LoadXml(`$template)
`$toast = New-Object Windows.UI.Notifications.ToastNotification `$xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(`$app).Show(`$toast)
}
Show-Toast `$title `$message `$img
"@

    Invoke-Command -ComputerName $compName -ScriptBlock { Invoke-Expression $using:toast }
}


function Convert-OSBuildToVersion {
    # maps windows operating system build to version
    param ($build)

    $version = switch -regex ($build) {
        "18362"  { "1903"  }
        "18363"  { "1909" }
        "19041"  { "2004" }
        "19042"  { "20H2" }
        "19043"  { "21H1" }
        "19044"  { "21H2" }
        Default  {  "N/A"  }
    }
    
    return $version
}


Function Set-OGVWindow {
    # Resizes Window 
    # Retrieved from https://www.reddit.com/r/PowerShell/comments/ak14o2/auto_size_outgridview/

    [OutputType('System.Automation.WindowInfo')]
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$True)]
        $ProcessName,

        [parameter(Mandatory=$true)]
        [string]$WindowTitle,

        [int]$X,

        [int]$Y,

        [int]$Width,

        [int]$Height
    )

    Begin {
        Try{
            [void][Window]
        } Catch {

        Add-Type @"
              using System;
              using System.Runtime.InteropServices;
              public class Window {
                [DllImport("user32.dll")]
                [return: MarshalAs(UnmanagedType.Bool)]
                public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
                [DllImport("user32.dll")]
                public extern static bool MoveWindow(IntPtr handle, int x, int y, int width, int height, bool redraw);
              }

              public struct RECT
              {
                public int Left;        // x position of upper-left corner
                public int Top;         // y position of upper-left corner
                public int Right;       // x position of lower-right corner
                public int Bottom;      // y position of lower-right corner
              }
"@
        }
    }

    Process {
        $Rectangle = New-Object RECT
        $Handle = (Get-Process -Name $ProcessName | ? MainWindowTitle -eq $WindowTitle).MainWindowHandle

        if($Handle){
            $Return = [Window]::GetWindowRect($Handle,[ref]$Rectangle)

            If ($Return) {
                $Return = [Window]::MoveWindow($Handle, $x, $y, $Width, $Height,$True)
            }
        }
    }
}


function Test-PasswordForDomain {
    # Tests password complexity. Retrieved and modified from https://stackoverflow.com/questions/66156786/
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Password,
        
        [Parameter(Mandatory = $false)]
        [string]$samAccountName = $null,
        
        [Parameter(Mandatory = $false)]
        [string]$AccountDisplayName = $null
    )
    # [Microsoft.ActiveDirectory.Management.ADEntity]
    $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue

    If ($Password.Length -lt $PasswordPolicy.MinPasswordLength) {
        Write-Host "Password is too short. Minimum length: $($PasswordPolicy.MinPasswordLength)" -ForegroundColor "Red"
        return $false
    }
    if (($samAccountName) -and ($Password -match "$samAccountName")) {
        Write-Host "Password includes the user's SamAccountName ($samAccountName)" -ForegroundColor "Red"
        return $false
    }
    if ($AccountDisplayName) {
        # if ANY PART of the display name that is split by the characters below, the password should fail the complexity rules.
        $tokens = $AccountDisplayName.Split(",.-,_ #`t")
        foreach ($token in $tokens) {
            if (($token) -and ($Password -match "$token")) {
                Write-Host "Password includes the user's DisplayName ($AccountDisplayName)" -ForegroundColor "Red"
                return $false
            }
        }
    }
    if ($PasswordPolicy.ComplexityEnabled -eq $true) {
        # check for presence of 
        # - Uppercase: A through Z, with diacritic marks, Greek and Cyrillic characters
        if ($Password -cnotmatch "[A-Z\p{Lu}\s]") {
            Write-Host "Password is missing uppercase characters" -ForegroundColor "Red"
            return $false
        }
        # - Lowercase: a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters
        if ($Password -cnotmatch "[a-z\p{Ll}\s]") {
            Write-Host "Password is missing lowercase characters" -ForegroundColor "Red"
            return $false
        }
        # - Base 10 digits (0 through 9)
        if ($Password -notmatch "[\d]") {
            Write-Host "Password is missing digits (0-9)" -ForegroundColor "Red"
            return $false
        }
        # - Nonalphanumeric characters: ~!@#$%^&*_-+=`|\(){}[]:;"'<>,.?/
        if ($Password -notmatch "[^\w]") {
            Write-Host "Password is missing non-alphanumeric characters" -ForegroundColor "Red"
            return $false
        }
    }

    return $true
}




function Join-Object
{
    <#
    .SYNOPSIS
        Join data from two sets of objects based on a common value
    .DESCRIPTION
        Join data from two sets of objects based on a common value
        For more details, see the accompanying blog post:
            http://ramblingcookiemonster.github.io/Join-Object/
        For even more details,  see the original code and discussions that this borrows from:
            Dave Wyatt's Join-Object - http://powershell.org/wp/forums/topic/merging-very-large-collections
            Lucio Silveira's Join-Object - http://blogs.msdn.com/b/powershell/archive/2012/07/13/join-object.aspx
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipeLine = $true)]
        [object[]] $Left,

        # List to join with $Left
        [Parameter(Mandatory=$true)]
        [object[]] $Right,

        [Parameter(Mandatory = $true)]
        [string] $LeftJoinProperty,

        [Parameter(Mandatory = $true)]
        [string] $RightJoinProperty,

        [object[]]$LeftProperties = '*',

        # Properties from $Right we want in the output.
        # Like LeftProperties, each can be a plain name, wildcard or hashtable. See the LeftProperties comments.
        [object[]]$RightProperties = '*',

        [validateset( 'AllInLeft', 'OnlyIfInBoth', 'AllInBoth', 'AllInRight')]
        [Parameter(Mandatory=$false)]
        [string]$Type = 'AllInLeft',

        [string]$Prefix,
        [string]$Suffix
    )
    Begin
    {
        function AddItemProperties($item, $properties, $hash)
        {
            if ($null -eq $item)
            {
                return
            }

            foreach($property in $properties)
            {
                $propertyHash = $property -as [hashtable]
                if($null -ne $propertyHash)
                {
                    $hashName = $propertyHash["name"] -as [string]         
                    $expression = $propertyHash["expression"] -as [scriptblock]

                    $expressionValue = $expression.Invoke($item)[0]
            
                    $hash[$hashName] = $expressionValue
                }
                else
                {
                    foreach($itemProperty in $item.psobject.Properties)
                    {
                        if ($itemProperty.Name -like $property)
                        {
                            $hash[$itemProperty.Name] = $itemProperty.Value
                        }
                    }
                }
            }
        }

        function TranslateProperties
        {
            [cmdletbinding()]
            param(
                [object[]]$Properties,
                [psobject]$RealObject,
                [string]$Side)

            foreach($Prop in $Properties)
            {
                $propertyHash = $Prop -as [hashtable]
                if($null -ne $propertyHash)
                {
                    $hashName = $propertyHash["name"] -as [string]         
                    $expression = $propertyHash["expression"] -as [scriptblock]

                    $ScriptString = $expression.tostring()
                    if($ScriptString -notmatch 'param\(')
                    {
                        Write-Verbose "Property '$HashName'`: Adding param(`$_) to scriptblock '$ScriptString'"
                        $Expression = [ScriptBlock]::Create("param(`$_)`n $ScriptString")
                    }
                
                    $Output = @{Name =$HashName; Expression = $Expression }
                    Write-Verbose "Found $Side property hash with name $($Output.Name), expression:`n$($Output.Expression | out-string)"
                    $Output
                }
                else
                {
                    foreach($ThisProp in $RealObject.psobject.Properties)
                    {
                        if ($ThisProp.Name -like $Prop)
                        {
                            Write-Verbose "Found $Side property '$($ThisProp.Name)'"
                            $ThisProp.Name
                        }
                    }
                }
            }
        }

        function WriteJoinObjectOutput($leftItem, $rightItem, $leftProperties, $rightProperties)
        {
            $properties = @{}

            AddItemProperties $leftItem $leftProperties $properties
            AddItemProperties $rightItem $rightProperties $properties

            New-Object psobject -Property $properties
        }

        #Translate variations on calculated properties.  Doing this once shouldn't affect perf too much.
        foreach($Prop in @($LeftProperties + $RightProperties))
        {
            if($Prop -as [hashtable])
            {
                foreach($variation in ('n','label','l'))
                {
                    if(-not $Prop.ContainsKey('Name') )
                    {
                        if($Prop.ContainsKey($variation) )
                        {
                            $Prop.Add('Name',$Prop[$Variation])
                        }
                    }
                }
                if(-not $Prop.ContainsKey('Name') -or $Prop['Name'] -like $null )
                {
                    Throw "Property is missing a name`n. This should be in calculated property format, with a Name and an Expression:`n@{Name='Something';Expression={`$_.Something}}`nAffected property:`n$($Prop | out-string)"
                }


                if(-not $Prop.ContainsKey('Expression') )
                {
                    if($Prop.ContainsKey('E') )
                    {
                        $Prop.Add('Expression',$Prop['E'])
                    }
                }
            
                if(-not $Prop.ContainsKey('Expression') -or $Prop['Expression'] -like $null )
                {
                    Throw "Property is missing an expression`n. This should be in calculated property format, with a Name and an Expression:`n@{Name='Something';Expression={`$_.Something}}`nAffected property:`n$($Prop | out-string)"
                }
            }        
        }

        $leftHash = @{}
        $rightHash = @{}

        # Hashtable keys can't be null; we'll use any old object reference as a placeholder if needed.
        $nullKey = New-Object psobject
        
        $bound = $PSBoundParameters.keys -contains "InputObject"
        if(-not $bound)
        {
            [System.Collections.ArrayList]$LeftData = @()
        }
    }
    Process
    {
        #We pull all the data for comparison later, no streaming
        if($bound)
        {
            $LeftData = $Left
        }
        Else
        {
            foreach($Object in $Left)
            {
                [void]$LeftData.add($Object)
            }
        }
    }
    End
    {
        foreach ($item in $Right)
        {
            $key = $item.$RightJoinProperty

            if ($null -eq $key)
            {
                $key = $nullKey
            }

            $bucket = $rightHash[$key]

            if ($null -eq $bucket)
            {
                $bucket = New-Object System.Collections.ArrayList
                $rightHash.Add($key, $bucket)
            }

            $null = $bucket.Add($item)
        }

        foreach ($item in $LeftData)
        {
            $key = $item.$LeftJoinProperty

            if ($null -eq $key)
            {
                $key = $nullKey
            }

            $bucket = $leftHash[$key]

            if ($null -eq $bucket)
            {
                $bucket = New-Object System.Collections.ArrayList
                $leftHash.Add($key, $bucket)
            }

            $null = $bucket.Add($item)
        }

        $LeftProperties = TranslateProperties -Properties $LeftProperties -Side 'Left' -RealObject $LeftData[0]
        $RightProperties = TranslateProperties -Properties $RightProperties -Side 'Right' -RealObject $Right[0]

        #I prefer ordered output. Left properties first.
        [string[]]$AllProps = $LeftProperties

        #Handle prefixes, suffixes, and building AllProps with Name only
        $RightProperties = foreach($RightProp in $RightProperties)
        {
            if(-not ($RightProp -as [Hashtable]))
            {
                Write-Verbose "Transforming property $RightProp to $Prefix$RightProp$Suffix"
                @{
                    Name="$Prefix$RightProp$Suffix"
                    Expression=[scriptblock]::create("param(`$_) `$_.'$RightProp'")
                }
                $AllProps += "$Prefix$RightProp$Suffix"
            }
            else
            {
                Write-Verbose "Skipping transformation of calculated property with name $($RightProp.Name), expression:`n$($RightProp.Expression | out-string)"
                $AllProps += [string]$RightProp["Name"]
                $RightProp
            }
        }

        $AllProps = $AllProps | Select -Unique

        Write-Verbose "Combined set of properties: $($AllProps -join ', ')"

        foreach ( $entry in $leftHash.GetEnumerator() )
        {
            $key = $entry.Key
            $leftBucket = $entry.Value

            $rightBucket = $rightHash[$key]

            if ($null -eq $rightBucket)
            {
                if ($Type -eq 'AllInLeft' -or $Type -eq 'AllInBoth')
                {
                    foreach ($leftItem in $leftBucket)
                    {
                        WriteJoinObjectOutput $leftItem $null $LeftProperties $RightProperties | Select $AllProps
                    }
                }
            }
            else
            {
                foreach ($leftItem in $leftBucket)
                {
                    foreach ($rightItem in $rightBucket)
                    {
                        WriteJoinObjectOutput $leftItem $rightItem $LeftProperties $RightProperties | Select $AllProps
                    }
                }
            }
        }

        if ($Type -eq 'AllInRight' -or $Type -eq 'AllInBoth')
        {
            foreach ($entry in $rightHash.GetEnumerator())
            {
                $key = $entry.Key
                $rightBucket = $entry.Value

                $leftBucket = $leftHash[$key]

                if ($null -eq $leftBucket)
                {
                    foreach ($rightItem in $rightBucket)
                    {
                        WriteJoinObjectOutput $null $rightItem $LeftProperties $RightProperties | Select $AllProps
                    }
                }
            }
        }
    }
}


function render-html { 
    $htmlPath = "C:\temp\temp.html"
    Remove-Item $htmlPath -ErrorAction SilentlyContinue -Force
    $input > $htmlPath
    while (!(Test-Path $htmlPath)) {
        sleep 1
    }
    start $htmlPath
}



function Get-MSIVersion {
    # Get the product version from the MSI file
    param ($fullPath)

    $windowsInstaller = New-Object -com WindowsInstaller.Installer
    $database = $windowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null, $windowsInstaller, @($FullPath, 0))
    $q = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
    $View = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $Null, $database, ($q))
    $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null)
    $record = $View.GetType().InvokeMember("Fetch", "InvokeMethod", $Null, $View, $Null)
    $MSIVersion = $record.GetType().InvokeMember("StringData", "GetProperty", $Null, $record, 1)
    $View.GetType().InvokeMember("Close", "InvokeMethod", $Null, $View, $Null)

    return $MSIVersion
}



$ManufacturerHash = @{ 
    "AAC" =	"AcerView";
    "ACR" = "Acer";
    "ACI" = "Asus";
    "AOC" = "AOC";
    "AIC" = "AG Neovo";
    "APP" = "Apple Computer";
    "AST" = "AST Research";
    "AUO" = "Asus";
    "AUS" = "Asus";
    "BNQ" = "BenQ";
    "CMO" = "Acer";
    "CPL" = "Compal";
    "CPQ" = "Compaq";
    "CPT" = "Chunghwa Pciture Tubes, Ltd.";
    "CTX" = "CTX";
    "DEC" = "DEC";
    "DEL" = "Dell";
    "DPC" = "Delta";
    "DWE" = "Daewoo";
    "EIZ" = "EIZO";
    "ELS" = "ELSA";
    "ENC" = "EIZO";
    "EPI" = "Envision";
    "FCM" = "Funai";
    "FUJ" = "Fujitsu";
    "FUS" = "Fujitsu-Siemens";
    "GSM" = "LG Electronics";
    "GWY" = "Gateway 2000";
    "HEI" = "Hyundai";
    "HIT" = "Hyundai";
    "HSL" = "Hansol";
    "HTC" = "Hitachi/Nissei";
    "HWP" = "HP";
    "HPN" = "HP";
    "IBM" = "IBM";
    "ICL" = "Fujitsu ICL";
    "IVM" = "Iiyama";
    "KDS" = "Korea Data Systems";
    "LEN" = "Lenovo";
    "LGD" = "Asus";
    "LPL" = "Fujitsu";
    "MAX" = "Belinea"; 
    "MEI" = "Panasonic";
    "MEL" = "Mitsubishi Electronics";
    "MS_" = "Panasonic";
    "MSI" = "MSI";
    "NAN" = "Nanao";
    "NEC" = "NEC";
    "NOK" = "Nokia Data";
    "NVD" = "Fujitsu";
    "ONN" = "ONN";
    "OPT" = "Optoma";
    "PHL" = "Philips";
    "REL" = "Relisys";
    "SAN" = "Samsung";
    "SAM" = "Samsung";
    "SBI" = "Smarttech";
    "SGI" = "SGI";
    "SNY" = "Sony";
    "SRC" = "Shamrock";
    "SUN" = "Sun Microsystems";
    "SEC" = "Hewlett-Packard";
    "TAT" = "Tatung";
    "TOS" = "Toshiba";
    "TSB" = "Toshiba";
    "VSC" = "ViewSonic";
    "ZCM" = "Zenith";
    "UNK" = "Unknown";
    "_YV" = "Fujitsu";
}




# -----------------------------------------------------------------------------------------------------
# Main Functions
# -----------------------------------------------------------------------------------------------------

function Transfer-File {
    ########## Select and transfer a file to given computer name ##########
    param ($compName)


    Connect-RemoteComp -compName $compName

    $session = Get-PSSession

    # Opens File Browser pop up for file selection

    Write-Host
    Write-Host "Select the file(s) to transfer"
    Add-Type -AssemblyName System.Windows.Forms
    # $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog 
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
    $currentUser = (Get-CIMInstance -class Win32_ComputerSystem).username.split("\")[1]
    $FileBrowser.InitialDirectory = "C:\Users\$currentUser"
    $FileBrowser.Multiselect = $true
    $null = $FileBrowser.ShowDialog()
    $filePath = $FileBrowser.FileNames
    Write-Host "Selected file(s): $filePath"
    Write-Host

    if ( $filePath -eq "" ) {
        Write-Host "No file selected." -ForegroundColor "Red"
        return
    }

    # Transfers selected file to client

    Write-Host "Transferring file(s)..."
    try {
        foreach ($file in $filePath) {
            Copy-Item -Path $filePath -Destination "C:\temp" -ToSession $session
        }
        Write-Host "File(s) successfully copied to C:\temp on $compName" -ForeGroundColor "Green"

    } catch {
        Write-Host "Some or all file(s) did not transfer" -ForeGroundColor "Red"
    }

    # Invoke-Command -ScriptBlock { Get-ChildItem -Path "C:\temp\*" } -Session $session
    Write-Host ""

    Disconnect-RemoteComp -session $session

}



function Get-BitLockerRecoveryPassword {
    ########## Retrieves most recent BitLocker Recovery Password by computer name or Recovery ID ##########

    $validChars = "^[a-zA-Z0-9\-]{1,15}$" # Valid computer name is any letter or number, max 15 chars
    # $compName = Read-Host -Prompt "Enter the computer name or first 8 characters of Recovery ID"
    $compName = Read-HostCustom -prompt "Enter the computer name or first 8 characters of Recovery ID: "
    
    if ($compName -eq "") {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    } elseif ($compName -notmatch $validChars){
        Write-Host "Invalid input entered" -ForegroundColor "red"
        Write-Host
        Get-BitLockerRecoveryPassword   
        return
    }

    $compName = $compName.trim()

    # cant identify by 8 characters because comp name could also happen to be 8 characters
    # so use try/catch/finally blocks to check if compname fails and try getting with recovery id

    $result = $false
    try {
        # Finds bitlocker pass with computer name
        $computer = Get-ADComputer $compName.trim()
        $bitLockerInfo = Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' -SearchBase $computer.DistinguishedName -Properties whenCreated, msFVE-RecoveryPassword | `
            Sort whenCreated -Descending | Select whenCreated, @{Name="RecoveryPassword";Expression={$_."msFVE-RecoveryPassword"}}
        $result = $true

        if ($bitLockerInfo) {
            $bitLockerInfo | Out-Host
        } else {
            Write-Host "No BitLocker Recovery Password found for this machine." -ForegroundColor "Red"
        }

    } catch {
        # will throw the error 'Get-ADComputer : Cannot find an object with identity'
        # if computer name wasnt found or they entered the recovery pin instead
    } finally {
        if (!$result) {
            # Finds bitlocker pass with recovery ID
            $Splat = @{Properties = 'msfve-recoverypassword', 'created'}
            $RecoveryGUID = $compName
            if ($RecoveryGUID.Length -gt 8) {$RecoveryGUID = $RecoveryGUID.Substring(0,8)}
            $Splat.Filter = "objectclass -eq 'msFVE-RecoveryInformation' -and Name -Like '*{$RecoveryGUID-*}'"
            $Recoveries = Get-ADObject @Splat
            
            foreach ($Recovery in $Recoveries)
            {
                $Object = [PSCustomObject]@{
                        # ComputerName     = ($Recovery.DistinguishedName -split ',')[1] -replace 'CN=',''
                        whenCreated        = $Recovery.Created
                        RecoveryPassword = $Recovery.'msfve-RecoveryPassword'
                }

                # if (!$all) {break}
            }
            
            if ($object) {
                $Object | Out-Host
                $result = $true
            }
        }
    }

    if (!$result) {
        Write-Host "No BitLocker Recovery Password found. Please check your input for typos" -ForegroundColor "Red"
        Write-Host
    }
}



function Get-LocalAdmPass {
    ########## Retrieves Local Admin Password ##########

    $validChars = "^[a-zA-Z0-9\-]{1,15}$" # Valid computer name is any letter or number, max 15 chars
    # $compName = Read-Host -Prompt "Enter the computer name"
    $compName = Read-HostCustom -prompt "Enter the computer name: "
    if ($compName -eq "") {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    } elseif ($compName -notmatch $validChars){
        Write-Host "Invalid input entered" -ForegroundColor "red"
        Write-Host
        Get-LocalAdmPass    
        return
    }

    $compName = $compName.trim()

    # Get AD object of computer 
    $computer = Get-ADComputer $compName -Properties ms-Mcs-AdmPwdExpirationTime, ms-Mcs-AdmPwd
    $computer | Select @{Name="DateTime Expiration   ";Expression={$([datetime]::FromFileTime([convert]::ToInt64($_."ms-Mcs-AdmPwdExpirationTime",10)))}}, @{Name="Password"; Expression={$_."ms-Mcs-AdmPwd"}} | Out-Default

    # Set password expiry date to 1 day from today 
    Write-Host "Set password expiry to tomorrow?"
    $result = Read-YNKeyPrompt
    if ($result) { 

        $newTime = (Get-date).AddDays(1).toFileTimeUtc()
        # gives error (Set-ADObject : An attempt was made to modify an object to include an attribute that is not legal for its class) but still seems to apply changes?? 
        $computer | Set-ADComputer -Replace @{"ms-Mcs-AdmPwdExpirationTime"=$newTime} 

        Get-ADComputer $compName -Properties ms-Mcs-AdmPwdExpirationTime | Select @{Name="New expiration time";Expression={$([datetime]::FromFileTime([convert]::ToInt64($_."ms-Mcs-AdmPwdExpirationTime",10)))}} | Out-Default
    }

}



function Change-RemoteCompName {
    ########## Remotely changes computer name of machine ##########

    # $compName = Read-Host -Prompt "Enter current computer name "
    $compName = Read-HostCustom -Prompt "Enter current computer name: "
    if ($compName -eq "") {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }
    $compName = $compName.trim()

    ipconfig /flushdns | Out-Null
    if (!(Test-TCPPort -address $compName -port $WinRMPort)){
        Write-Host "Machine appears to be offline"
        return
    }

    $hostname = Invoke-Command -ComputerName $compName -ScriptBlock { hostname }
    if ($hostname -ne $compName) {
        Write-Host "Accessed wrong computer ($compName)"
        return
    }

    # $newName = Read-Host -Prompt "Enter the new computer name"
    $newName = Read-HostCustom -Prompt "Enter the new computer name: "
    if ($newName -eq ""){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    try {
        $credential = Get-AuthCredential
    } catch {
        Write-Host "Failed to validate credentials - Action cancelled." -ForegroundColor "red"
        return
    }

    Write-Host "Automatically restart after changing name?"
    $result = Read-YNKeyPrompt
    

    # using invoke-command instead of -computername parameter for rename-computer because it returns RPC server is unavailable error
    Invoke-Command -ComputerName $compName -ScriptBlock {

        Write-Host
        if ($using:result) {
            # Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 1 | Out-Null
        } else {
            Write-Warning "Warning: If the user signs out/locks their machine before it restarts, they may not be able to sign back in until the machine has restarted. This can result in lost work, so please restart ASAP."
        }

        $params = @{
            NewName              = $using:newName
            DomainCredential     = $using:credential
            PassThru             = $true
            Force                = $true
            Restart              = $using:result
        }

        Rename-Computer @params
        Write-Host
    }

}


function Get-SystemInfo {
    ########## Displays system info of remote machine ##########
    # im aware of Get-ComputerInfo but when using that command, the progress bar sometimes gets stuck
    param($compName)

    $compSystem = Get-CimInstance CIM_ComputerSystem -ComputerName $compName 
    # $compOS = Get-WmiObject win32_operatingsystem -ComputerName $compName
    $compOS = Get-CimInstance CIM_operatingsystem -ComputerName $compName
    $timeZone = Get-CimInstance win32_TimeZone -ComputerName $compName
    $CurrentTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId((Get-Date), "$($TimeZone.StandardName)")
    # $OSVersion = invoke-command -ScriptBlock {(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseID).ReleaseID} -ComputerName $compName
    $OSVersion = Convert-OSBuildToVersion -build $compOS.Version
    $compBios = Get-CimInstance Win32_Bios -ComputerName $compName 
    $compPhysicalDisk = Get-PhysicalDisk -cimSession $compName
    $compLogicalDisk = Get-CimInstance Win32_LogicalDisk -ComputerName $compName -Filter DriveType=3
    $compProcessor = Get-CimInstance CIM_Processor -ComputerName $compName


    Write-Host "---------------------------------------------" -NoNewLine -ForegroundColor $accentColour; Write-Host " Boot Info" -ForegroundColor "Yellow"
    Write-Host
    $sysuptime= (Get-Date) - $compOS.LastBootUpTime
    Write-Host ("Last boot    : " + $compOS.LastBootUpTime)
    Write-Host ("Uptime       : " + $sysuptime.Days + " Days " + $sysuptime.Hours + " Hours " + $sysuptime.Minutes + " Minutes" )
    Write-Host
    Write-Host "Timezone     :" $timeZone.Caption
    Write-Host "Cur. Time    :" $CurrentTime
    Write-Host

    Write-Host "---------------------------------------------" -NoNewLine -ForegroundColor $accentColour; Write-Host " Machine Info" -ForegroundColor "Yellow"
    Write-Host
    $remoteCompInfo = ($compSystem | Select Manufacturer, Model | Format-List | Out-String).trim()
    $remoteCompInfo += "`n"
    $remoteCompInfo += ($compBios | Select SerialNumber, @{N='BiosVersion';E={$_.SMBIOSBIOSVersion}} | Format-List | Out-String).trim()
    $remoteCompInfo
    Write-Host
    Write-Host "CPU          :" $compProcessor.Name
    "RAM          : {0:N2}" -f [int]($compSystem.TotalPhysicalMemory/1GB) + " GB"
    # Didnt write Write-host here cuz it errors for some reason
    Write-Host

    Write-Host "---------------------------------------------" -NoNewLine -ForegroundColor $accentColour; Write-Host " OS Info" -ForegroundColor "Yellow"
    Write-Host
    Write-Host "Edition      :" $compOS.caption
    Write-Host "System Type  :" $compOS.OSArchitecture
    Write-Host "OS Build     :" $compOS.Version
    Write-Host "OS Version   :" $OSVersion
    Write-Host

    Write-Host "---------------------------------------------" -NoNewLine -ForegroundColor $accentColour; Write-Host " Storage Info" -ForegroundColor "Yellow"
    $compPhysicalDisk | Select Model, MediaType, @{'Name'='Size'; 'Expression'={[string]::Format('{0:N0} GB',[math]::truncate($_.size / 1GB))}} | Format-Table
    ($compLogicalDisk | Select DeviceID, @{'Name'='Freespace'; 'Expression'={[string]::Format('{0:N0} GB',[math]::truncate($_.freespace / 1GB))}}, @{'Name'='Size'; 'Expression'={[string]::Format('{0:N0} GB',[math]::truncate($_.size / 1GB))}} | Format-Table | out-string).split("`n") -match '\S'
    Write-Host


    Write-Host "---------------------------------------------" -NoNewLine -ForegroundColor $accentColour; Write-Host " Connected Monitors" -ForegroundColor "Yellow"


    $monitors = Get-CimInstance -ComputerName $compName -ClassName WmiMonitorID -Namespace root\wmi -ErrorAction SilentlyContinue
    if ($monitors) {
        $monitors | % {

            if ($null -ne $_) {
                $manufCode = -join [char[]] ($_.Manufacturername -ne 0)
                
                [PSCustomObject]@{
                    # Active          = $_.Active 
                    Manufacturer    = $ManufacturerHash.$manufCode
                    Model           = if ($_.UserFriendlyName) {-join [char[]] ($_.UserFriendlyName -ne 0)} else {$null}
                    SerialNumber    = if ($_.SerialNumberID) {-join [char[]] ($_.SerialNumberID -ne 0)} else {$null}
                    # 'Year Of Manufacture' = $_.YearOfManufacture
                    # 'Week Of Manufacture' = $_.WeekOfManufacture
                }
            }
            
        } | Format-Table
    }
    else {
        Write-Host
        Write-Host "No monitors connected"
    }
    Write-Host



}


function Get-SystemInfoOffline {
    ########## Displays system info of remote machine by querying SCCM ##########
    param($compName)

    # query for system info
    $query = "
        SELECT 

            SMS_R_System.LastLogonUserDomain,
            SMS_R_System.LastLogonUserName,

            SMS_G_System_PC_BIOS.Manufacturer,
            SMS_G_System_PC_BIOS.SerialNumber,
            SMS_G_System_PC_BIOS.SMBIOSBIOSVersion,

            SMS_G_System_OPERATING_SYSTEM.Caption,
            SMS_G_System_OPERATING_SYSTEM.Version,

            SMS_G_System_COMPUTER_SYSTEM.SystemType,
            SMS_G_System_COMPUTER_SYSTEM.Manufacturer,
            SMS_G_System_COMPUTER_SYSTEM.Model,

            SMS_G_System_PROCESSOR.Name,

            SMS_G_System_Logical_Disk.Name,
            SMS_G_System_Logical_Disk.Size,
            SMS_G_System_Logical_Disk.FreeSpace

        FROM SMS_R_System
        INNER JOIN SMS_G_System_PC_BIOS on SMS_G_System_PC_BIOS.ResourceID = SMS_R_System.ResourceId
        INNER JOIN SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceId
        INNER JOIN SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId
        INNER JOIN SMS_G_System_PROCESSOR on SMS_G_System_PROCESSOR.ResourceID = SMS_R_System.ResourceId
        INNER JOIN SMS_G_System_Logical_Disk on SMS_G_System_Logical_Disk.ResourceID = SMS_R_System.ResourceId

        WHERE SMS_R_SYSTEM.Name=""$($compName)"" AND SMS_G_System_Logical_Disk.Name=""C:""
    "
    # query for all physical disks
    $query2 = "
        SELECT 
            SMS_G_System_Physical_Disk.Model,
            SMS_G_System_Physical_Disk.Size,
            SMS_G_System_Physical_Disk.MediaType
        FROM SMS_R_System
        INNER JOIN SMS_G_System_Physical_Disk on SMS_G_System_Physical_Disk.ResourceID = SMS_R_System.ResourceId
        WHERE SMS_R_SYSTEM.Name=""$($compName)""
    "
    # query for all ram modules
    $query3 = "
        SELECT SMS_G_System_PHYSICAL_MEMORY.Capacity
        FROM SMS_R_System
        INNER JOIN SMS_G_System_PHYSICAL_MEMORY on SMS_G_System_PHYSICAL_MEMORY.ResourceID = SMS_R_System.ResourceId
        WHERE SMS_R_SYSTEM.Name=""$($compName)""
    "

    $object = Query-SCCMWmiObject -query $query
    $object2 = Query-SCCMWmiObject -query $query2
    $object3 = Query-SCCMWmiObject -query $query3

    # format physical disk info
    $physicalDisks = foreach ($o in $object2) {
        $MediaType = switch ($o.MediaType) { 
            0 {"Unspecified"} 
            3 {"HDD"} 
            4 {"SSD"} 
            5 {"SCM"}
            Default {"N/A"}
        }

        [pscustomobject]@{
            Model = $o.Model
            Size = [string]::Format('{0:N0} GB',[math]::truncate($o.Size / 1GB))
            MediaType = $MediaType
        }
    } 

    # format ram info
    foreach ($o in $object3) {
        $ramSize += $o.Capacity
    }

    $OSVersion = Convert-OSBuildToVersion -build $object.SMS_G_System_OPERATING_SYSTEM.Version


    Write-Host "---------------------------------------------" -NoNewLine -ForegroundColor $accentColour; Write-Host " Boot Info" -ForegroundColor "Yellow"
    Write-Host
    Write-Host "Last User    : $($object.SMS_R_System.LastLogonUserDomain)\$($object.SMS_R_System.LastLogonUserName)"
    Write-Host

    Write-Host "---------------------------------------------" -NoNewLine -ForegroundColor $accentColour; Write-Host " Machine Info" -ForegroundColor "Yellow"
    Write-Host
    Write-Host "Manufacturer :" $object.SMS_G_System_PC_BIOS.Manufacturer
    Write-Host "Model        :" $object.SMS_G_System_COMPUTER_SYSTEM.Model
    Write-Host "SerialNumber :" $object.SMS_G_System_PC_BIOS.SerialNumber
    Write-Host "BiosVersion  :" $object.SMS_G_System_PC_BIOS.SMBIOSBIOSVersion
    Write-Host
    Write-Host "CPU          :" $object.SMS_G_System_PROCESSOR.Name
    "RAM          : {0:N2}" -f [int]($ramSize/1KB) + " GB"
    # Didnt write Write-host here cuz it errors for some reason
    Write-Host

    Write-Host "---------------------------------------------" -NoNewLine -ForegroundColor $accentColour; Write-Host " OS Info" -ForegroundColor "Yellow"
    Write-Host
    Write-Host "Edition      : " $object.SMS_G_System_OPERATING_SYSTEM.Caption
    Write-Host "System Type  : " $object.SMS_G_System_COMPUTER_SYSTEM.SystemType
    Write-Host "OS Build     : " $object.SMS_G_System_OPERATING_SYSTEM.Version
    Write-Host "OS Version   : " $OSVersion
    Write-Host

    Write-Host "---------------------------------------------" -NoNewLine -ForegroundColor $accentColour; Write-Host " Storage Info" -ForegroundColor "Yellow"
    $physicalDisks | Format-Table -Auto
    ($object | Select @{'Name'='DeviceID'; 'Expression'={$_.SMS_G_System_Logical_Disk.Name}}, @{'Name'='Freespace'; 'Expression'={[string]::Format('{0:N0} GB',[math]::truncate($_.SMS_G_System_Logical_Disk.Freespace / 1KB))}}, @{'Name'='Size'; 'Expression'={[string]::Format('{0:N0} GB',[math]::truncate($_.SMS_G_System_Logical_Disk.size / 1KB))}} | Format-Table | out-string).split("`n") -match '\S'
    Write-Host

}



function Map-NetworkDrive {
    ########## Maps a Network drive by adding it to the registry on the remote computer ##########

    param ($compName)

    # Ensure user has a profile on target computer
    $PathTest = Test-UserProfile -compName $compName
    if (!$PathTest) {
        return
    }

    # Get the user's SID
    $SID = (Get-ADUser -Filter "SamAccountName -eq '$Username'" -SearchBase $userSearchBase -Server "$($server):3268" | Select SID).SID.Value

    # Display currently mapped drives
    Get-MappedDrives -compName $compName -sid $sid

    # Verify user doesn't have drive letter already mapped
    do {
        # Save the desired Network drive letter as a variable
        do
        {
            # Initialize input verification variable
            $Input = "NotOK"

            # Choose Drive letter
            # $NetworkDriveLetter = Read-Host "Enter a drive letter"
            $NetworkDriveLetter = Read-HostCustom -prompt "Enter a drive letter: "

            if ($NetworkDriveLetter -eq "") {
                Write-Host "Action cancelled." -ForegroundColor "red"
                return
            }

            # Limit Drive Letter to one character
            If ($NetworkDriveLetter -NotMatch "^[A,B,D-Z]$")
            {
                Write-Host ""
                Write-Host "Enter a valid drive letter " -ForegroundColor Red
                Write-Host ""

                $Input = "NotOK"
            }

            Else
            {
                $Input = "OK"
            }


        } while ($Input -ne "OK")

        $isTaken = Test-DriveLetter -compName $compName

    } while ($isTaken)

    # Convert any input to Upper Case
    $NetworkDriveLetter = $NetworkDriveLetter.ToUpper()

    # Set the Registry Path
    $RegistryPath = "HKEY_USERS\$SID\Network\$NetworkDriveLetter"



    # Save the desired network path as a variable
    Write-Host ""
    # $NetworkPath = Read-Host "Enter the FULL network path (eg. \\server\shares\folder)"
    $NetworkPath = Read-HostCustom -prompt "Enter the FULL network path (eg. \\server\shares\folder): "

    # Map the network drive
    Create-NetworkShare -compName $compName


    # Restarts explorer.exe so that drive will show
    Write-Warning "Enter A for the following prompt. This will restart Explorer.exe on the machine so that the drive will be visible to the client. Inform them that the desktop will momentarily flash black. Otherwise enter N and you can tell them to sign out/in again."
    Invoke-Command -Computer $compName -ScriptBlock {
        Stop-Process -ProcessName Explorer
    }


    # Displays all mapped drives after mapping to confirm it is there
    Get-MappedDrives -compName $compName -sid $sid

}



function Map-NetworkDrive2 {
    ########## Maps a Network drive via scheduling a task ##########

    param ($compName)

    # Display currently mapped drives
    $SID = (Get-ADUser -Filter "SamAccountName -eq '$Username'" -SearchBase $userSearchBase -Server "$($server):3268" | Select SID).SID.Value

    Get-MappedDrives -compName $compName -sid $SID

    # $drivePath = Read-Host "Enter the FULL network path (eg. \\server\shares\folder)"
    $drivePath = Read-HostCustom -prompt "Enter the FULL network path (eg. \\server\shares\folder): "
    Write-Host
    if ($drivePath -eq "") {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    $logFilePath = "C:\temp\mapdrive.log"

    $checkLockDef = "function checkLock { ${function:checkLock} }"

    Invoke-Command -Computer $compName -ArgumentList $checkLockDef -ScriptBlock {
        param( $checkLockDef )

        . ([ScriptBlock]::Create($checkLockDef))

        $currentUser = (Get-CIMInstance -Class win32_computersystem).UserName

        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -NoProfile -command (net use * '$($using:drivePath)' /persistent:Yes *> $($using:logFilePath))"
        $trigger = New-ScheduledTaskTrigger -Once -At (get-date).AddSeconds(2)
        $trigger.EndBoundary = (get-date).AddSeconds(3).ToString('s')
        $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType ServiceAccount 
        $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DeleteExpiredTaskAfter 00:00:02
        Register-ScheduledTask -TaskName "Map-NetworkDrive" -Action $action -Trigger $trigger -Principal $principal -Settings $Settings -Force | Out-Null

        try {
            # Stop-Process -Name powershell -Force -ErrorAction SilentlyContinue | Out-Null # stops all powershell processes that may be locking up the log file from being deleted
        } catch {} #dont show cannot find powershell process error 
        Remove-Item $using:logFilePath -ErrorAction SilentlyContinue -Force
        $timeoutCount
        # Waits until the log file is created before proceeding
        while (!(Test-Path $using:logFilePath)) {
            Start-Sleep 1
            $timeoutCount ++

            if ($timeoutCount -eq 10) {
                Write-Host "Timed out while waiting for scheduled task to run. Please try again" -ForegroundColor "Red"
                return
            }
        }

        $timeoutCount = 0
        # Waits until the log file is unlocked
        while ($True) {
            Start-Sleep -seconds 1

            if($timeoutCount -eq 10) {
                Write-Host "Failed to map network drive. $Username may not have sufficient privileges" -ForegroundColor "Red"
                Write-Host
                break
            }

            if ((checkLock $using:logFilePath)) {
                $timeoutCount ++
                continue
            }
            else {
                # Read contents of log file and display to console
                gc $using:logFilePath | more

                Start-Sleep -seconds 1

                Remove-Item $using:logFilePath
                break
            }
        }
    }

    Start-Sleep 2
    # Displays all mapped drives after mapping to confirm it is there
    Get-MappedDrives -compName $compName -sid $sid
}



function Map-NetworkPrinter {
    ########## Maps a network printer via scheduling a task ##########

    param ($compName)

    $now = (Get-Date).datetime
    Write-Host "Network printers found as of $($now):"
    Get-UserNetworkPrinters -compName $compName | Out-Host
    Write-Host

    # $printerPath = Read-Host "Enter the FULL network path (eg. \\server\printer)"
    $printerPath = Read-HostCustom -prompt "Enter the FULL network path (eg. \\server\printer): "
    Write-Host
    if ($printerPath -eq "") {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Write-Host "Adding network printer..."
    
    Invoke-Command -ComputerName $compName -ScriptBlock {

        $logFilePath = "C:\temp\addprinter.txt"
        $currentUser = (Get-CIMInstance -Class win32_computersystem).UserName

        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -NoProfile -command (Add-Printer -ConnectionName $($using:printerPath) *> $($logFilePath))"
        $trigger = New-ScheduledTaskTrigger -Once -At (get-date).AddSeconds(2)
        $trigger.EndBoundary = (get-date).AddSeconds(3).ToString('s')
        $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType ServiceAccount
        $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DeleteExpiredTaskAfter 00:00:02
        Register-ScheduledTask -TaskName "Map-NetworkPrinter" -Action $action -Trigger $trigger -Principal $principal -Settings $Settings -Force | Out-Null

        Start-Sleep 25

        if ((Get-Content $logFilePath | Measure-Object -Line).lines -ge 1) {
            Write-Host "The specified server does not exist, or the server or printer name is invalid." -ForegroundColor "Red"
            $found_error = $true
        }

        Start-Sleep -seconds 1

        Remove-Item $logFilePath -ErrorAction SilentlyContinue
        
    }

    if (!$found_error) {
        Write-Host
        Write-Host "Network printers found on $($compName):"
        Get-UserNetworkPrinters -compName $compName
        Write-Verbose "If $printerPath is not present, it may still be installing. Check again in a couple minutes" -Verbose
    }

}



function Get-InstalledPrograms {
    ########## Queries SCCM and returns installed programs for given machine ##########
    # Fastest but doesnt show user installs

    param ($compName)
    Write-Host "Retrieving installed programs..."
    
    # # Method 1
    # # This method checks the packages and attempts to verify and repair the install before returning the results so dont use
    # GWMI -Computer $compName Win32_Product | Sort-Object Name | Format-Table Name, Vendor, Version

    $installedPrograms = Get-CimInstance -Namespace root\cimv2\sms -ClassName SMS_InstalledSoftware -ComputerName $compName | Select ProductName, Publisher, ProductVersion | Sort-Object ProductName 
    Write-Host "Opening a new window to display output" -ForegroundColor "green"
    $installedPrograms | Out-GridView -Title "$compName Installed Programs"

    Set-OGVWindow -ProcessName powershell -WindowTitle "$compName Installed Programs" -Width 1000 -Height 1000

}


function Get-InstalledPrograms2 {
    ########## Queries the registry remotely and returns installed programs for given machine ##########
    # Slowest but gets most accurate information as it reads from machine's registry

    param ($compName, $SamAccountName)

    Write-Host "Retrieving installed programs..."

    $Keys = '','\Wow6432Node'

    if ($SamAccountName) {
        $SID = (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -SearchBase $userSearchBase -Server "$($server):3268" | Select SID).SID.Value
    }

    $software = foreach ($Key in $keys) {

        # local machine apps
        try {
            $Apps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$compName).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
        } 

        catch {
            continue
        }

        foreach ($App in $Apps) {

            $Program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$compName).OpenSubKey("SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
            $Name = $Program.GetValue('DisplayName')

            if ($name -like "Update for Microsoft*" -or $name -like "Security Update*") {
                continue
            }

            if ($Name -and $Name -match '') {

                [pscustomobject]@{

                    Software = $Name
                    Version = $Program.GetValue('DisplayVersion')
                    Publisher = $Program.GetValue('Publisher')
                    "Install Date" = $Program.GetValue('InstallDate')
                    # "Uninstall String" = $Program.GetValue('UninstallString')
                    Bits = $(if ($Key -eq '\Wow6432Node') {'32'} else {'64'})
                    # Path = $Program.name
                }
            }
        }

        # current user apps that may have been installed in AppData
        if ($SamAccountName) {
            try {
                $CurUserApps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users',$compName).OpenSubKey("$SID\SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
            } catch {
                continue
            }

            foreach ($app in $CurUserApps) {
                $Program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users',$compName).OpenSubKey("$SID\SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
                $Name = $Program.GetValue('DisplayName')

                if ($Name -and $Name -match '') {
                    [pscustomobject]@{

                        Software = $Name
                        Version = $Program.GetValue('DisplayVersion')
                        Publisher = $Program.GetValue('Publisher')
                        # "Install Date" = $Program.GetValue('InstallDate')
                        # "Uninstall String" = $Program.GetValue('UninstallString')
                        Bits = $(if ($Key -eq '\Wow6432Node') {'32'} else {'64'})
                        # Path = $Program.name
                    }
                }
            }
        }
    }

    Write-Host "Opening a new window to display output" -ForegroundColor "green"
    $software | Select Software, Version, Publisher, Bits | Sort-Object Software | Out-GridView -Title "$compName Installed Programs"
    Set-OGVWindow -ProcessName powershell -WindowTitle "$compName Installed Programs" -Width 1000 -Height 1000

}


function Get-InstalledPrograms3 {
    ########## Queries SCCM for machine and remote registry for current user and returns installed programs for given machine ##########

    param ($compName, $SamAccountName)

    Write-Host "Retrieving installed programs..."
    Write-Host

    # local machine apps
    Write-Host "Querying SCCM for machine installs..."
    $installedPrograms = Get-CimInstance -Namespace root\cimv2\sms -ClassName SMS_InstalledSoftware -ComputerName $compName | Select ProductName, ProductVersion, Publisher, @{Name="InstallType";Expression={"System"}}


    # current user apps that may have been installed in AppData
    if ($SamAccountName) {
        Write-Host "Checking registry for current user installs..."
        $SID = (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -SearchBase $userSearchBase -Server "$($server):3268" | Select SID).SID.Value
    
        $Keys = '','\Wow6432Node'

        $installedPrograms += foreach ($Key in $keys) {

            try {
                $CurUserApps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users',$compName).OpenSubKey("$SID\SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
            } catch {
                continue
            }

            foreach ($app in $CurUserApps) {
                $Program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users',$compName).OpenSubKey("$SID\SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
                $Name = $Program.GetValue('DisplayName')

                if ($Name -and $Name -match '') {
                    [pscustomobject]@{

                        ProductName = $Name
                        ProductVersion = $Program.GetValue('DisplayVersion')
                        Publisher = $Program.GetValue('Publisher')
                        InstallType = "User"
                    }
                }
            }
        }
    }

    Write-Host "Opening a new window to display output" -ForegroundColor "green"
    $installedPrograms | Select ProductName, ProductVersion, Publisher, InstallType | Sort-Object ProductName | Out-GridView -Title "$compName Installed Programs"
    Set-OGVWindow -ProcessName powershell -WindowTitle "$compName Installed Programs" -Width 1000 -Height 1000
}


Function Get-InstalledPrograms4 {
    ########## Queries the registry remotely and returns installed programs for given machine and current user ##########
    # similar to Get-InstalledPrograms2 but uses invoke-command instead of mounting registry for local machine installs so much faster

    param ($compName, $SamAccountName)

    $Keys = '','\Wow6432Node'

    $masterKeys = @()

    Write-Host "Checking registry for local machine installs..."

    foreach ($key in $keys) {
        $regKeys = Invoke-command -ComputerName $compName -ScriptBlock {
            Get-ItemProperty "HKLM:\Software$using:key\Microsoft\Windows\CurrentVersion\Uninstall\*"
        }

        foreach($program in $regKeys) {
            $EstimatedSize = if ($Program.'EstimatedSize') {[String]([Math]::Round([int]$Program.'EstimatedSize' * 1024 / 1MB, 2)) + " MB"} else {$null}
            $InstallDate = if ($program."InstallDate") {$program."InstallDate".Insert(4,'-').Insert(7,'-')} else {$null}
            $masterKeys += (New-Object PSObject -Property @{
                "DisplayName" = $program."displayname"
                "Publisher" = $program."publisher"
                "EstimatedSize" = $EstimatedSize
                "InstallDate" = $InstallDate
                "InstallType" = "System"
                "SystemComponent" = $program."systemcomponent"
                "ParentKeyName" = $program."parentkeyname"
                "Version" = $program."DisplayVersion"
                "UninstallCommand" = $program."UninstallString"
                "Bits" = $(if ($Key -eq '\Wow6432Node') {'32'} else {'64'})
            })
        }
        
    }


    # current user apps that may have been installed in AppData
    if ($SamAccountName) {
        Write-Host "Checking registry for current user installs..."
        $SID = (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -SearchBase $userSearchBase -Server "$($server):3268" | Select SID).SID.Value
    
        $Keys = '','\Wow6432Node'

        foreach ($Key in $keys) {

            try {
                $CurUserApps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users',$compName).OpenSubKey("$SID\SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
            } catch {
                continue
            }

            foreach ($app in $CurUserApps) {
                $Program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users',$compName).OpenSubKey("$SID\SOFTWARE$Key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
                $Name = $Program.GetValue('DisplayName')

                if ($Name -and $Name -match '') {
                    $EstimatedSize = if ($Program.GetValue('EstimatedSize')) {[String]([Math]::Round([int]$Program.GetValue('EstimatedSize') * 1024 / 1MB, 2)) + " MB"} else {$null}
                    $InstallDate = if ($program."InstallDate") {$program."InstallDate".Insert(4,'-').Insert(7,'-')} else {$null}
                    $masterKeys += (New-Object PSObject -Property @{

                        "DisplayName" = $Name
                        "Version" = $Program.GetValue('DisplayVersion')
                        "InstallDate" = $InstallDate
                        "EstimatedSize" = $EstimatedSize
                        "Publisher" = $Program.GetValue('Publisher')
                        "InstallType" = "User"
                        "UninstallCommand" = $Program.GetValue("UninstallString")
                        "SystemComponent" = $Program.GetValue("systemcomponent")
                        "ParentKeyName" = $Program.GetValue("parentkeyname")
                        "Bits" = $(if ($Key -eq '\Wow6432Node') {'32'} else {'64'})

                    })
                }
            }
        }
    }


    Write-Host "Opening a new window to display output" -ForegroundColor "green"
    $woFilter = {$null -ne $_.displayname -AND $null -eq $_.ParentKeyName}
    # $props = 'DisplayName','Version','Publisher','Installdate','InstallType','UninstallCommand','RegPath'
    $props = 'DisplayName','Version','Publisher','EstimatedSize','Installdate','InstallType', 'Bits'
    $masterKeys = ($masterKeys | Where-Object $woFilter | Select-Object $props | Sort-Object DisplayName)
    $masterKeys | Out-GridView -Title "$compName Installed Programs"
    Set-OGVWindow -ProcessName powershell -WindowTitle "$compName Installed Programs" -Width 1000 -Height 1000
    
}



function Get-InstalledProgramsOffline {
    ########## Queries SCCM and returns installed programs for given machine ##########

    param ($compName)
    
    $query = "
        SELECT ProductName, ProductVersion, Publisher
        FROM SMS_R_System
        JOIN SMS_G_SYSTEM_Installed_Software on SMS_R_System.ResourceID = SMS_G_SYSTEM_Installed_Software.ResourceID
        WHERE SMS_R_SYSTEM.Name=""$($compName)""
    "

    Write-Host "Querying SCCM for machine installs..."
    $installedPrograms = Query-SCCMWmiObject -query $query | Select-Object -Property ProductName, Publisher, ProductVersion | Sort-Object ProductName 
    Write-Host "Opening a new window to display output" -ForegroundColor "green"
    $installedPrograms | Out-GridView -Title "$compName Installed Programs"
    Set-OGVWindow -ProcessName powershell -WindowTitle "$compName Installed Programs" -Width 1000 -Height 1000
}


function Open-CDollar {
    ########## Opens c$ for remote comp ##########

    param($compName)

    # doesnt seem possible to pass credentials into explorer. it will always open as current user
    Write-Host "Opening \\$($compName)\c$ in File Explorer. Enter your admin credentials" -ForeGroundColor "Green"
    Invoke-Item "\\$compName\c$"
}


function Get-SamAccountName {
    # Returns SamAccountName; if full name or UPN is given, will query AD for it

    param ($name)

    $ADUserObject = switch -Wildcard ($name) {

        "* *" {
            # Full Name
            $splitname = $name.split(" ")
            if ($splitname.Length -eq 2) {
                $givenName = $splitname[0]
                $surname = $splitname[1]
                $ADUser = Get-ADUserByFullName -givenName $givenName -surname $surname
            } elseif ($splitname.Length -eq 3) { # Case where user has 3 words in their name
                # case where first name has 2 words
                $givenName = $splitname[0] + " " + $splitname[1]
                $surname = $splitname[2]
                $ADUser = Get-ADUserByFullName -givenName $givenName -surname $surname

                if ($ADUser -eq $null) {
                    # case where last name has 2 words
                    $givenName = $splitname[0]
                    $surname = $splitname[1] + " " + $splitname[2]
                    $ADUser = Get-ADUserByFullName -givenName $givenName -surname $surname
                }
            } elseif ($splitname.Length -gt 3) {
                # case where name has more than 3 words, try first name + remaining part of name as last name
                $givenName = $splitname[0]
                $surname = $splitname[1..($splitname.length)] -join ""
                $ADUser = Get-ADUserByFullName -givenName $givenName -surname $surname
            }
            $ADUser
        }
        "*@*" {
            # User Principal Name (email)
            Get-ADUser -Filter "userPrincipalName -eq '$name'" -SearchBase $userSearchBase -Server "$($server):3268"
        }
        default {
            # sAMAccountName (LastnameF)
            [pscustomobject]@{
                SamAccountName = $name
            }
        }
    }
    
    return ($ADUserObject | Select SamAccountName).SamAccountName
}



function SCCM-FindUserObject {
    ########## Gets all SCCM objects that has the given user as its primary user OR current logon user OR last logon user ##########

    param ($SamAccountName)

    $query = "
        SELECT Name, CNIsOnline, PrimaryUser, CurrentLogonUser, LastActiveTime
        FROM SMS_CombinedDeviceResources
        WHERE SMS_CombinedDeviceResources.PrimaryUser LIKE '%\\$SamAccountName%' 
            OR SMS_CombinedDeviceResources.CurrentLogonUser LIKE '%\\$SamAccountName%'
            OR SMS_CombinedDeviceResources.LastLogonUser = '$SamAccountName'
    "

    $CompObj = Query-SCCMWmiObject -query $query
    
    return $CompObj
}


function Display-ComputerNameOutput {

    param ($CompObj)

    if ($CompObj) {
        $table = foreach ($o in $compObj ) {

            $convertedTimeStamp = ""
            if ($o.LastActiveTime) {
                $wmiTimestamp = $o.LastActiveTime.replace("***", "000")
                $convertedTimeStamp = [Management.ManagementDateTimeConverter]::ToDateTime($wmiTimestamp)
            }
            New-Object PSObject -Property @{
                ComputerName = $o.Name
                PrimaryUser = $o.PrimaryUser
                CurrentLogonUser = $o.CurrentLogonUser
                LastActiveTime = $convertedTimeStamp
                Status = if($o.CNIsOnline) {"Online"} else {"Offline"}
            }
        }
        $table | Sort-Object -Property LastActiveTime | Format-Table -Property Status, ComputerName, PrimaryUser, CurrentLogonUser, LastActiveTime | Out-Default
        if ($CompObj.Length -lt 1) {
            Set-Clipboard -Value $CompObj.Name
            Write-Host "Copied $($CompObj.Name) to clipboard!" -ForegroundColor "Green"

            Write-Host
            Write-Host "Launch Remote Machine Menu for $($CompObj.Name)?"
            $result = Read-YNKeyPrompt
            if ($result) {
                $global:remoteCompName = $CompObj.Name
                RemoteCompSubMenu
                $global:showReadHostAnyKey = $false
            }
        } else {
            Write-Host "More than 1 computer found associated with user. Please refer to the correct system" -ForegroundColor "Yellow"
        }
    } else {
        Write-Host "No associated computer name found." -ForegroundColor "Red"

        Write-Host
        Get-ComputerName -showInstructions $false

    }
}


function Get-ComputerName {
    param ($showInstructions=$true)
    $global:showReadHostAnyKey = $true

    if ($showInstructions) {
        Write-Host "Enter one of the following formats:"
        Write-Host " - LastnameF  (eg. KwanH)"
        Write-Host " - Full name  (eg. Hugo Kwan)"
        Write-Host " - UPN/Email  (eg. Hugo.Kwan@ec.gc.ca)"
        Write-Host " - IPv4       (eg. 1##.###.###.###)"
        Write-Host
    }
    # Write-Host ">> " -NoNewLine
    # $name = $Host.UI.ReadLine()
    $name = Read-HostCustom
    
    if ($name -eq "") {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    $name = $name.trim()

    # if input is an ip address, return comp name and current logon user
    $charCount = ($name.ToCharArray() -eq ".").count

    if (($charCount -eq 3) -and ($name -notlike "*@*")) {
        if (IsValidIPv4Address -ip $name) {
            ipconfig /flushdns | Out-Null
            
            try {
                $compName = [System.Net.Dns]::GetHostByAddress($name).Hostname.Split(".")[0]
                Write-Host
                Write-Host "Computer name : $compName"
            } catch {
                Write-Host "No associated computer name found." -ForegroundColor "Red"

                Write-Host
                Get-ComputerName -showInstructions $false
                return
            }
            try {
                $currentUser = (Get-CIMInstance -Class win32_computersystem -ComputerName $compName -ErrorAction SilentlyContinue).UserName
                if ($currentUser -eq $null) {$currentUser = "N/A"}
                Write-Host "Current user  : $currentUser" 
            } catch {}
            Write-Host
            return

        } else {
            Write-Host "Invalid IPv4." -ForegroundColor "Red"
            Get-ComputerName -showInstructions $false
            return
        }
    }

    $SamAccountName = Get-SamAccountName -name $name

    if ($SamAccountName -eq $null) {
        Write-Host "Could not find user profile in AD." -ForegroundColor "Red"
        Write-Host
        Get-ComputerName -showInstructions $false
        return
    } 
    elseif ($SamAccountName.Count -gt 1) {
        Write-Host "More than 1 user found with the same name. Use the specific LastnameF or UPN to refer to the correct user." -ForegroundColor "Red"
        Write-Host
        Get-ComputerName -showInstructions $false
        return 
    }

    $CompObj = SCCM-FindUserObject -SamAccountName $SamAccountName

    Display-ComputerNameOutput -CompObj $CompObj

}


function Clear-CCMCache {
    ########## Clears CCM cache/temp files found in C:\Windows\ccmcache by running Control Panel > Configuration Manager > Cache Tab > Delete Files ##########

    param ($compName)

    $ccmcachePath = ([wmi]"ROOT\ccm\SoftMgmtAgent:CacheConfig.ConfigKey='Cache'").Location
    Write-Warning "This will delete the files found in $ccmcachePath"
    Write-Host "Proceed with clearing ccm cache?"
    $result = Read-YNKeyPrompt
    if (!$result) {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }
    Write-Host

    $freeSpaceBytesBefore = (Get-CimInstance Win32_LogicalDisk -ComputerName $compName -Filter DriveType=3).freespace

    # Clear ccm cache
    Write-Host "Clearing ccm cache..."
    Invoke-Command -ComputerName $compName -ScriptBlock {
        try {
            $resman = new-object -comObject "UIResource.UIResourceMgr"
            $cacheInfo = $resman.GetCacheInfo()
            $cacheinfo.GetCacheElements() | foreach {$cacheInfo.DeleteCacheElement($_.CacheElementID)}
        } catch {
            Write-Host "Access is denied."
        }
    }

    "Freespace Before : {0:N2} GB" -f ($freeSpaceBytesBefore / 1GB)

    $freeSpaceBytesAfter = (Get-CimInstance Win32_LogicalDisk -ComputerName $compName -Filter DriveType=3).freespace
    "Freespace After  : {0:N2} GB" -f ($freeSpaceBytesAfter / 1GB)

    $spaceReclaimed = $freeSpaceBytesAfter - $freeSpaceBytesBefore
    $formatString = $spaceReclaimed / 1GB

    $template = "Reclaimed Space  : {0:N2} GB"
    if ($formatString -eq 0) { 
        $template -f "Less than 1"

    } else {
        $template -f $formatString
    }

}



function Clear-MSTeamsCache {
    ########## Clears MSTeams cache/temp files for all users on given computer name ##########

    param ($compName)
    Write-Warning "This will end the Teams.exe process and delete the following folders: Cache, blob_storage, databases, GPUcache, IndexedDB, Local Storage, tmp"
    Write-Host "Proceed with clearing MS Teams cache?"
    $result = Read-YNKeyPrompt
    if (!$result) {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }


    Invoke-Command -ComputerName $compName -ScriptBlock {

        # end all msteams processes
        Stop-Process -Name Teams -ErrorAction SilentlyContinue -Force; 

        # remove cache folders
        Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Teams\*" -Directory | Where name -in ('Cache','blob_storage','databases','GPUcache','IndexedDB','Local Storage','tmp') | ForEach{Write-Warning "Deleting all files in $($_.FullName)"; Remove-Item $_.FullName -Recurse -Force}

        Start-Sleep 5

        # Creates a scheduled task to open MSTeams immediately 
        $currentUser = (Get-CIMInstance -Class win32_computersystem).UserName
        $currentUserSAM = $currentUser.Split("\")[1]

        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -NoProfile -command (& 'C:\Users\$($currentUserSAM)\AppData\Local\Microsoft\Teams\current\Teams.exe')"
        # $action = New-ScheduledTaskAction -Execute $env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe
        $trigger = New-ScheduledTaskTrigger -Once -At (get-date).AddSeconds(2)
        $trigger.EndBoundary = (get-date).AddSeconds(3).ToString('s')
        $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType ServiceAccount
        $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DeleteExpiredTaskAfter 00:00:02
        Register-ScheduledTask -TaskName "Open-MSTeams" -Action $action -Trigger $trigger -Principal $principal -Settings $Settings | Out-Null
    }
}


function Push-GPUpdate {
    ########## Updates group policy settings on specified computer ##########
    param ($compName)

    Write-Host "Proceed with GPUpdate?"
    $result = Read-YNKeyPrompt
    if (!$result) {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    # Using pssession instead of invoke command so we can see output
    Enter-PSSession $compName
    gpupdate /force
    Exit-PSSession
}



function Run-InitialMachineScriptSomewhatParallel {
    <#
    
    Initial Machine Setup script to run on a computer after it has been reimaged

    - Set departmentNumber to 007 in AD
    - Set timezone for PYR machines to Pacific Standard Time
    - McAfee Status Monitor Actions: collect and send props, send events, enforce policies, and check new policies
    - Configuration Manager Actions: MachinePolicy, HardwareInventory, UpdateDeployment, UpdateScan, and SoftwareInventory
    - Change Power settings to never sleep when plugged in and 20 minutes on battery
    - Change Power button action to Shut Down
	- Change Close lid action to Do Nothing
    - Renames the computer to 'Ready (ComputerName)'

    #>

    Write-Verbose "This script is to be used after the imaging process has been completed and the machine(s) is/are currently logged on with your admin credentials. Proceed when the desktop has loaded." -Verbose
    # Write-Verbose "This script is to be used after the imaging process has been completed and the machine is currently at the login screen." -Verbose

    Write-Host "
    - Sets departmentNumber to 007 in AD
    - Sets time zone for PYR machines to Pacific Standard Time
    - McAfee Status Monitor Actions: Collect and Send Props/Send Events/Enforce Policies/Check New Policies
    - Configuration Manager Actions: MachinePolicy/HardwareInventory/UpdateDeployment/UpdateScan/SoftwareInventory
    - Power settings: Sleep to Never for Plugged in and 20 minutes for On battery
    - Power Button setting: Shutdown for both Plugged in and On battery
    - Close Lid setting: Do Nothing for both Plugged in and On battery
    - Disables Hibernate
    - Runs GPUpdate
    - Installs DisplayLink Graphics & reinitializes inf driver files
    - If Windows 1909:
      - Installs Windows updates (KB5005412 & KB5005031) for printer setup fix
    - If Windows 20H2
      - Installs Outlook KB5001998 fix
      - Installs OneNote 2016
    - If script is remotely executed, changes display name to `"Ready (WPXXX######)`"
    - Sends a Windows notification to the admin's computer when script is completed
    "


    Write-Host "Enter computer name (delimit by comma if multiple; eg. WXXXN######, WXXXN######, ...)"
    # Write-Host ">> " -NoNewLine
    # $computers = $Host.UI.ReadLine()
    $computers = Read-HostCustom
    if ($computers -eq "") {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    $computers = $computers.split(",").trim()

    ipconfig /flushdns | Out-Null


    $cred = Get-AuthCredential

    foreach ($c in $computers) {

        Write-Host
        Write-Host "------------------------------------------------------------------------------ $c" -ForeGroundColor $accentColour

        if (Test-TCPPort -address $c -port $WinRMPort) {

            Write-Host "Running script in external console" -ForegroundColor "Green"

            # Serialize credential object into XML? and then into encrypt into base64 string to be passed to external console
            # have to do it this way in order to pass it to external powershell as only strings can be passed between processes
            # because of this, credential object cannot be passed into external powershell normally
            $credSerialized = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([Management.Automation.PSSerializer]::Serialize($cred)))

            $ScriptBlock = {
                function Run-OnStartProcess($credSerialized, $c, $ScriptPath) {
                    # Deserialize credentials and convert back to credential object
                    $host.UI.RawUI.WindowTitle = $c
                    $cred = [Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($credSerialized)))
                    Invoke-Command -ComputerName $c -FilePath $ScriptPath -ArgumentList $cred
                    # pause
                }
            }
            Start-Process powershell -ArgumentList "-NoExit -command & {$ScriptBlock Run-OnStartProcess -credSerialized '$credSerialized' -c $($c) -ScriptPath '$InitialMachineSetupScriptPath'}" -ErrorAction SilentlyContinue

        } else {
            Write-Host "Cannot connect to $($c). Check if computer name was inputted correctly or try again with this computer later; it may take a moment for it to be set up on the network and PowerShell remoteable. Otherwise you can login on that computer and run this script again when it is loaded to the desktop." -ForeGroundColor "Red"
        }
        
        Write-Host "------------------------------------------------------------------------------" -ForeGroundColor $accentColour
    }

}


function Run-InitialMachineScriptLinear {
    <#
    
    Initial Machine Setup script to run on a computer after it has been reimaged

    - Set departmentNumber to 007 in AD
    - Set timezone for PYR machines to Pacific Standard Time
    - McAfee Status Monitor Actions: collect and send props, send events, enforce policies, and check new policies
    - Configuration Manager Actions: MachinePolicy, HardwareInventory, UpdateDeployment, UpdateScan, and SoftwareInventory
    - Change Power settings to never sleep when plugged in and 20 minutes on battery
    - Change Power button action to Shut Down
	- Change Close lid action to Do Nothing
    -Renames the computer to 'Ready (ComputerName)'

    #>

    Write-Verbose "This script is to be used after the imaging process has been completed and the machine(s) is/are currently logged on with your admin credentials. Proceed when the desktop has loaded." -Verbose

    Write-Host "Enter computer name (delimit by comma if multiple; eg. WXXXN######, WXXXN######, ...)"
    Write-Host ">> " -NoNewLine
    $computers = $Host.UI.ReadLine()
    if ($computers -eq "") {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    $computers = $computers.split(",").trim()

    ipconfig /flushdns | Out-Null

    $cred = Get-Credential "$env:USERDOMAIN\$env:USERNAME"

    foreach ($c in $computers) {

        Write-Host ""
        Write-Host "------------------------------------------------------------------------------ $c" -ForeGroundColor $accentColour

        if (Test-TCPPort -address $c -port $WinRMPort) {

            Invoke-Command -ComputerName $c -FilePath $InitialMachineSetupScriptPath -ArgumentList $cred

            # $restartWinlogonDef = "function RestartWinlogon { ${function:RestartWinlogon} }"
            # Invoke-Command -ComputerName $c -ArgumentList $restartWinlogonDef -ScriptBlock {

            #     param( $restartWinlogonDef )
            #     . ([ScriptBlock]::Create($restartWinlogonDef))
                
                # Write-Output "Logging all users off..."
                # Write-Output "============================="
                # # Logs off all users
                # $regex='(?<=\s+)\d+(?=\s+[a-z])'
                # quser 2>&1 | select-string -allmatches $regex | % {logoff $_.matches.value}
                # Start-Sleep -Seconds 10
                # Write-Output "Logged off"
                # Write-Output "============================="
                # Write-Output ""

                # # Changes the display name at login screen so we can tell which machines are ready
                # Write-Output "Changing Login Display Name..."
                # Write-Output "============================="
                # $registryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
                
                # $localAdminSID = (Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = TRUE and SID like 'S-1-5-%-500'" | Select SID).SID
                # $usernameADM = $env:USERNAME
                # $displayName = "Ready ($($env:computerName))"
                # $provider = "{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}"
                # $SAMUser = "$($env:UserDomain)\$($usernameADM)"
                # $upn = "$($usernameADM)@ec.gc.ca"
                # $currentUserSID = (Get-CimInstance Win32_UserAccount -Filter "Name = '$($usernameADM)'").SID

                # # # Uncomment these and comment out the next block to use own admin account as placeholder instead of local admin
                # # set-ItemProperty -Path $registryPath -Name "LastLoggedOnDisplayName" -Value $displayName
                # # set-ItemProperty -Path $registryPath -Name "LastLoggedOnProvider" -Value $provider
                # # set-ItemProperty -Path $registryPath -Name "LastLoggedOnSAMUser" -Value $SAMUser
                # # set-ItemProperty -Path $registryPath -Name "LastLoggedOnUser" -Value $upn
                # # set-ItemProperty -Path $registryPath -Name "LastLoggedOnUserSID" -Value $currentUserSID
                # # set-ItemProperty -Path $registryPath -Name "SelectedUserSID" -Value $currentUserSID

                # set-ItemProperty -Path $registryPath -Name "LastLoggedOnDisplayName" -Value $displayName
                # set-ItemProperty -Path $registryPath -Name "LastLoggedOnProvider" -Value $provider
                # set-ItemProperty -Path $registryPath -Name "LastLoggedOnSAMUser" -Value ".\ECSECUSER"
                # set-ItemProperty -Path $registryPath -Name "LastLoggedOnUser" -Value ".\ECSECUSER"
                # set-ItemProperty -Path $registryPath -Name "LastLoggedOnUserSID" -Value $localAdminSID
                # set-ItemProperty -Path $registryPath -Name "SelectedUserSID" -Value $localAdminSID

                # Write-Output "Login Display Name set to '$($displayName)'"
                # Write-Output "============================="
                # Write-Output ""

                # # Restart comp so the display name will change
                # # Restart-Computer
                # RestartWinlogon
            # }



        } else {
            Write-Host "Cannot connect to $($c). Please check if it was inputted correctly or try again with this computer later; it sometimes takes a moment for it to be set up on the network." -ForeGroundColor "Red"
        }
        
        Write-Host "------------------------------------------------------------------------------" -ForeGroundColor $accentColour
    }

}


function Open-RemoteControlViewer {
    # Write-Host "Opening Remote Control Viewer with admin credentials" -ForegroundColor "Green"
    try {
        & "C:\Program Files (x86)\Microsoft Endpoint Manager\AdminConsole\bin\i386\CmRcViewer.exe"
    } catch {
        # if CmRcViewer isnt installed at above location
        $RCViewerLocation = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name SMS_ADMIN_UI_PATH).SMS_ADMIN_UI_PATH
        $RCViewerLocation = $RCViewerLocation + "\CmRcViewer.exe"
        & $RCViewerLocation
    }
}


function Connect-RemoteControlViewer {
    ########## Opens Remote Control Viewer and connects to given computer name ##########
    param ($compName)

    Write-Verbose "This will open Remote Control Viewer and immediately send a connection request" -Verbose
    Write-Host "Open Remote Control Viewer and connect to $($compName)?"
    $result = Read-YNKeyPrompt
    if ($result) {
        Write-Host "Opening Remote Control Viewer..." -ForeGroundColor "Green"
        try {
            & "C:\Program Files (x86)\Microsoft Endpoint Manager\AdminConsole\bin\i386\CmRcViewer.exe" $compName
        } catch {
            # if CmRcViewer isnt installed at above location
            $RCViewerLocation = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name SMS_ADMIN_UI_PATH).SMS_ADMIN_UI_PATH
            $RCViewerLocation = $RCViewerLocation + "\CmRcViewer.exe"
            & $RCViewerLocation $compName
        }

    } else {
        Write-Host "Action cancelled." -ForegroundColor "red"
    }
}


function Get-ADUserObject {
    ########## Returns object of user from AD ##########

    param ($name)

    $ADUserObject = switch -Wildcard ($name) {

        "* *" {
            # Full Name
            $splitname = $name.split(" ")
            if ($splitname.Length -eq 2) {
                $givenName = $splitname[0]
                $surname = $splitname[1]
                $ADUser = Get-ADUserByFullName -givenName $givenName -surname $surname
            } elseif ($splitname.Length -eq 3) { # Case where user has 3 words in their name
                # case where first name has 2 words
                $givenName = $splitname[0] + " " + $splitname[1]
                $surname = $splitname[2]
                $ADUser = Get-ADUserByFullName -givenName $givenName -surname $surname

                if ($ADUser -eq $null) {
                    # case where last name has 2 words
                    $givenName = $splitname[0]
                    $surname = $splitname[1] + " " + $splitname[2]
                    $ADUser = Get-ADUserByFullName -givenName $givenName -surname $surname
                }
            }
            $ADUser
        }
        "*@*" {
            # User Principal Name (email)
            Get-ADUser -Filter "userPrincipalName -eq '$name'" -SearchBase $userSearchBase -Server "$($server):3268" -Properties *
        }
        default {
            # SamAccountName (LastnameF)
            Get-ADUser -Filter "SamAccountName -eq '$name'" -SearchBase $userSearchBase -Server "$($server):3268" -Properties *
        }

    }
    
    return $ADUserObject
}


function Get-ADUserInfo {
    ########## Returns info about user from AD ##########

    param ($DistinguishedName)

    $userObj = $global:ADUserObjectGlobal | Select-Object -Property GivenName, Surname, Title, AccountExpirationDate, Description, SID, PrimaryGroup, SamAccountName, EmailAddress, StreetAddress, City, State, @{Name="Manager";Expression={$_.Manager + "`n"}}, mailNickname, targetAddress
    ($userObj | Out-String).trim()

    # will show a message if mailNickname is not the same as targetAddress
    $splitTargetAddress = $userObj.targetAddress.split("@")[0].split(":")[1]
    if ($userObj.mailNickname -ne $splitTargetAddress) {
        Write-Host "targetAddress does not match mailNickname. Please submit a ticket to IT-ACC MGT for a fix request" -ForegroundColor "Red"
        Write-Host
    }
    Write-Host
}


function Get-ADUserGroupInfo {
    # returns the name and description of all groups the given user is a member of

    param ($DistinguishedName, $regionDomain)

    Write-Host "This will return the name and description of all groups the user is a member of. Proceed?"
    $result = Read-YNKeyPrompt
    if (!$result) {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Write-Host "Querying AD for all groups that the user is a member of. This may take a moment..."
    $Groups = Get-ADPrincipalGroupMembership -Identity $DistinguishedName -Server $regionDomain | Get-ADGroup -Properties * | select-object Name, Description | Sort-Object Name
    Write-Host "Opening a new window to display output" -ForegroundColor "green"
    $Groups | Out-GridView -title "Group Memberships"
    Set-OGVWindow -ProcessName powershell -WindowTitle "Group Memberships" -Width 1000 -Height 1000

}


function Reset-ADUserPassword {
    ########## Changes the user's password in AD ##########
    
    param ($DistinguishedName, $regionDomain)

    Write-Host "Proceed with resetting the password?"
    $result = Read-YNKeyPrompt
    if (!$result) {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }
    
    Write-Host

    do {
        # use this way instead of Read-Host with prompt or it wont accept nonalphanumeric characters for first character
        # Write-Host -NoNewline 'Enter a new password: '; $newPassword = Read-Host
        $newPassword = Read-HostCustom -prompt "Enter a new password: "

        if (!$newPassword) {
            Write-Host "Action cancelled." -ForegroundColor "red"
            return
        }
        $meetsComplexity = Test-PasswordForDomain -Password $newPassword -samAccountName $samAccountName -AccountDisplayName $displayName

        if ($meetsComplexity) { break }

        Write-Host
    } while (!$meetsComplexity)


    try {
        Set-ADAccountPassword $DistinguishedName -Server $regionDomain -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force -Verbose) -PassThru
        Write-Host
        Write-Host "Password updated successfully" -ForeGroundColor "Green"
    } catch {
        Write-Host "Password failed to change" -ForeGroundColor "Red"
    }
}

function Unlock-ADUserAccount {
    ########## Unlocks user account in AD due to being locked from too many password attempts ##########
    
    param ($DistinguishedName, $regionDomain)

    Write-Host "Proceed with unlocking the account?"
    $result = Read-YNKeyPrompt
    if (!$result) {
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Unlock-ADAccount -Identity $DistinguishedName -Server $regionDomain
}



function Run-McAfeeActions {
    ########## Runs McAfee actions on remote comp ##########

    param($compName)

    Write-Host "This will run the following actions in McAfee Agent Monitor:"
    Write-Host " - Collect and Send Props"
    Write-Host " - Send Events"
    Write-Host " - Check New Policies"
    Write-Host " - Enforce Policies"
    Write-Host
    Write-Host "Proceed with running McAfee Actions?"
    $result = Read-YNKeyPrompt
    if (!$result) {
        return
    }

    Write-Host
    Write-Host "Creating Scheduled Task to run McAfee Actions..."
    Write-Host
    $checkLockDef = "function checkLock { ${function:checkLock} }"
    Invoke-Command -ComputerName $compName -ArgumentList $checkLockDef -ScriptBlock ${function:RunMcAfeeActions}
    Write-Host
}


function Run-ConfigManagerActions {
    ########## Runs ConfigMngr and McAfee actions on remote comp ##########

    param($compName)

    Write-Host "This will run the following actions in Configuration Manager:"
    Write-Host " - Machine Policy Retrieval & Evaluation Cycle"
    Write-Host " - Application Deployment Evaluation Cycle"
    Write-Host " - Hardware Inventory Cycle"
    Write-Host " - Software Updates Deployment Evaluation Cycle"
    Write-Host " - Software Updates Scan Cycle"
    # Write-Host " - Software Inventory Cycle"
    Write-Host
    Write-Host "Proceed with running Configuration Manager Actions?"
    $result = Read-YNKeyPrompt
    if (!$result) {
        return
    }
    
    Write-Host
    Write-Host "Running Configuration Manager Actions..."
    RunConfigManagerActions -compName $compName
    Write-Host

}


function Suspend-BitLocker1 {
    # Suspends BitLocker on C: drive for 1 reboot
    # named it with a 1 because the actual function is named the same and im too dumb to think of another name

    # this is mainly for me to use since my laptop lid is closed and it's a bitch to enter the pin for the next boot

    Get-BitLockerVolume $env:systemDrive | Select MountPoint, CapacityGB, VolumeStatus, EncryptionPercentage, ProtectionStatus | Format-Table

    Write-Host "Suspend Bitlocker for 1 reboot?"
    $result = Read-YNKeyPrompt
    if (!$result) {
        return
    }

    Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 1 | Out-Null
    
    $ProtectionStatus = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
    if ($ProtectionStatus -eq "Off") {
        Write-Host
        Write-Host "Successfuly suspended BitLocker for 1 reboot" -ForegroundColor "Green"
    } else {
        Write-Host "BitLocker was not suspended"  -ForegroundColor "Red"
    }
    Get-BitLockerVolume $env:systemDrive | Select MountPoint, CapacityGB, VolumeStatus, EncryptionPercentage, ProtectionStatus | Format-Table

    Write-Host
}


function AzureAD-ElevateRoles {
    ########## Modified version of PIM Activation script by Patrick Carrier ##########
   
    # Checks to see if AzureADPreview Module is installed
    if (-Not (Get-Module -ListAvailable -Name AzureADPreview)) {
        Write-Host "AzureADPreview Module not found. Downloading & installing..." -ForegroundColor "Green"
        Install-Module AzureADPreview -Force -Verbose -Scope CurrentUser
    }
    Import-Module AzureADPreview

    $tenID = "740c5fd3-6e8b-4176-9cc9-454dbe4e62c4"
    $autAdmin = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    $secReader = "5d6b6bb7-de71-4623-b4af-96380a352509"
    $repReader = "4a5d8f65-41da-4de4-8968-e035b65339cf"
    $reason = "Script Activated - Daily Tasks"
    try {
        if (!$global:connect) {
            Write-Host "Sign in to AzureAD on login pop up"
            $global:connect = Connect-AzureAD -ErrorAction SilentlyContinue
            Write-Host "Successfully authenticated" -ForegroundColor "Green"
            Write-Host
        }
    } catch {
        Write-Host "Could not connect to AzureAD." -ForegroundColor "Red"
        Write-Host $Error[0] -ForegroundColor "Red"
        return
    }
    $account = Get-AzureADUser -ObjectId "$($global:connect.account.id)"
    $uoid = $account.objectid
    $quit = $false
    while ($quit -eq $false){
        write-host "[1] " -NoNewLine -ForegroundColor $accentColour; Write-Host "Authentication Admin (MFA)"
        write-host "[2] " -NoNewLine -ForegroundColor $accentColour; Write-Host "Reports Reader"
        write-host "[3] " -NoNewLine -ForegroundColor $accentColour; Write-Host "Security Reader"
        write-host
        write-host "[ESC] " -NoNewLine -ForegroundColor $accentColour; Write-Host "Return"
        write-host

        $validInputs = @("1","2","3")
        # 27 = ESC
        $validVKCInputs = @("27")

        do {

            $KeyPress = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown');

            $K = $KeyPress.Character
            $VKC = $KeyPress.VirtualKeyCode

        } until (($K -in $validInputs) -or ($VKC -in $validVKCInputs))
        if ($VKC -eq "27") {
            $choice = "Q"
        } else {
            $choice = $K
        }

        $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
        $schedule.Type = "Once"
        $schedule.StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $schedule.EndDateTime = (Get-Date).AddHours(8).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        try {
            switch ($choice){
                1 { # Allows you to reset or assign new number for MFA in Azure AD and clear all current MFA sessions.
                    Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId "aadRoles" -ResourceId "$tenID" -RoleDefinitionId "$autAdmin" -SubjectId "$uoid" -Type "userAdd" -AssignmentState "Active" -Schedule $schedule -Reason "$reason"
                }
                2 { # Allows you to read sign-in and audit logs in AzureAD for any user.
                    Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId "aadRoles" -ResourceId "$tenID" -RoleDefinitionId "$repReader" -SubjectId "$uoid" -Type "userAdd" -AssignmentState "Active" -Schedule $schedule -Reason "$reason"
                }
                3 { # Allows you to read security information and reports in AzureAD and O365
                    Open-AzureADMSPrivilegedRoleAssignmentRequest -ProviderId "aadRoles" -ResourceId "$tenID" -RoleDefinitionId "$secReader" -SubjectId "$uoid" -Type "userAdd" -AssignmentState "Active" -Schedule $schedule -Reason "$reason"
                }
                Q { return }
            }
            write-host "Activation successful" -ForegroundColor Green
        } catch {
            write-host "Activation failed. Please ensure you have the rights to access these permissions" -ForegroundColor Red
        }

        write-host
        Write-host "Activate another?"
        $result = Read-YNKeyPrompt
        write-host
        if (!$result){
            $quit = $true
        }
    }

}


function Deploy-DisplayLink {
    ########## Installs DisplayLink onto given computer ##########

    param ($compName)

    Write-Host "Install DisplayLink?"
    $result = Read-YNKeyPrompt

    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    $installedVersion = Invoke-Command -ComputerName $compName -ScriptBlock {
        (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -like "*DisplayLink*"} | Select-Object DisplayVersion).DisplayVersion
    }

    # # Checks given MSI's version
    # $FullPath = $displayLinkMsiPath  
    # $windowsInstaller = New-Object -com WindowsInstaller.Installer
    # $database = $windowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null, $windowsInstaller, @($FullPath, 0))
    # $q = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
    # $View = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $Null, $database, ($q))
    # $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null)
    # $record = $View.GetType().InvokeMember("Fetch", "InvokeMethod", $Null, $View, $Null)
    # $MSIVersion = $record.GetType().InvokeMember("StringData", "GetProperty", $Null, $record, 1)
    # $View.GetType().InvokeMember("Close", "InvokeMethod", $Null, $View, $Null)

    $MSIVersion = Get-MSIVersion $displayLinkMsiPath

    if ($MSIVersion -gt $installedVersion) {

        Write-Host "Transferring Displaylink.msi file..."
        Copy-Item $displayLinkMsiPath "\\$compName\c$\temp\"

        Invoke-Command -ComputerName $compName -ScriptBlock {

            $DLInstallLog = "C:\temp\DisplayLinkLog.txt"

            Write-Host "Installing DisplayLink $MSIVersion..."
            $resultCode = (Start-Process -Wait -PassThru -FilePath msiexec -Args "/i c:\temp\DisplayLink_Win10RS.msi /qn /norestart /l* $DLInstallLog").ExitCode
            if ($resultCode -eq 0) {
                Write-Host "Installed DisplayLink successfully"
            } else {
                Write-Host "Installation failed. Check $DLInstallLog for details"
            }
            Write-Host
            $drivers = Get-ChildItem "C:\Program Files\DisplayLink Core Software\Drivers" -Recurse -Filter "*.inf"
            foreach ($driver in $drivers) { 
                PNPUtil.exe /add-driver $Driver.FullName /install 
            }

            Write-Host "Deleting the installation file..."
            Remove-Item "c:\temp\DisplayLink_Win10RS.msi" -force -Recurse
            
        }
    } else {
        Write-Host "Installed DisplayLink version is already equal to or greater than the given MSI installer"
    }

}




function Deploy-McAfeeFRP {
    ########## Installs McAfee File and Removable Media Protection onto given computer ##########

    param ($compName)

    $software = "McAfee File and Removable Media Protection"

    Write-Host "Install $($software)?"
    $result = Read-YNKeyPrompt

    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }


    $msiFiles = Get-ChildItem -Path $McAfeeFRPMSIPath -Recurse -Include *.msi

    $latestVerPath = ""
    $latestVer = 0
    foreach ($msi in $msiFiles) {
        $MSIVersion = Get-MSIVersion $msi.FullName
        if ($MSIVersion -gt $latestVer) {
            $latestVer = $MSIVersion
            $latestVerPath = $msi.FullName
        }
    }

    $fileName = Split-Path $latestVerPath -leaf
    $fileNameWOext = [System.IO.Path]::GetFileNameWithoutExtension($fileName)

    # check if it is already installed
    $installed = Invoke-Command -ComputerName $compName -ScriptBlock {
        (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -eq $using:software }) -ne $null
    }

    if ($installed) {
        Write-Host "$software is already installed." -ForegroundColor "Green"
        return
    }

    Write-Host
    Write-Host "Copying $fileName to \\$($compName)\c$\temp"
        
    Copy-Item $latestVerPath "\\$compName\c$\temp"
    
    Write-Host "Installing $fileName on $compName"
    Write-Host
    
    $result_code = Invoke-Command -ComputerName $compName -ScriptBlock {
        (Start-Process -Wait -Passthru -FilePath msiexec -ArgumentList /q, /i, "c:\temp\$($using:fileName)", /norestart, /l*, "C:\temp\$($using:fileNameWOext)Install.log").ExitCode
    }
    # Start-Sleep 3
    if ($result_code -eq 0) {
        Write-Host "Successfully installed"

    } elseif ($result_code -eq 3010) {
        Write-Host "Successfully installed. A reboot is required to complete the installation" -ForegroundColor "Green"

        # $msg = "$software has been successfully installed. Please reboot your computer to complete the installation."
        # msg * /server:$compName "$msg"                                                                       # This show the user that sent it
        # Invoke-WmiMethod -Path Win32_Process -Name Create -ArgumentList "msg * $msg" -ComputerName $compName # This doesnt

        Write-Host "A Windows toast notification was sent to inform $compName"
        $title = "McAfee FRP installed successfully"
        $msg = "Please reboot your computer to complete the installation"
        # $existStartApps = Get-StartApps | Select-String "McAfee File and Removable Media Protection"
        $app = Invoke-Command -ComputerName $compName -ScriptBlock {
            $existStartApps = Get-StartApps | Select-String "McAfee Endpoint Security"
            if ($existStartApps) {
                "McAfee.EndpointSecurity.AlertToasts"
            } else {
                # uses microsoft security as toast notif app
                "Microsoft.Windows.SecHealthUI_cw5n1h2txyewy!SecHealthUI"
            }
        }
        $img = "C:\Program Files\McAfee\Endpoint Encryption for Files and Folders\resources\logo-mcafee-shield.png"

        Send-ToastMessage -compName $compName -app $app -title $title -Message $msg -img $img

    } else {
        Write-Host "Received error code: $result_code"
        Write-Host "Refer to https://docs.microsoft.com/en-us/windows/win32/msi/error-codes for more details"
    }

    Write-Host
    Write-Host "Deleting the installation file"
    Write-Host
    Invoke-Command -ComputerName $compName -ScriptBlock {Remove-Item "c:\temp\$($using:fileName)" -force }

}



function Lock-Workstation {
    # Schedules a task to lock the computer
    param ($compName)


    Write-Host "This will lock the workstation. Proceed?"
    $result = Read-YNKeyPrompt

    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Invoke-Command -ComputerName $compName -ScriptBlock {
        $currentUser = (Get-CIMInstance -Class win32_computersystem).UserName

        $action =  (New-ScheduledTaskAction -Execute powershell.exe -Argument "-WindowStyle Hidden -NoProfile -command (rundll32.exe user32.dll,LockWorkStation)")
        $trigger = New-ScheduledTaskTrigger -Once -At (get-date).AddSeconds(2)
        $trigger.EndBoundary = (get-date).AddSeconds(3).ToString('s')
        $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType ServiceAccount 
        $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DeleteExpiredTaskAfter 00:00:02
        Register-ScheduledTask -TaskName "Lock-Workstation" -Action $action -Trigger $trigger -Principal $principal -Settings $Settings | Out-Null
    }

    Start-Sleep 2.5

}






# -----------------------------------------------------------------------------------------------------
# Report Generating Script Functions
# -----------------------------------------------------------------------------------------------------

function SCCM-GetAllCompsWithInstalledSoftware {
    ########## Creates a report of all machines that have a given software from SCCM ##########

    Write-Verbose "This script will return a report of all $($regionLetters) machines that have a specified software installed." -Verbose

    Write-Host "Do you wish to proceed?"
    $result = Read-YNKeyPrompt

    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Write-Host
    Write-Verbose "Be as specific as possible (eg. Enter 'Cisco AnyConnect Secure Mobility Client' or it will also include 'Cisco Diagnostics & Reporting tool' if only 'Cisco' is entered)" -Verbose
    $SoftwareName = Read-Host "Enter the software name"

    if ($SoftwareName -eq ""){
        Write-Host "Action cancelled. No input given." -ForegroundColor "red"
        return
    }

    Check-ImportExcelInstall

    Write-Host
    Write-Verbose "Querying SCCM for all $($regionLetters) machines with $SoftwareName. This may take a moment..." -Verbose

    $query = "
        SELECT SMS_R_System.Name, SMS_G_SYSTEM_Installed_Software.ProductName, SMS_G_SYSTEM_Installed_Software.ProductVersion, SMS_G_SYSTEM_System_Console_Usage.TopConsoleUser, SMS_CombinedDeviceResources.PrimaryUser, SMS_CombinedDeviceResources.CurrentLogonUser
        FROM SMS_R_System 
        JOIN SMS_G_SYSTEM_Installed_Software on SMS_R_System.ResourceID = SMS_G_SYSTEM_Installed_Software.ResourceID
        JOIN SMS_G_System_SYSTEM_CONSOLE_USAGE on SMS_R_System.ResourceID = SMS_G_System_SYSTEM_CONSOLE_USAGE.ResourceID
        JOIN SMS_CombinedDeviceResources ON SMS_CombinedDeviceResources.ResourceID = SMS_R_System.ResourceID
        WHERE SMS_G_SYSTEM_Installed_Software.ARPDisplayName LIKE ""$($SoftwareName)%"" AND SMS_R_System.Name LIKE ""W$($regionLetters)%""
    "

    $object = Query-SCCMWmiObject -Query $query

    New-Item -ItemType Directory -Force -Path $pathToReports | Out-Null
    $softwareNameNoSpace = $SoftwareName.replace(' ','')
    $csvFile = "$($pathToReports)\CompsWith$($softwareNameNoSpace).csv"

    $csv = New-Object -TypeName PSObject

    foreach ($o in $object){

        $csvobj = [pscustomobject]@{
            ComputerName = $o.SMS_R_System.Name
            PrimaryUser = $o.SMS_CombinedDeviceResources.PrimaryUser
            # TopConsoleUser = $o.SMS_G_SYSTEM_System_Console_Usage.TopConsoleUser
            CurrentLogonUser = $o.SMS_CombinedDeviceResources.CurrentLogonUser
            ProductName = $o.SMS_G_SYSTEM_Installed_Software.ProductName
            ProductVersion = $o.SMS_G_SYSTEM_Installed_Software.ProductVersion
        }
        $csvobj | Export-Csv $csvFile -NoTypeInformation -Append

    }

    Convert-CSVToExcel -csvFile $csvFile

}


function SCCM-GetAllCompsWithOutInstalledSoftware {
    ########## Creates a report of all machines that have a given software from SCCM ##########

    Write-Verbose "This script will return a report of all $($regionLetters) machines that DO NOT have a specified software installed." -Verbose
    
    Write-Host "Do you wish to proceed?"
    $result = Read-YNKeyPrompt

    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Write-Host
    Write-Verbose "Be as specific as possible (eg. Cisco AnyConnect Secure Mobility Client or it will also include Cisco Diagnostics & Reporting tool if only Cisco is entered)" -Verbose
    $SoftwareName = Read-Host "Enter the software name"

    if ($SoftwareName -eq ""){
        Write-Host "Action cancelled. No input given." -ForegroundColor "red"
        return
    }

    Check-ImportExcelInstall

    Write-Host
    Write-Verbose "Querying SCCM for all $($regionLetters) machines without $SoftwareName. This may take a moment..." -Verbose

    $query = "
        SELECT SMS_R_System.Name, SMS_CombinedDeviceResources.PrimaryUser, SMS_CombinedDeviceResources.CurrentLogonUser
        FROM SMS_R_System  
        JOIN SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId
        JOIN SMS_CombinedDeviceResources ON SMS_CombinedDeviceResources.ResourceID = SMS_R_System.ResourceID
        WHERE SMS_G_System_COMPUTER_SYSTEM.Name LIKE ""W$($regionLetters)%"" AND SMS_G_System_COMPUTER_SYSTEM.Name NOT IN
            (SELECT DISTINCT SMS_G_System_COMPUTER_SYSTEM.Name 
            FROM SMS_R_System
            JOIN SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceId  
            JOIN SMS_G_System_INSTALLED_SOFTWARE on SMS_G_System_INSTALLED_SOFTWARE.ResourceID = SMS_R_System.ResourceId  
            WHERE SMS_G_System_INSTALLED_SOFTWARE.ProductName LIKE ""$($SoftwareName)%"")
    "

    $object = Query-SCCMWmiObject -Query $query

    New-Item -ItemType Directory -Force -Path $pathToReports | Out-Null
    $softwareNameNoSpace = $SoftwareName.replace(' ','')
    $csvFile = "$($pathToReports)\CompsWITHOUT$($softwareNameNoSpace).csv"

    $csv = New-Object -TypeName PSObject

    foreach ($o in $object){

        $csvobj = [pscustomobject]@{
            ComputerName = $o.SMS_R_System.Name
            PrimaryUser = $o.SMS_CombinedDeviceResources.PrimaryUser
            # TopConsoleUser = $o.SMS_G_SYSTEM_System_Console_Usage.TopConsoleUser
            CurrentLogonUser = $o.SMS_CombinedDeviceResources.CurrentLogonUser
            # ProductName = $o.SMS_G_SYSTEM_Installed_Software.ProductName
            # ProductVersion = $o.SMS_G_SYSTEM_Installed_Software.ProductVersion
        }
        $csvobj | Export-Csv $csvFile -NoTypeInformation -Append

    }

    Convert-CSVToExcel -csvFile $csvFile

}


function SCCM-GetClientCheckDetail {
    ########## Creates a report of the client check detail tab for machines from SCCM ##########

    Write-Verbose "This script will return a report of the Client Check Details / Evaluation Status for all $($regionLetters) machines." -Verbose

    Write-Host "Do you wish to proceed?"
    $result = Read-YNKeyPrompt

    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Check-ImportExcelInstall

    Write-Host
    Write-Verbose "Querying SCCM for all $($regionLetters) machines' client status check. This may take a moment..." -Verbose

    $query = "
        SELECT *
        FROM SMS_R_System as sys
        JOIN SMS_CH_EvalResult as eval on sys.ResourceID = eval.ResourceID
        WHERE sys.Name LIKE ""W$($regionLetters)%""
    "
    $object = Query-SCCMWmiObject -Query $query

    New-Item -ItemType Directory -Force -Path $pathToReports | Out-Null
    $csvFile = "$($pathToReports)\SCCM_EvaluationStatus.csv"

    $csv = New-Object -TypeName PSObject

    foreach ($o in $object){
        
        # Converts timestamp into smt readable
        $wmiTimestamp = $o.eval.EvalTime.replace("***", "000")
        $convertedTimeStamp = [Management.ManagementDateTimeConverter]::ToDateTime($wmiTimestamp)

        # Converts result to evaluation status
        $evalResult = switch ($o.eval.Result) {
            1 {'Not Yet Evaluated'}
            2 {'Not Applicable'}
            3 {'Evaluation Failed'}
            4 {'Evaluated Remediated Failed'}
            5 {'Not Evaluated Dependency Failed'}
            6 {'Evaluated Remediated Succeeded'}
            7 {'Evaluation Succeeded'}
        }

        # Converts result code decimal to hex
        $resultCodeHex = '0x{0:X8}' -f $o.eval.ResultCode

        $csvobj = [pscustomobject]@{
            ComputerName = $o.sys.Name

            RuleName = $o.eval.HealthCheckDescription
            EvalTime = $convertedTimeStamp
            Result = $evalResult
            ResultCode = $resultCodeHex
            ResultDetail = $o.eval.ResultDetail
        }
        $csvobj | Export-Csv $csvFile -NoTypeInformation -Append

    }

    Convert-CSVToExcel -csvFile $csvFile

}



function SCCM-GetMachineData {
    ########## Creates a report of machine data from SCCM ##########

    Write-Verbose "This script will return a report of all $($regionLetters) machines and its system info. This includes comp name, last logon user, SCCM version, manufacturer/model/SN" -Verbose
    
    Write-Host "Do you wish to proceed?"
    $result = Read-YNKeyPrompt

    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Check-ImportExcelInstall
    
    Write-Host
    Write-Verbose "Querying SCCM for all $($regionLetters) machine data. This may take a moment..." -Verbose

    New-Item -ItemType Directory -Force -Path $pathToReports | Out-Null
    $csvFile = "$($pathToReports)\SCCM_MachineData.csv"

    $query = "
        SELECT
            SMS_R_System.Name,
            SMS_R_System.LastLogonUserName,
            SMS_R_System.LastLogonUserDomain,
            SMS_R_System.LastLogonTimestamp,
            SMS_G_System_OPERATING_SYSTEM.Version,
            SMS_G_System_COMPUTER_SYSTEM.SystemType,
            SMS_CombinedDeviceResources.ClientVersion,
            SMS_G_System_COMPUTER_SYSTEM.Manufacturer,
            SMS_G_System_COMPUTER_SYSTEM.Model,
            SMS_CombinedDeviceResources.SerialNumber
        FROM SMS_R_System 
        JOIN SMS_CombinedDeviceResources on SMS_CombinedDeviceResources.ResourceID = SMS_R_System.ResourceID
        JOIN SMS_G_System_OPERATING_SYSTEM on SMS_G_System_OPERATING_SYSTEM.ResourceID = SMS_R_System.ResourceID
        JOIN SMS_G_System_COMPUTER_SYSTEM on SMS_G_System_COMPUTER_SYSTEM.ResourceID = SMS_R_System.ResourceID
        WHERE SMS_R_System.Name LIKE ""W$($regionLetters)%""
    "


    $object = Query-SCCMWmiObject -Query $query

    $csv = New-Object -TypeName PSObject

    foreach ($o in $object){
        try {
            $datetimestamp = [Management.ManagementDateTimeConverter]::ToDateTime($o.SMS_R_System.LastLogonTimestamp) 
        } catch {
            $datetimestamp = $null
        }
        $csvobj = [pscustomobject]@{
            ComputerName = $o.SMS_R_System.Name
            UserName = $o.SMS_R_System.LastLogonUserName
            UserDomainName = $o.SMS_R_System.LastLogonUserDomain
            OSVersion = $o.SMS_G_System_OPERATING_SYSTEM.Version
            SystemType = $o.SMS_G_System_COMPUTER_SYSTEM.SystemType
            LastLogonTimestamp = $datetimestamp
            SCCMClientVersion = $o.SMS_CombinedDeviceResources.ClientVersion
            Manufacturer = $o.SMS_G_System_COMPUTER_SYSTEM.Manufacturer
            Model = $o.SMS_G_System_COMPUTER_SYSTEM.Model
            SerialNumber = $o.SMS_CombinedDeviceResources.SerialNumber
        }
        $csvobj | Export-Csv $csvFile -NoTypeInformation -Append

    }

    Convert-CSVToExcel -csvFile $csvFile
}




function Get-RemoteSCCMHealthStatus {
    ########## Creates a report of all machines' SCCM health by running a remote command to read the result in CcmEvalReport.xml file ##########
    Write-Verbose "This script will return a report of all $($regionLetters) machines' SCCM Health by running a remote command to check the result in their C:\Windows\CCM\CcmEvalReport.xml file" -Verbose
    
    Write-Host "Do you wish to proceed?"
    $result = Read-YNKeyPrompt

    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Check-ImportExcelInstall
    
    Write-Host

    $startTime = (Get-Date)

    Get-AllCompsFromAD
    $Computers = Get-Content $allCompsFile
    
    New-Item -ItemType Directory -Force -Path $pathToReports | Out-Null
    $csvFile = "$pathToReports\Remote_SCCMHealthCheck.csv"


    # Flush DNS to clear records from cache 
    ipconfig /flushdns | Out-Null

    Write-Host "Retriving SCCM Health from machines..."


    Invoke-Command -ComputerName $Computers -ThrottleLimit $ThrottleLimit -ErrorAction SilentlyContinue -ErrorVariable uhOh -ScriptBlock {
        try {

            [xml]$CcmEvalReport = Get-Content C:\Windows\CCM\CcmEvalReport.xml

            $xmlObj = Select-Xml -Xml $CcmEvalReport -XPath "/ClientHealthReport/Summary" 
            $evalTime = $xmlObj.node.EvaluationTime
            if ($evalTime -ne $null) {
                $evalTime = Get-Date $evalTime
            } 
            return [PSCustomObject]@{
                ComputerName     = $($env:ComputerName)
                EvaluationStatus = $xmlObj.node.innerxml
                EvaluationTime   = $evalTime
            }

        } catch {
            # catch misc errors
            return [PSCustomObject]@{
                ComputerName     = $($env:ComputerName)
                Error            = $($_)
            }
        }
    } | % { 
            $selectProperties = $_ | Select-Object -Property ComputerName, EvaluationStatus, EvaluationTime, Error
            Write-Output $selectProperties
            # Select only the listed properties and exported it into csv file
            $selectProperties | Export-csv $csvfile -NoTypeInformation -append 
    }
            
    Write-Host "####################################### Compiling errors..."

    if ($uhOh) {
        Write-Host "Could not reach $($uhOh.count) machines"
        foreach ($e in $uhOh) {

            [PSCustomObject]@{
                ComputerName     = $($e.TargetObject)
                Error            = $($e.FullyQualifiedErrorId)
                
            } | % {
                $selectProperties = $_ | Select-Object -Property ComputerName, EvaluationStatus, EvaluationTime, Error
                Write-Output $selectProperties
                $selectProperties | Export-csv $csvfile -NoTypeInformation -append 
            } 
        } 
    }

    Convert-CSVToExcel -csvFile $csvFile

    # Calculate the time it took to finish the script
    $endTime = (Get-Date)
    $ElapsedTime = ($endTime-$startTime).ToString('''Duration: ''mm'' min ''ss'' sec''')
    Write-Host $ElapsedTime

}



function Get-RemoteBitLockerStatus {
    ########## Creates a report of all machines' C: BitLocker Status by running a remote command to do so ##########
    Write-Verbose "This script will return a report of all $($regionLetters) machines' C: BitLocker Status by running a remote command to check their encryption status" -Verbose
    
    Write-Host "Do you wish to proceed?"
    $result = Read-YNKeyPrompt
    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Check-ImportExcelInstall
    
    Write-Host

    $startTime = (Get-Date)

    Get-AllCompsFromAD
    $Computers = Get-Content $allCompsFile
    
    New-Item -ItemType Directory -Force -Path $pathToReports | Out-Null
    $csvFile = "$pathToReports\Remote_BitLockerStatus.csv"


    # Flush DNS to clear records from cache 
    ipconfig /flushdns | Out-Null

    Write-Host "Retriving BitLocker Status from machines..."

    Invoke-Command -ComputerName $Computers -ThrottleLimit $ThrottleLimit -ErrorAction SilentlyContinue -ErrorVariable uhOh -ScriptBlock {

        $result = Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume | Where { $_.DriveLetter -eq 'C:'}
        
        return [PSCustomObject]@{
            PSComputerName = $($env:ComputerName)
            DriveLetter    = $result.DriveLetter
            IsVolumeInitializedForProtection = $result.IsVolumeInitializedForProtection
            ProtectionStatus = $result.ProtectionStatus
        } 
        
        if (-Not $result) {
            
            return [PSCustomObject]@{
                PSComputerName   = $($env:ComputerName)
                Error            = "C: does not have an associated BitLocker volume."
                
            }
        }

    } | % {
    
        $selectProperties = $_ | Select-Object -Property PSComputerName, DriveLetter, IsVolumeInitializedForProtection, @{Name="ProtectionStatus";Expression={if ($_.ProtectionStatus -eq 1){return "On"} elseif ($_.ProtectionStatus -eq 0) {return "Off"}}}, Error
        Write-Output $selectProperties
        # Select only the listed properties and exported it into csv file
        $selectProperties | Export-csv $csvfile -NoTypeInformation -append 

    }

    Write-Host "####################################### Compiling errors..."

    if ($uhOh) {
        Write-Host "Could not reach $($uhOh.count) machines"
        foreach ($e in $uhOh) {

            [PSCustomObject]@{
                PSComputerName     = $($e.TargetObject)
                Error            = $($e.FullyQualifiedErrorId)
                
            } | % {
                $selectProperties = $_ | Select-Object -Property PSComputerName, DriveLetter, IsVolumeInitializedForProtection, ProtectionStatus, Error 
                $_ | Select-Object -Property PSComputerName, Error | Write-Output
                # Select only the listed properties and exported it into csv file
                $selectProperties | Export-csv $csvfile -NoTypeInformation -append 
            }
        }
    }

    Convert-CSVToExcel -csvFile $csvFile

    # Calculate the time it took to finish the script
    $endTime = (Get-Date)
    $ElapsedTime = ($endTime-$startTime).ToString('''Duration: ''mm'' min ''ss'' sec''')
    Write-Host $ElapsedTime

}




function Get-SCCMSAPComparisonReport {
    # Creates a report that shows the dissimilarities between the laptops in SCCM and SAP

    Write-Verbose "This script will return a report of the dissimilarities between the laptops in SCCM and SAP. An xlsx file containing the SAP info is required." -Verbose
    
    Write-Host "See instructions to create SAP Excel report?"
    $result = Read-YNKeyPrompt
    if ($result) {
        $html = "
        <!DOCTYPE html>
        <html>
        <body>
        <style>
            * {
                font-family: calibri;
            }
            li {
                padding-top: .5em;
            }
            textarea {
                resize: none;
                overflow: hidden;
            }
            .buttonDiv{
                display:inline-block;
                position:relative;
            }

            button{
                position:absolute;
                bottom:0px;
                right:0px;
                height: 100%;
            }
            #flocbox {
                list-style: none;
            }
            textarea{
                display: block;
            }
            .setup {
                display: block;
            }
            .setupDone {
                display: none;
            }
            img {
                vertical-align: middle;
            }

        </style>
        <h2>Instructions to create SAP info Excel file</h2>

        <form>
            <label class='radio-inline'>
            <input type='radio' id='setupRadio' name='optradio' checked>First time setup
            </label>
            <label class='radio-inline'>
            <input type='radio' name='optradio'>I have the Variant and Layout setup already
            </label>
        </form>

        <ol>
            <li>Login to SAP and execute transaction <b>IH08</b></li>

            <div class='setupDone'>
            <li>Load Variant</li>
            <ol>
                <li>Click the <b>Get Variant</b> button
                    ( <img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB0AAAAYCAYAAAAGXva8AAAAAXNSR0IArs4c6QAAARFJREFUSEtj/Pnz538GOgJ2dnZGxlFLaRXixAfvr5MMf242M/y5v5sBVwJglKphYFWvZWDmxe/cwWTpS4YL27YxbN9+juEZAwODlJEng6eLMIPOB5r6FGTpEYanf6UYjHztGeTZGBgYfp5g+HmtgeHn3X0Mn7fzMLzbzsHwC0cosvsXMIgXFDDwK2JXgCN4Ry0d8ODVZdjrlMIwy8mO4TqOuJUR52Ko0eNlSBRnQlFBQZzSw1K4W+8xvO/tZXjWe4VhN819OgIthXn5N8Pm8x8YGs9/YzhLs4SEYfDIsRTZ6/8Z/v39y/D37z+c1R6yajz5FFHLEK7MpRiMPD0ZvLwMGMQJK2Ygvj4lwjBilYwsSwG35WYogGJZpAAAAABJRU5ErkJggg=='> )
                </li>
                <li>Enter <div class='buttonDiv'><input type='text' value='SAPCOMPAREINFO' id='variant' size='22' readonly><button onclick='myFunction(`"variant`")'>Copy</button></div> into Variant</li>
                <!-- <li>Click <b>Goto</b> tab > <b>Variants</b> > <b>Get...</b> > Enter <div class='buttonDiv'><input type='text' value='SAPCOMPAREINFO' id='variant' size='22' readonly><button onclick='myFunction(`"variant`")'>Copy</button></div> into Variant</li> -->
                <li>Click the <b>Execute</b> button or <b>F8</b></li>
            </ol>
            </div>

            <div class='setup'>
            <li>For <b>Technical Object</b>, paste in <div class='buttonDiv'><input type='text' value='E2005' id='techObj' size='10' readonly><button onclick='myFunction(`"techObj`")'>Copy</button></div></li>
            <li>For <b>Functional Location</b>, click the <b>Multiple selection</b> button 
                ( <img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB0AAAAXCAYAAAD3CERpAAAAAXNSR0IArs4c6QAAAj5JREFUSEu9lU1rE1EUhp97J23pR7BNiOmYtIE0RSwh6Qeu1OpSd64E8a+47d8QFy7cuy9ScFVNGxqLJCFQbdU0TigGTIWZe2VioJZMM5lqvMvL4Tzzvvc9c8Snoy+6Xq+j0RhCYEiBozSO1rjnX90pDfF4nLmEKcTbwq5ufjvuXAzzuMJcRj6fF2K7sKNDArLZ7DCZlEolNILVlWUhCju7WiuHpaWloUL39/dRQnJzdUWIYrGobdv+v9DLKW2jWxW0M44ILyIMf5NcpUIav+1131RqFVBpE3X4DOd4D3HlPjK6jggn+sJdaCgUOguSL7S9i7K2UD++dyWdok+20NY22lhATN/pgPvBzykdxF5tPccpb+BYhxf7OHELmXqKkbyHHOstCx6kfkodYCKLvPoIaT5ETnu/8Tmol9Kv1SrVSoXWHx88Fk2RyWSYj4wCTdTBBnb5BYyvI5NPkPF15HjkQid8g1TcLFKp1QinppDdNqORORbSaZIzXejhS5R1gDAfI6PLvgn2DVLxTQMdCrF212SkC9XKxp1nR7kX7sgcAe7IJPznBfANkidUK5RSdPcA4ND6bHGqYHI2gqu/3/ENkhe0t+FPPr7eo2EbXLt9g5kgUK8gDQZtU3v1jiN7hPkHefx2lH+QPN60V0hwaN8/0tCVetrrMTK9Sm1Oyi0m09dZG9DevqvN6+fgnZMw5mKGTGaWqb8N0kCDF7CoJ0jWcZ1YLBawTbDyRqOBaZpnq+3D+1KwDpeszuVyHegveWSsJxud/u4AAAAASUVORK5CYII='> )
            </li>
            <li>Under the <b>Single value</b> column, paste in the following:
            <ul id='flocbox'>
                <li>
                <div class='buttonDiv'>
                <textarea cols='17' rows='2' id='floc' readonly>07-BLDG-BC*&#13;&#10;07-BLDG-YT*</textarea>
                <button onclick='myFunction(`"floc`")'>Copy</button>
                </li>
                </div>
                </ul>
            </li>
            </div>
            <div class='setup'>
            <li>Click the <b>Copy</b> button
                ( <img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB4AAAAWCAYAAADXYyzPAAAAAXNSR0IArs4c6QAAAgBJREFUSEvNljFoGlEcxn83diwd0hyky0GmIohgIRA6xSPN0sGlUcTo0KEEtx44dAhFuG4ldOiglUPbxSGLDV66ZCkoiPTm3hSwfUPoUih0sdypl0Q9fFawvfXe+/++77vvPU4ZDAYD/sGjeOB6vc6q+IqikEql8MG1Wo10Or0S32NWAE4mkysBNxoN3+QCYIFjtzjtden3xxpVVHWd3axOZG1NSvhiYGFjlpoQy5PVI1wxBMJpUS136at7FI0E8/DyYB/aI1o0SIROFdhmiSbz4ZJgB6tQhvxrMpGbSQrBNefeuyG8Fy1ihCtECixsk1IvOh2hl0IVspPROhZDnRkmdAaqpcC2WeD77rRbwsCea+sLd/UEkZDPIgW2CoWZMYeD5xf778Gjhgcnymep7BUNtJ8mua/bVPQttBANUmAv6pllmRW1a3Lr4xmww8mhgb4MeHa5LnBd0LSNq9E/PvCwVqaDxqv0Ww5vh0cu5Rimj5Pbecr9tkt882gU6WeeHb+gAuQefeJNWMYjLZJgwD8i34jls2T8ql5w/P6A55fAnR1ynFG5hPiDd5zHr6WwTNTjvcK2qDa7oMZG9/JvWp2XPG67wyWbR/zSt+ZXGuQukBuThIPdOqXZXQ8uCNc1ybXvUdl/EtriSTXyUUv5kF/0/4DlNS+/MvgRWH7U4hP+APdgdc4DCgfxAAAAAElFTkSuQmCC'> )
                or <b>F8</b></li>
            </div>
            <div class='setup'>
            <li>Create a Variant so you dont have to do steps 2-5 in the future:
                <ol>
                    <li>Click <b>Goto</b> tab > <b>Variants</b> > <b>Save as Variant</b></li>
                    <li>Enter <div class='buttonDiv'><input type='text' value='SAPCOMPAREINFO' id='variant' size='22' readonly><button onclick='myFunction(`"variant`")'>Copy</button></div> for the Variant name and description</li>
                    <li>Click the <b>Save</b> button or <b>Ctrl + S</b></li>
                </ol>
            </li>
            </div>

            <li>Run the report by clicking the <b>Execute</b> button or <b>F8</b></li>

            <div class='setupDone'>
            <li>Load Layout</li>
            <ol>
                <li>Click <b>Settings</b> tab > <b>Layouts</b> > <b>Get...</b> > Click <b>SAPCOMPAREINFO</b>
            </ol>

            </div>

            <div class='setup'>
            <li>Change the layout by clicking the <b>Current...</b> button 
                ( <img src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAB0AAAAYCAYAAAAGXva8AAAAAXNSR0IArs4c6QAAARFJREFUSEtj/Pnz538GOgJ2dnZGxlFLaRXixAfvr5MMf242M/y5v5sBVwJglKphYFWvZWDmxe/cwWTpS4YL27YxbN9+juEZAwODlJEng6eLMIPOB5r6FGTpEYanf6UYjHztGeTZGBgYfp5g+HmtgeHn3X0Mn7fzMLzbzsHwC0cosvsXMIgXFDDwK2JXgCN4Ry0d8ODVZdjrlMIwy8mO4TqOuJUR52Ko0eNlSBRnQlFBQZzSw1K4W+8xvO/tZXjWe4VhN819OgIthXn5N8Pm8x8YGs9/YzhLs4SEYfDIsRTZ6/8Z/v39y/D37z+c1R6yajz5FFHLEK7MpRiMPD0ZvLwMGMQJK2Ygvj4lwjBilYwsSwG35WYogGJZpAAAAABJRU5ErkJggg=='> )
                or <b>Ctrl + F8</b></li>
            <li>Move the following values from <b>Column Set</b> to <b>Displayed Columns</b>: 
                <ul>
                    <li>Selected Line</li>
                    <li>Technical identification no.</li>
                    <li>Description of Technical Object</li>
                    <li>Sort field</li>
                    <li>Custodian</li>
                    <li>ManufactSerialNumber.</li>
                </ul>
            </li>
            <li>Save the layout
            
            <ol>
                <li>Press the <b>Save</b> button</li>
                <li>Enter <div class='buttonDiv'><input type='text' value='SAPCOMPAREINFO' id='variant' size='22' readonly><button onclick='myFunction(`"variant`")'>Copy</button></div> for <b>Save Layout</b> and <b>Name</b></li>
                <li>Press the <b>Continue</b> button or <b>Enter</b></li>
            </ol>
            
            
            </li>
            
            <li>Click the <b>Transfer</b> button or <b>Enter</b></li>
            </div>
            <li>Click the <b>Spreadsheet</b> button or <b>Shift + F4</b></li>
            <li>Change <b>No. of key columns</b> to <b>5</b> and click the <b>Continue</b> button</li>
            <li>Select the <b>Table</b> radio button and click the <b>Continue</b> button twice</li>
            <li>Save the generated Excel spreadsheet as <b>SAPReport.xlsx</b> to your Desktop</li>
            <li>Close the Excel file</li>
            <li>Return to the script and press Y to proceed</li>
        </ol>
        <script>
        function myFunction(elemId) {
            var copyText = document.getElementById(elemId);
            copyText.select();
            navigator.clipboard.writeText(copyText.value);
        }

        const setupListElems = document.getElementsByClassName('setup');
        const setupDoneListElems = document.getElementsByClassName('setupDone');

        function handleRadioClick() {
            if (document.getElementById('setupRadio').checked) {
                for (elem of setupListElems) {
                    elem.style.display = 'block';
                }
                for (elem of setupDoneListElems) {
                    elem.style.display = 'none';
                }
            } else {
                for (elem of setupListElems) {
                    elem.style.display = 'none';
                }
                for (elem of setupDoneListElems) {
                    elem.style.display = 'block';
                }
            }
        }

        const radioButtons = document.querySelectorAll('input[name=`"optradio`"]');
        radioButtons.forEach(radio => {
            radio.addEventListener('click', handleRadioClick);
        });


        </script>
        </body>
        </html>

        " 

        $html | render-html
    }

    Write-Host
    Write-Host "Do you wish to proceed?"
    $result = Read-YNKeyPrompt
    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Check-ImportExcelInstall
    
    Write-Host


    Write-Host "Select the xlsx file containing the SAP info"
    Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
    $currentUser = (Get-CIMInstance -class Win32_ComputerSystem).username.split("\")[1]
    $FileBrowser.InitialDirectory = "C:\Users\$($currentUser)\Desktop"
    $FileBrowser.Filter = 'SpreadSheet (*.xlsx)|*.xlsx'
    $null = $FileBrowser.ShowDialog()
    $xlFile = $FileBrowser.FileName


    if ( $xlFile -eq "" ) {
        Write-Host "No file selected." -ForegroundColor "Red"
        return
    }

    Write-Host
    $xlsx = Open-ExcelPackage -Path $xlFile


    $data = Import-Excel -Path $xlFile -Sheet "Sheet1"
    $foundHeaders = $data | Get-Member -MemberType NoteProperty | %{ "$($_.Name)" }
    $requiredHeaders = @("Custodian", "Description", "ManufSerialNo.", "Sort field", "TechIdentNo.")

    foreach ($header in $requiredHeaders) {
        if ($header -notin $foundHeaders) {
            Write-Host "SAP Info was not setup properly - $header column was not found."
            return
        }
    }



    Write-Host "Formatting SAP info worksheet..."
    # convert sap info into table and rename sheet
    $paramsSAP = @{
        ExcelPackage  = $xlsx
        AutoSize      = $true
        TableName     = 'SAPInfoTable'
        TableStyle    = 'Medium2'
        WorksheetName = 'Sheet1'
        PassThru      = $true
    }
    $null = Export-Excel @paramsSAP
    $ws = $xlsx.Workbook.Worksheets[$paramsSAP.WorksheetName]
    $ws.Name = "SAP Info"



    Write-Host "Retrieving SCCM info..."

    $query = "
        SELECT 
            SMS_CombinedDeviceResources.Name, 
            SMS_CombinedDeviceResources.PrimaryUser, 
            SMS_CombinedDeviceResources.CurrentLogonUser,
            SMS_G_System_PC_BIOS.SerialNumber
        FROM SMS_CombinedDeviceResources
        JOIN SMS_G_System_PC_BIOS on SMS_CombinedDeviceResources.ResourceID = SMS_G_System_PC_BIOS.ResourceID
        WHERE SMS_CombinedDeviceResources.Name LIKE ""W$($regionLetters)%"" AND SMS_CombinedDeviceResources.Name NOT LIKE '%VM%'
    "


    $compObj = Query-SCCMWmiObject -Query $query



    $null = Add-Worksheet -ExcelPackage $xlsx -WorkSheetname "SCCM Info"
    $paramsSCCM = @{
        ExcelPackage  = $xlsx
        AutoSize      = $true
        TableName     = 'SCCMInfoTable'
        TableStyle    = 'Medium9'
        WorksheetName = 'SCCM Info'
        PassThru      = $true
        Append        = $true
    }

    Write-Host "Formatting and appending SCCM info to worksheet..."
    foreach ($o in $compObj ) {

        $null = [pscustomobject]@{
            "Computer Name" = $o.SMS_CombinedDeviceResources.Name
            "Serial Number" = $o.SMS_G_System_PC_BIOS.SerialNumber
            "Primary" = $o.SMS_CombinedDeviceResources.PrimaryUser
            "Current User" = $o.SMS_CombinedDeviceResources.CurrentLogonUser
            "Primary User LastnameF" = if ($o.SMS_CombinedDeviceResources.PrimaryUser) {
                    if ($o.SMS_CombinedDeviceResources.PrimaryUser.Contains(",")) {
                        $users = $o.SMS_CombinedDeviceResources.PrimaryUser.split(",")
                        $primaryUsers = foreach ($user in $users) {
                            $user.split("\")[1]
                        }
                        $primaryUsers -join ","
                    } else {
                        $o.SMS_CombinedDeviceResources.PrimaryUser.split("\")[1]
                    }
                } else {$null}
            "Current User LastnameF" = if ($o.SMS_CombinedDeviceResources.CurrentLogonUser) { $o.SMS_CombinedDeviceResources.CurrentLogonUser.split("\")[1] } else {$null}
            "Prefix Removed" = $o.SMS_CombinedDeviceResources.Name.Substring(4)
        } | Export-Excel @paramsSCCM
    }

    Close-ExcelPackage $xlsx



    $sapInfo = Import-Excel -Path $xlFile -Sheet "SAP Info"
    $sccmInfo = Import-Excel -Path $xlFile -Sheet "SCCM Info"

    $combined = Join-Object -Left $sccmInfo -Right $sapInfo -LeftJoinProperty "Prefix Removed" -RightJoinProperty "TechIdentNo." -Type OnlyIfInBoth


    $errMsg1 = "Custodian may be set to their manager"
    $errMsg2 = "Custodian != Primary"
    $errMsg3 = "Custodian != Current User"
    $errMsg4 = "Serial number mismatch"
    $errMsg5 = "Primary != Current User"

    Write-Host "Comparing SAP with SCCM info..."
    $data = foreach ($c in $combined) {

        # Format Custodian name
        if ($c.Custodian -match ", ") {
            $nameSplit = $c.Custodian.replace(" ", "").replace("-", "").replace("`'", "").split(",")
            if ($nameSplit[0] -like "ITDESKSIDE*") {
                $custodianLastnameF = "ITDESKSIDESUPPORT"
            } else {
                $custodianLastnameF = $nameSplit[0] + $nameSplit[1].Substring(0,1)
            }
        } else {
            $custodianLastnameF = $c.Custodian
        }

        # Format Sort Field name
        if ($c."Sort field") {
            $sortField = $c."Sort field"
            # Program Bought
            if ($sortField -match "program" -AND $sortField -match "bought") {
                $sortFieldLastnameF = "PROGRAM BOUGHT"
            }

            # Written as Lastname, Firstname
            elseif ($sortField -match "[a-zA-Z]+, [a-zA-Z]+") {
                $nameSplit = $sortField.replace(" ", "").replace("-", "").split(",")
                $sortFieldLastnameF = $nameSplit[0] + $nameSplit[1].Substring(0,1)
            }

            # Written as Firstname Lastname
            elseif ($sortField -match "[a-zA-Z]+ [a-zA-Z]+") {
                $nameSplit = $sortField.replace("-", "").split(" ")
                # name has 2 words
                if ($nameSplit.Length -eq 2) {
                    $sortFieldLastnameF = $nameSplit[1] + $nameSplit[0].Substring(0,1)

                # name has 3 words (kinda messed because there isnt a convention so will just use the first word and last word)
                } elseif ($nameSplit.Length -eq 3) {
                    $sortFieldLastnameF = $nameSplit[2] + $nameSplit[0].Substring(0,1)
                }
            }

            # Written as Firstname.Lastname
            elseif ($sortField -match "[a-zA-Z]+\.[a-zA-Z]+") {
                $nameSplit = $sortField.replace(" ", "").replace("-", "").split(".")
                $sortFieldLastnameF = $nameSplit[1] + $nameSplit[0].Substring(0,1)
            }

            else {
                $sortFieldLastnameF = $sortField
            }

        } else {
            $sortFieldLastnameF = $null
        }


        
        $errorMessage = ""

        if ($c.'Primary User LastnameF') { # need to check if Primary exists first or it also includes empty users with -like operator
            $users = $c.'Primary User LastnameF'.split(",")
            foreach ($u in $users) {
                # if comp is a shared comp and primary has multiple users, break when custodian = primary
                # OR SSC has cusodian as SSC and name in sort field
                if ($u -like "$($custodianLastnameF)*" -OR ($custodianLastnameF -like "SSCEMPLOYEE*" -AND $u -like "$($sortFieldLastnameF)*")) {
                    $errorMessage = ""
                    break
                }

                # Custodian =/= Primary but Sort field = Primary or current
                if ($sortFieldLastnameF) {
                    if ($u -like "$($sortFieldLastnameF)*" -AND $u -notlike "$($custodianLastnameF)*") {
                        $errorMessage = $errMsg1
                    } 
                    else {
                        $errorMessage = $errMsg2 + " && Primary != Sort field"
                    }
                }

                # Custodian =/= Primary
                elseif ($u -notlike "$($custodianLastnameF)*") {
                    $errorMessage = $errMsg2
                }


                # Primary user =/= Current user
                if ($c."Current User LastnameF" -AND $u -ne $c."Current User LastnameF") {
                    if ($errorMessage) {
                        $errorMessage = $errorMessage + " && " + $errMsg5
                    } else {
                        $errorMessage = $errMsg5
                    }
                }

            }
        }

        # Custodian =/= Current user and no Primary
        elseif ($c.'Current User LastnameF' -AND !$c.'Primary User LastnameF') {
            if ($sortFieldLastnameF) {
                if ($c.'Current User LastnameF' -like "$($sortFieldLastnameF)*" -AND $c.'Current User LastnameF' -notlike "$($custodianLastnameF)*") {
                    $errorMessage = $errMsg1
                }
            }
            # Custodian =/= Current user
            elseif ($c.'Current User LastnameF' -notlike "$($custodianLastnameF)*" ) {
                $errorMessage = $errMsg3
            }

        }



        # SAP serial number =/= SCCM serial number
        # some but not all lenovo laptops have an S added in front in SAP/SCCM for some fucking reason
        if ($c."Serial Number" -notlike "*$($c.'ManufSerialNo.')" -AND $c.'ManufSerialNo.' -notlike "*$($c.'Serial Number')") { 
            if ($errorMessage) {
                $errorMessage = $errorMessage + " && " + $errMsg4
            } else {
                $errorMessage = $errMsg4
            }
        }
        

        
        [pscustomobject]@{
            "Alignment" = $c."TechIdentNo."
            "SAP Custodian" = $custodianLastnameF
            "SAP Sort field" = $sortFieldLastnameF
            "SCCM Primary User" = $c."Primary User LastnameF"
            "SCCM Current User" = $c."Current User LastnameF"
            "SAP SN" = $c."ManufSerialNo."
            "SCCM SN" = $c."Serial Number"
            "Error Message" = $errorMessage

        }

    }


    Write-Host "Generating Results worksheet...."
    Add-Type -Assembly System.Drawing
    $excelNeutralBG = [System.Drawing.Color]::FromArgb(255,235,156)
    $excelNeutralFont = [System.Drawing.Color]::FromArgb(156,101,0)
    $errRange = "H:H"
    $ConditionalFormat = $(
        New-ConditionalText -Text $errMsg1 -Range $errRange -BackgroundColor $excelNeutralBG -ConditionalTextColor $excelNeutralFont
        New-ConditionalText -Text $errMsg2 -Range $errRange -BackgroundColor "Pink" -ConditionalTextColor "DarkRed"
        New-ConditionalText -Text $errMsg3 -Range $errRange -BackgroundColor "PaleVioletRed" -ConditionalTextColor "Black"
        New-ConditionalText -Text $errMsg4 -Range $errRange -BackgroundColor "None" -ConditionalTextColor "Red"
        New-ConditionalText -Text $errMsg5 -Range $errRange -BackgroundColor "Sienna" -ConditionalTextColor "DarkRed"
    )

    $params = @{
        AutoSize      = $true
        TableName     = 'ResultsTable'
        TableStyle    = 'Medium2'
        WorksheetName = 'Results'
        Path          = $xlFile
        # Show          = $true
        ConditionalFormat  = $ConditionalFormat
    }

    $excel = $data | Sort-Object -Property "Error Message" -Descending | Export-Excel @params



    $dateNow = get-date -f "yyyy-MM-dd@hhmm"
    $newName = "SCCMSAPReport$($dateNow).xlsx"
    $xlFileDir = Split-Path $xlFile -Parent

    Rename-Item $xlFile $newName
    Start-Sleep 1
    Write-Host
    Write-Host "Done! Saved to $($xlFileDir)\$($newName)" -ForegroundColor "Green"
    # open the file this way instead of Show parameter so that it will open as current user instead of admin user
    explorer "$($xlFileDir)\$($newName)"


}




function Get-MonitorsInfo {
    # Generates a report of the manufacturer, model, and serial number of all monitors that are currently connected to the machine
    Write-Verbose "This script will return a report of all $($regionLetters) machines' currently connected monitors' info (manufacturer, model, serial number) by running a remote command" -Verbose
    
    Write-Host "Do you wish to proceed?"
    $result = Read-YNKeyPrompt
    if (!$result){
        Write-Host "Action cancelled." -ForegroundColor "red"
        return
    }

    Check-ImportExcelInstall
    
    Write-Host

    $startTime = (Get-Date)

    Get-AllCompsFromAD
    $Computers = Get-Content $allCompsFile
        

    $dateNow = get-date -f "yyyy-MM-dd@HHmm"
    New-Item -ItemType Directory -Force -Path $pathToReports | Out-Null
    $xlFile = "$($pathToReports)\MonitorsSN$dateNow.xlsx"

    $params = @{
        # ExcelPackage  = $xlsx
        AutoSize      = $true
        TableName     = 'MonitorSNsTable'
        TableStyle    = 'Medium9'
        WorksheetName = 'Serial Numbers'
        # PassThru      = $true
        Append        = $true
        Path          = $xlFile
    }


    # Flush DNS to clear records from cache 
    ipconfig /flushdns | Out-Null

    Write-Host "Retriving monitors' serial number from machines. This may take a moment"

    Invoke-Command -ComputerName $Computers -ThrottleLimit $ThrottleLimit -ArgumentList $ManufacturerHash -ErrorAction SilentlyContinue -ScriptBlock {
        param ($ManufacturerHash)

        Get-CimInstance -ClassName WmiMonitorID -Namespace root\wmi | Foreach-Object {
            # if ($null -ne $_) {
                $manufCode = -join [char[]] ($_.Manufacturername -ne 0)
                $monitorInfo = [PSCustomObject]@{
                    ComputerName          = $env:ComputerName
                    # Active                = $_.Active
                    # Manufacturer          = ($_.Manufacturername | ForEach-Object { [char]$_ }) -join ""
                    Manufacturer          = $ManufacturerHash.$manufCode
                    Model                 = ($_.UserFriendlyName | ForEach-Object { [char]$_ }) -join ""
                    'Serial Number'       = ($_.SerialNumberID | ForEach-Object { [char]$_ }) -join ""
                    # 'Year Of Manufacture' = $_.YearOfManufacture
                    # 'Week Of Manufacture' = $_.WeekOfManufacture
                }

                # $monitorInfo | Out-Default
                return $monitorInfo
            # }
        }


    } | Select ComputerName, Manufacturer, Model, "Serial Number" | Sort ComputerName | Export-Excel @params



    # Calculate the time it took to finish the script
    $endTime = (Get-Date)
    $ElapsedTime = ($endTime-$startTime).ToString('''Duration: ''mm'' min ''ss'' sec''')
    Write-Host $ElapsedTime

    Write-Host "Report saved to $($xlFile)" -ForegroundColor "Green"
    explorer $xlFile


}






















# -----------------------------------------------------------------------------------------------------
# Menus
# -----------------------------------------------------------------------------------------------------



function ReadKey {
    param ($menuPage, $compName, $compStatus)


    $validInputs = Switch ($menuPage) {
        "main"    { @("u","1","2","3","4","5","6","7","8","9","0","-","=","v","b") }
        "ADUser"  { @("1","2","3","4") }
        "comp"    { if ($compStatus) { @("r","1","2","3","4","5","6","7","8","9","0","-","=","d","f","l") } 
                    else             { @("r","1","2") } }
        "reports" { @("1","2","3","4","5","6","7","8") }
    }

    do {

        $KeyPress = $Host.UI.RawUI.ReadKey('NoEcho, IncludeKeyDown');

        $K = $KeyPress.Character

        $VKC = $KeyPress.VirtualKeyCode

        # 27 = ESC
        $validVKCInputs = @("27")

    } until (($K -in $validInputs) -or ($VKC -in $validVKCInputs))

    #Jumps down to the corresponding menu actions function to take the keypress

    Switch ($menuPage) {
        "main"    {MenuActions}
        "ADUser"  {ADUserSubMenuActions}
        "comp"    { if ($compStatus) { RemoteCompSubMenuActions -compName $compName } else { RemoteCompSubMenuActionsOffline -compName $compName } }
        "reports" {ReportsSubMenuActions}
    }

}






$reportMenuItem1 = "Machine Data"
$reportMenuItem2 = "Machines Active Monitor Info"

$reportMenuItem3 = "Machines with Specified Software Installed"
$reportMenuItem4 = "Machines without Specified Software Installed"

$reportMenuItem5 = "Client Status Check"

$reportMenuItem6 = "SCCM Health Check"
$reportMenuItem7 = "BitLocker Status"
$reportMenuItem8 = "SCCM and SAP Comparison Report"

$reportmenuItemESC = "Return"


function ReportsSubMenu {
    Clear-Host
    Display-Title -title "Generate Reports for All $($regionLetters) Machines";

    Write-Host "[1] " -ForegroundColor $accentColour -NoNewLine; Write-Host $reportMenuItem1
    Write-Host "[2] " -ForegroundColor $accentColour -NoNewLine; Write-Host $reportMenuItem2
    Write-Host
    Write-Host "[3] " -ForegroundColor $accentColour -NoNewLine; Write-Host $reportMenuItem3
    Write-Host "[4] " -ForegroundColor $accentColour -NoNewLine; Write-Host $reportMenuItem4
    Write-Host
    Write-Host "[5] " -ForegroundColor $accentColour -NoNewLine; Write-Host $reportMenuItem5
    Write-Host
    Write-Host "[6] " -ForegroundColor $accentColour -NoNewLine; Write-Host $reportMenuItem6
    Write-Host "[7] " -ForegroundColor $accentColour -NoNewLine; Write-Host $reportMenuItem7
    Write-Host
    Write-Host "[8] " -ForegroundColor $accentColour -NoNewLine; Write-Host $reportMenuItem8

    Write-Host
    Write-Host "[ESC] " -ForegroundColor $accentColour -NoNewLine; Write-Host $reportmenuItemESC -NoNewLine

    ReadKey -menuPage "reports"

}


function ReportsSubMenuActions {
    Clear-Host
    
    Switch ($K) {
        1 {Display-Title -title $reportMenuItem1;SCCM-GetMachineData;Read-HostESCKey;ReportsSubMenu}
        2 {Display-Title -title $reportMenuItem2;Get-MonitorsInfo;Read-HostESCKey;ReportsSubMenu}

        3 {Display-Title -title $reportMenuItem3;SCCM-GetAllCompsWithInstalledSoftware;Read-HostESCKey;ReportsSubMenu}
        4 {Display-Title -title $reportMenuItem4;SCCM-GetAllCompsWithoutInstalledSoftware;Read-HostESCKey;ReportsSubMenu}
        5 {Display-Title -title $reportMenuItem5;SCCM-GetClientCheckDetail;Read-HostESCKey;ReportsSubMenu}
        6 {Display-Title -title $reportMenuItem6;Get-RemoteSCCMHealthStatus;Read-HostESCKey;ReportsSubMenu}
        7 {Display-Title -title $reportMenuItem7;Get-RemoteBitLockerStatus;Read-HostESCKey;ReportsSubMenu}
        8 {Display-Title -title $reportMenuItem8;Get-SCCMSAPComparisonReport;Read-HostESCKey;ReportsSubMenu}
        

        # Q {return}
    }

    Switch ($VKC) {
        27 {return}
    }

}



$ADUserMenuItem1 = "User Information"
$ADUserMenuItem2 = "Group Memberships"

$ADUserMenuItem3 = "Reset Password"
$ADUserMenuItem4 = "Unlock Account"

$ADUserMenuItemESC = "Return"


function ADUserSubMenu {

    Clear-Host
    Display-Title -title $menuItem3


    if (!$global:ADUserObjectGlobal) {
        # $name = Read-Host "Enter LastnameF or Firstname Lastname or UPN (eg. KwanH or Hugo Kwan or Hugo.Kwan@ec.gc.ca)"
        Write-Host "Enter one of the following formats:"
        Write-Host " - LastnameF  (eg. KwanH)"
        Write-Host " - Full name  (eg. Hugo Kwan)"
        Write-Host " - UPN/Email  (eg. Hugo.Kwan@ec.gc.ca)"
        Write-Host

        do {
            # Write-Host ">> " -NoNewLine
            # $name = $Host.UI.ReadLine()
            $name = Read-HostCustom

            if ($name -eq "") {
                Write-Host "Action cancelled." -ForegroundColor "red"
                Read-HostESCKey
                return
            }

            $name = $name.trim()
            $ADUserObject = Get-ADUserObject -name $name

            if ($ADUserObject -eq $null) {
                Write-Host "Could not find user profile in AD." -ForegroundColor "Red"
                Write-Host
                continue
            } 

            if ($ADUserObject.count -gt 1) {
                Write-Host "More than 1 user found with the same name. Use the specific LastnameF or UPN to refer to the correct user." -ForegroundColor "Yellow"
                Write-Host
                continue
            }

            $global:ADUserObjectGlobal = $ADUserObject
            break

        } while ($name -ne "")
        
    }


    $DistinguishedName = ($global:ADUserObjectGlobal).DistinguishedName
    $SamAccountName = ($global:ADUserObjectGlobal).SamAccountName
    $DisplayName = ($global:ADUserObjectGlobal).DisplayName
    $FirstName = ($global:ADUserObjectGlobal).GivenName
    $Surname = ($global:ADUserObjectGlobal).Surname
    $UPN = ($global:ADUserObjectGlobal).UserPrincipalName
    $LockedOut = ($global:ADUserObjectGlobal).LockedOut
    $regionDomain = ($global:ADUserObjectGlobal).CanonicalName.split("/")[0]

    Clear-Host
    Display-Title -title "$($menuItem3): $DisplayName";
    Write-Host "SamAccName : $SamAccountName"
    Write-Host "Full Name  : $FirstName $Surname"
    Write-Host "Email/UPN  : $UPN"
    Write-Host "Region     : $regionDomain"
    # Write-Host "Locked Out : $LockedOut"
    Write-Host

    Write-Host "[1] " -ForegroundColor $accentColour -NoNewLine; Write-Host $ADUserMenuItem1
    Write-Host "[2] " -ForegroundColor $accentColour -NoNewLine; Write-Host $ADUserMenuItem2
    Write-Host
    Write-Host "[3] " -ForegroundColor $accentColour -NoNewLine; Write-Host $ADUserMenuItem3
    Write-Host "[4] " -ForegroundColor $accentColour -NoNewLine; Write-Host $ADUserMenuItem4

    Write-Host
    Write-Host "[ESC] " -ForegroundColor $accentColour -NoNewLine; Write-Host $ADUserMenuItemESC -NoNewLine

    ReadKey -menuPage "ADUser"

}


function ADUserSubMenuActions {
    Clear-Host
    
    Switch ($K) {
        1 {Display-Title -title $ADUserMenuItem1;Get-ADUserInfo -DistinguishedName $DistinguishedName;Read-HostESCKey;ADUserSubMenu}
        2 {Display-Title -title $ADUserMenuItem2;Get-ADUserGroupInfo -DistinguishedName $DistinguishedName -regionDomain $regionDomain;Read-HostESCKey;ADUserSubMenu}

        3 {Display-Title -title $ADUserMenuItem3;Reset-ADUserPassword -DistinguishedName $DistinguishedName -regionDomain $regionDomain;Read-HostESCKey;ADUserSubMenu}
        4 {Display-Title -title $ADUserMenuItem4;Unlock-ADUserAccount -DistinguishedName $DistinguishedName -regionDomain $regionDomain;Read-HostESCKey;ADUserSubMenu}

    }

    Switch ($VKC) {
        27 {$global:ADUserObjectGlobal=$null;return}
    }

}








$compMenuItem1 = "System Info"
$compMenuItem2 = "Installed Programs"

$compMenuItem3 = "c$"
$compMenuItem4 = "Transfer File"

$compMenuItem5 = "Map Network Drive"
$compMenuItem6 = "Map Network Printer"

$compMenuItem7 = "GPUpdate"
$compMenuItem8 = "McAfee Agent Actions"
$compMenuItem9 = "Configuration Manager Actions"

$compMenuItem0 = "Clear CCM Cache"
$compMenuItem11 = "Clear MSTeams Cache"

$compMenuItem12 = "Remote Control Viewer"

$compMenuItemD = "Deploy DisplayLink"
$compMenuItemF = "Deploy McAfee FRP"

$compMenuItemL = "Lock Workstation"

$compMenuItemESC = "Return"




function RemoteCompSubMenu {

    Clear-Host

    Write-Host "================" -NoNewLine -ForegroundColor $accentColour; Write-Host " Remote Machine Menu " -NoNewLine; Write-Host "================" -ForegroundColor $accentColour;
    Write-Host

    if (!$global:remoteCompName) {
        $validChars = "^[a-zA-Z0-9\-]{1,15}$" # Valid computer name is any letter or number, max 15 chars
        # $compName = Read-Host "Computer name  "
        $compName = Read-HostCustom -prompt "Computer name  : "
        $compName = $compName.trim()
        if ($compName -eq "") {
            Write-Host "Action cancelled. No input given" -ForegroundColor "red"
            Read-HostESCKey
            return
        } elseif ($compName -notmatch $validChars){
            Write-Host "Invalid computer name entered" -ForegroundColor "red"  
            Read-HostESCKey       
            return
        }
        $global:remoteCompName = $compName
    } else {
        Write-Host "Computer name  : $global:remoteCompName"
    }

    
    # # check if computer exists in SCCM
    # $exists = Check-CompExistence -compName $global:remoteCompName
    # if (!$exists){
    #     Write-Host "$global:remoteCompName does not exist in SCCM" -ForegroundColor "red"
    #     return
    # }

    ipconfig /flushdns | Out-Null

    # Runs Data Discovery Collection Cycle so remote comp sends SCCM to update its client info / online status
    # runs in new hidden powershell console so it doesnt hold up the current console
    Start-Process powershell -NoNewWindow "Invoke-WMIMethod -ComputerName $global:remoteCompName -Namespace root\ccm -Class SMS_CLient -Name TriggerSchedule '{00000000-0000-0000-0000-000000000003}' -ErrorAction SilentlyContinue | Out-Null" -ErrorAction SilentlyContinue


    $isOnline = Check-OnlineStatusSCCM -compName $global:remoteCompName
    if ($isOnline -eq $null){
        Write-Host "$global:remoteCompName does not exist in SCCM" -ForegroundColor "red"
        Read-HostESCKey
        $global:remoteCompName=$null
        return
    }

    # check if WinRM port is open for powershell remoting
    $winRMStatus = Test-TCPPort -address $global:remoteCompName -port $WinRMPort

    if ($isOnline -and $winRMStatus) {
        $optionsColour = $accentColour
        $statusMsg = "Online" 
        $statusColour = "Green"

        try {
            $networkObj = (Get-CimInstance -class win32_networkadapterconfiguration -filter "ipenabled = 'true'" -ComputerName $global:remoteCompName -ErrorAction SilentlyContinue | where {$_.dnsdomain -like '*.ec.gc.ca'})
        
            $ip = $networkObj.IPAddress[0]
            # check if comp is connected via vpn
            if ($networkObj.ServiceName -eq "vpnva") {
                $ip += " (VPN)"
            }
        } catch { $ip = "N/A"}
        # Gets current user 
        $domainAndUsername = (Get-CimInstance -Class win32_computersystem -ComputerName $global:remoteCompName -ErrorAction SilentlyContinue).UserName
        
        if ($domainAndUsername) {
            $username = $domainAndUsername.Split("\")[1]

            # $atLogonScreen = Invoke-Command -ComputerName $global:remoteCompName -ScriptBlock {Get-Process logonui -ErrorAction SilentlyContinue} 
            $atLogonScreen = Invoke-Command -ComputerName $global:remoteCompName -ScriptBlock {[System.Diagnostics.Process]::GetProcessesByName("logonui")} -ErrorAction SilentlyContinue 

            if ($atLogonScreen) {
                $domainAndUsername = $domainAndUsername + " @ Lock Screen"
            }
        } else {
            $domainAndUsername = "N/A"
        }
        

    } else {
        $optionsColour = "DarkGray"

        if ($isOnline) {
            # Online in SCCM, but cannot WinRM 
        # if ($pingStatus) {
            # pingable but cannot WinRM
            $statusMsg = "Unknown"
            $statusColour = "Yellow"

        } else {
            $statusMsg = "Offline"
            $statusColour = "Red"
        }

        $ip = "N/A"
        $domainAndUsername = "N/A"

        # $query = "
        #     SELECT SMS_R_System.LastLogonUserDomain, SMS_R_System.LastLogonUserName
        #     FROM SMS_R_System
        #     WHERE SMS_R_System.Name = ""$global:remoteCompName""
        # "

        # $obj = Query-SCCMWmiObject -Query $query

        # $domainAndUsername = "$($obj.LastLogonUserDomain)/$($obj.LastLogonUserName)"
    }

    Write-Host "Machine status : " -NoNewLine; Write-Host $statusMsg -ForegroundColor $statusColour
    Write-Host "Assigned IPv4  : $ip"
    Write-Host "Logged on user : $domainAndUsername"


    Write-Host
    Write-Host "[1] " -ForegroundColor $accentColour -NoNewLine; Write-Host $compMenuItem1
    Write-Host "[2] " -ForegroundColor $accentColour -NoNewLine; Write-Host $compMenuItem2
    Write-Host
    Write-Host "[3] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItem3
    Write-Host "[4] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItem4
    Write-Host
    Write-Host "[5] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItem5
    Write-Host "[6] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItem6
    Write-Host
    Write-Host "[7] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItem7
    Write-Host "[8] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItem8
    Write-Host "[9] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItem9
    Write-Host
    Write-Host "[0] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItem0
    Write-Host "[-] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItem11
    Write-Host
    Write-Host "[=] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItem12
    Write-Host
    Write-Host "[D] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItemD
    Write-Host "[F] " -ForegroundColor $optionsColour -NoNewLine; Write-Host $compMenuItemF
    Write-Host
    Write-Host "[ESC] " -ForegroundColor $accentColour -NoNewLine; Write-Host $compMenuItemESC -NoNewLine
    
    $onlineAndWinRM = $isOnline -and $winRMStatus
    # $onlineAndWinRM = $pingStatus -and $winRMStatus

    ReadKey -menuPage "comp" -compName $global:remoteCompName -compStatus $onlineAndWinRM
}


function RemoteCompSubMenuActions {
    
    param ($compName)
    Clear-Host

    $compName = $compName.ToUpper()
    Switch ($K) {

        1 {Display-Title -title "$($compName): $compMenuItem1";Get-SystemInfo -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}
        2 {Display-Title -title "$($compName): $compMenuItem2";Get-InstalledPrograms4 -compName $compName -SamAccountName $username;Read-HostESCKey;RemoteCompSubMenu -compName $compName}

        3 {Display-Title -title "$($compName): $compMenuItem3";Open-CDollar -compName $compName ;Read-HostESCKey;RemoteCompSubMenu -compName $compName}
        4 {Display-Title -title "$($compName): $compMenuItem4";Transfer-File -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}

        5 {Display-Title -title "$($compName): $compMenuItem5";Map-NetworkDrive2 -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}
        6 {Display-Title -title "$($compName): $compMenuItem6";Map-NetworkPrinter -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}

        7 {Display-Title -title "$($compName): $compMenuItem7";Push-GPUpdate -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}
        8 {Display-Title -title "$($compName): $compMenuItem8";Run-McAfeeActions -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}
        9 {Display-Title -title "$($compName): $compMenuItem9";Run-ConfigManagerActions -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}

        0 {Display-Title -title "$($compName): $compMenuItem0";Clear-CCMCache -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}
        - {Display-Title -title "$($compName): $compMenuItem11";Clear-MSTeamsCache -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}

        = {Display-Title -title "$($compName): $compMenuItem12";Connect-RemoteControlViewer -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}

        D {Display-Title -title "$($compName): $compMenuItemD";Deploy-DisplayLink -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}
        F {Display-Title -title "$($compName): $compMenuItemF";Deploy-McAfeeFRP -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}

        L {Display-Title -title "$($compName): $compMenuItemL";Lock-Workstation -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}

        R {RemoteCompSubMenu -compName $compName}

        # Q {$global:remoteCompName=$null;return}

    }

    Switch ($VKC) {
        27 {$global:remoteCompName=$null;return}
    }

    # have to put this in each switch instead of here or it bugs when u press ESC or BACKSPACE or ENTER while in the menu and try to return
    # RemoteCompSubMenu -compName $compName

}

function RemoteCompSubMenuActionsOffline {

    param ($compName)
    Clear-Host

    Switch ($K) {

        1 {Display-Title -title "$($compName): $compMenuItem1";Get-SystemInfoOffline -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}
        2 {Display-Title -title "$($compName): $compMenuItem2";Get-InstalledProgramsOffline -compName $compName;Read-HostESCKey;RemoteCompSubMenu -compName $compName}

        R {RemoteCompSubMenu -compName $compName}
        # Q {$global:remoteCompName=$null;return}
    
    }

    Switch ($VKC) {
        27 {$global:remoteCompName=$null;return}
    }

    # RemoteCompSubMenu -compName $compName
}

$menuItem1 = "Initial Machine Setup"
$menuItem2 = "Rename Computer"

$menuItem3 = "Active Directory User"
$menuItem4 = "Find Computer Name"
$menuItem5 = "Remote Machine Menu"

$menuItem6 = "BitLocker Recovery Password"
$menuItem7 = "Local Administrator Password"

$menuItem8 = "AzureAD Role Elevation"
$menuItem9 = "AzureAD Portal"

$menuItem0 = "Generate Reports"

$menuItemV = "Open Remote Control Viewer"
$menuItem11 = "ECCC Approved Software List"
$menuItem12 = "Open Documentation"

$menuItemESC = "Quit"

function MainMenu {

    Clear-Host
    Write-Host "========================================" -ForegroundColor $accentColour
    Write-Host "=                                      =" -ForegroundColor $accentColour;
    Write-Host "=" -NoNewLine -ForegroundColor $accentColour; Write-Host "      Hugo's ECCC Deskside Tool       " -NoNewLine; Write-Host "=" -ForegroundColor $accentColour;
    Write-Host "=" -NoNewLine -ForegroundColor $accentColour; Write-Host "            $version             " -NoNewLine; Write-Host "=" -ForegroundColor $accentColour;
    Write-Host "=                                      =" -ForegroundColor $accentColour;
    Write-Host "========================================" -ForegroundColor $accentColour
    if (-Not (Check-AdminPriv)) {
        Write-Host "Please relaunch with admin privileges" -ForegroundColor "Yellow"
        Write-Host
        exit
    } else {
        Version-Checker
        Write-Host
        
        Write-Host "[1] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem1
        Write-Host "[2] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem2
        Write-Host 
        Write-Host "[3] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem3
        Write-Host "[4] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem4
        Write-Host "[5] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem5
        Write-Host 
        Write-Host "[6] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem6
        Write-Host "[7] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem7
        Write-Host 
        Write-Host "[8] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem8
        Write-Host "[9] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem9
        Write-Host
        if (inWhiteList) {
            Write-Host "[0] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem0
            Write-Host
        }
        Write-Host "[V] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItemV
        Write-Host "[-] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem11
        Write-Host "[=] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItem12
        Write-Host 
        Write-Host "[ESC] " -ForegroundColor $accentColour -NoNewLine; Write-Host $menuItemESC -NoNewLine


        # $Script:SourceMenu = $MyInvocation.MyCommand.Name

        ReadKey -menuPage "main"
    }
}


function MenuActions {
    Clear-Host
    Switch ($K) {
        1 {Display-Title -title $menuItem1;Run-InitialMachineScriptSomewhatParallel;Read-HostESCKey}
        2 {Display-Title -title $menuItem2;Change-RemoteCompName;Read-HostESCKey}
        3 {Display-Title -title $menuItem3;ADUserSubMenu}
        4 {Display-Title -title $menuItem4;Get-ComputerName;if ($global:showReadHostAnyKey){Read-HostESCKey}}
        # 5 {RemoteCompSubMenu;Read-HostESCKey}
        5 {RemoteCompSubMenu}
        6 {Display-Title -title $menuItem6;Get-BitLockerRecoveryPassword;Read-HostESCKey}
        7 {Display-Title -title $menuItem7;Get-LocalAdmPass;Read-HostESCKey}
        8 {Display-Title -title $menuItem8;AzureAD-ElevateRoles}
        9 {Display-Title -title $menuItem9;Start-Process $AzureADPortalLink}
        
        0 {if (inWhiteList) {ReportsSubMenu}}
        
        V {Display-Title -title $menuItemV;Open-RemoteControlViewer}
        - {Display-Title -title $menuItem11;Start-Process $ECCCApprovedSoftwareListPath}
        = {Display-Title -title $menuItem12;Open-SolutionGuide}

        B {Display-Title -title "Suspend BitLocker";Suspend-BitLocker1;Read-HostESCKey}

        U {Update-LatestVersion}
        # Q {ExitMonke}
    }

    Switch ($VKC) {
        27 {ExitMonke}
    }

    # & $SourceMenu
}


while (420) {
    try {
        MainMenu
    } catch {
        Write-Host $Error.exception -ForegroundColor "red" -backgroundcolor "black"
        $error.clear()
        Clear-GlobalVariables
        Read-HostESCKey
    }
}
