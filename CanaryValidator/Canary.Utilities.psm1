
$Global:ContinueOnFailure = $false
$Global:JSONLogFile = "Run-Canary.JSON"
$Global:TxtLogFile = "AzureStackCanaryLog.Log"
$Global:wttLogFileName = ""
$Global:listAvailableUsecases = $false
$Global:exclusionList = @()

$Global:dryRun = $false

function assert {
    param(
        [bool]$Assertion,
        [string]$Message = ""
    )
    if (-not $Assertion) {
        Write-Error "Assertion failed`n`t$Message"
        exit
    }
}

if (Test-Path -Path "$PSScriptRoot\..\WTTLog.ps1") {
    Import-Module -Name "$PSScriptRoot\..\WTTLog.ps1" -Force
    $Global:wttLogFileName = (Join-Path $PSScriptRoot "AzureStack_CanaryValidation_Test.wtl")    
}

$CurrentUseCase = @{}
[System.Collections.Stack] $UseCaseStack = New-Object System.Collections.Stack
filter timestamp {"$(Get-Date -Format "yyyy-MM-dd HH:mm:ss.ffff") $_"}


function Out-Log {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [string]$Filename = "C:\Users\AzureStackAdmin\Desktop\MyCanary\debug.txt"
    )
    $Message | Out-File -Append -FilePath $Filename
}

function Log-Info {
    Param ($Message)

    if ($Message.GetType().Name -eq "String") {
        $Message = "[INFO] " + $Message | timestamp
    }
    $Message | Tee-Object -FilePath $Global:TxtLogFile -Append
    Log-JSONReport $Message
} 

function Log-Error {
    Param ([string] $Message)

    $Message = "[ERR] " + $Message | timestamp
    $Message | Tee-Object -FilePath $Global:TxtLogFile -Append
    Log-JSONReport $Message
}

function Log-Exception {
    Param ([string] $Message)

    $Message = "[EXCEPTION] " + $Message | timestamp
    $Message | Tee-Object -FilePath $Global:TxtLogFile -Append
    Log-JSONReport $Message
}

function Log-JSONReport {
    param (
        [string] $Message
    )
    if ($Message) {    
        if ($Message.Contains("[START]")) {
            $time = $Message.Substring(0, $Message.IndexOf("[")).Trim()
            $name = $Message.Substring($Message.LastIndexOf(":") + 1).Trim()
            if ($UseCaseStack.Count) {
                $nestedUseCase = @{
                    "Name"      = $name
                    "StartTime" = $time
                }
                if (-not $UseCaseStack.Peek().UseCase) {
                    $UseCaseStack.Peek().Add("UseCase", @())
                }
                $UseCaseStack.Peek().UseCase += , $nestedUseCase
                $UseCaseStack.Push($nestedUseCase)
            }
            else {
                $CurrentUseCase.Add("Name", $name)
                $CurrentUseCase.Add("StartTime", $time)
                $UseCaseStack.Push($CurrentUseCase)
            }
        }
        elseif ($Message.Contains("[END]")) {
            $time = $Message.Substring(0, $Message.IndexOf("[")).Trim()
            $result = ""            
            if ($UseCaseStack.Peek().UseCase -and ($UseCaseStack.Peek().UseCase | Where-Object {$_.Result -eq "FAIL"})) {
                $result = "FAIL" 
            }
            elseif ($Message.Contains("[RESULT = PASS]")) {
                $result = "PASS"
            }
            elseif ($Message.Contains("[RESULT = FAIL]")) {
                $result = "FAIL"
            }
            $UseCaseStack.Peek().Add("Result", $result)
            $UseCaseStack.Peek().Add("EndTime", $time)            
            $UseCaseStack.Pop() | Out-Null
            if (-not $UseCaseStack.Count) {
                $jsonReport = ConvertFrom-Json (Get-Content -Path $Global:JSONLogFile -Raw)
                $jsonReport.UseCases += , $CurrentUseCase
                $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $Global:JSONLogFile
                $CurrentUseCase.Clear()
            }
        }
        elseif ($Message.Contains("[DESCRIPTION]")) {
            $description = $Message.Substring($Message.IndexOf("[DESCRIPTION]") + "[DESCRIPTION]".Length).Trim()
            $UseCaseStack.Peek().Add("Description", $description)
        }
        elseif ($Message.Contains("[EXCEPTION]")) {
            $exception = $Message.Substring($Message.IndexOf("[EXCEPTION]") + "[EXCEPTION]".Length).Trim()
            $UseCaseStack.Peek().Add("Exception", $exception)
        }
    }
}

function Get-CanaryResult {    
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFilename
    )

    if ($LogFilename) {
        $logContent = Get-Content -Raw -Path $LogFilename | ConvertFrom-Json
    }
    else {
        $logContent = Get-Content -Raw -Path $Global:JSONLogFile | ConvertFrom-Json    
    }
    $results = @()   
    foreach ($usecase in $logContent.UseCases) {
        $ucObj = New-Object -TypeName PSObject
        if ([bool]($usecase.PSobject.Properties.name -match "UseCase")) {
            $ucObj | Add-Member -Type NoteProperty -Name Name -Value $usecase.Name
            $ucObj | Add-Member -Type NoteProperty -Name Result -Value $usecase.Result
            $ucObj | Add-Member -Type NoteProperty -Name "Duration`n[Seconds]" -Value ((Get-Date $usecase.EndTime) - (Get-Date $usecase.StartTime)).TotalSeconds     
            $ucObj | Add-Member -Type NoteProperty -Name Description -Value $usecase.Description
            $results += $ucObj               
            
            foreach ($subusecase in $usecase.UseCase) {                                                                                                                                                          
                $ucObj = New-Object -TypeName PSObject
                $ucObj | Add-Member -Type NoteProperty -Name Name -Value ("|-- $($subusecase.Name)")
                $ucObj | Add-Member -Type NoteProperty -Name Result -Value $subusecase.Result
                $ucObj | Add-Member -Type NoteProperty -Name "Duration`n[Seconds]" -Value ((Get-Date $subusecase.EndTime) - (Get-Date $subusecase.StartTime)).TotalSeconds     
                $ucObj | Add-Member -Type NoteProperty -Name Description -Value ("|-- $($subusecase.Description)")
                $results += $ucObj  
            }
        }
        else {
            $ucObj | Add-Member -Type NoteProperty -Name Name -Value $usecase.Name
            $ucObj | Add-Member -Type NoteProperty -Name Result -Value $usecase.Result
            $ucObj | Add-Member -Type NoteProperty -Name "Duration`n[Seconds]" -Value ((Get-Date $usecase.EndTime) - (Get-Date $usecase.StartTime)).TotalSeconds     
            $ucObj | Add-Member -Type NoteProperty -Name Description -Value $usecase.Description   
            $results += $ucObj
        }
    }   
    if ($results) {
        Log-Info($results | Format-Table -AutoSize)                                               
    }
}

function Get-CanaryLonghaulResult {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$LogPath
    )

    $logFiles = (Get-ChildItem -Path $LogPath -Filter *.JSON -File).FullName
    $logContent = @()
    foreach ($file in $logFiles) {
        $logContent += (Get-Content -Raw -Path $file | ConvertFrom-Json).UseCases
    }
    $usecasesGroup = $logContent | Group-Object -Property Name
    $usecasesGroup | Format-Table -AutoSize @{Expression = {$_.Name}; Label = "Name"; Align = "Left"},
    @{Expression = {$_.Count}; Label = "Count"; Align = "Left"},
    @{Expression = {$passPct = [math]::Round(((($_.Group | Where-Object Result -eq "PASS" | Measure-Object).Count / $_.Count) * 100), 0); $passPct.ToString() + "%"}; Label = "Pass`n[Goal: >99%]"; Align = "Left"},    
    @{Expression = {[math]::Round(($_.Group | Where-Object Result -eq "PASS" | ForEach-Object {((Get-Date $_.EndTime) - (Get-Date $_.StartTime)).TotalMilliseconds} | Measure-Object -Minimum).Minimum, 0)}; Label = "MinTime`n[msecs]"; Align = "Left"},
    @{Expression = {[math]::Round(($_.Group | Where-Object Result -eq "PASS" | ForEach-Object {((Get-Date $_.EndTime) - (Get-Date $_.StartTime)).TotalMilliseconds} | Measure-Object -Maximum).Maximum, 0)}; Label = "MaxTime`n[msecs]"; Align = "Left"},
    @{Expression = {[math]::Round(($_.Group | Where-Object Result -eq "PASS" | ForEach-Object {((Get-Date $_.EndTime) - (Get-Date $_.StartTime)).TotalMilliseconds} | Measure-Object -Average).Average, 0)}; Label = "AvgTime`n[msecs]"; Align = "Left"},
    @{Expression = {$pCount = ($_.Group | Where-Object Result -eq "PASS").Count; $times = ($_.Group | Where-Object Result -eq "PASS" | ForEach-Object {((Get-Date $_.EndTime) - (Get-Date $_.StartTime)).TotalMilliseconds}); $avgTime = ($times | Measure-Object -Average).Average; $sd = 0; foreach ($time in $times) {$sd += [math]::Pow(($time - $avgTime), 2)}; [math]::Round([math]::Sqrt($sd / $pCount), 0)}; Label = "StdDev"; Align = "Left"},
    @{Expression = {$pCount = ($_.Group | Where-Object Result -eq "PASS").Count; $times = ($_.Group | Where-Object Result -eq "PASS" | ForEach-Object {((Get-Date $_.EndTime) - (Get-Date $_.StartTime)).TotalMilliseconds}); $avgTime = ($times | Measure-Object -Average).Average; $sd = 0; foreach ($time in $times) {$sd += [math]::Pow(($time - $avgTime), 2)}; [math]::Round(([math]::Round([math]::Sqrt($sd / $pCount), 0) / $avgTime), 0) * 100}; Label = "RelativeStdDev`n[Goal: <50%]"; Align = "Left"}
}

function Get-CanaryFailureStatus {
    $logContent = Get-Content -Raw -Path $Global:JSONLogFile | ConvertFrom-Json
    if ($logContent.Usecases.Result -contains "FAIL") {
        return $true
    }
    return $false
}

function Start-Scenario {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Type,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFilename,
        [parameter(Mandatory = $false)]
        [bool]$ContinueOnFailure = $false,
        [parameter(Mandatory = $false)]
        [bool]$ListAvailable = $false,
        [parameter(Mandatory = $false)]
        [string[]]$ExclusionList
    )

    if ($LogFileName) {
        if ($fileExtension = [IO.Path]::GetExtension($LogFileName)) {
            $Global:JSONLogFile = $LogFileName.Replace($fileExtension, ".JSON")
            $Global:TxtLogFile = $LogFileName   
        }        
        else {
            $Global:JSONLogFile = $LogFileName + ".JSON"
            $Global:TxtLogFile = $LogFileName + ".Log"               
        }        
    }
    if ($Global:wttLogFileName) {
        OpenWTTLogger $Global:wttLogFileName    
    }

    if ($ListAvailable) {
        $Global:listAvailableUsecases = $true
    }

    if ($ExclusionList) {
        $Global:exclusionList = $ExclusionList
    }
    if (-not $ListAvailable) {
        New-Item -Path $Global:JSONLogFile -Type File -Force
        New-Item -Path $Global:TxtLogFile -Type File -Force
        $jsonReport = @{
            "Scenario" = ($Name + "-" + $Type)
            "UseCases" = @()
        }    
        $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $Global:JSONLogFile
    }

    $Global:ContinueOnFailure = $ContinueOnFailure
}

function End-Scenario {

    Start-ParallelJobs

    if ($Global:wttLogFileName) {
        CloseWTTLogger    
    }
}

function Invoke-Action {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]$ActionBlock
    )
    
    Log-Info ("[START] Action: $Name`n") 

    try {
        if (-not $Global:dryRun) {
            Invoke-Command -ScriptBlock $ActionBlock
        }
    }
    catch [System.Exception] {        
        Log-Exception ($_.Exception)
        Log-Info ("###### <FAULTING SCRIPTBLOCK> ######")
        Log-Info ("$UsecaseBlock")
        Log-Info ("###### </FAULTING SCRIPTBLOCK> ######")
        if (-not $Global:ContinueOnFailure) {
            throw $_.Exception
        }
    }
    finally {
        Log-Error ("[END] Action: $Name`n")
    }
}

function Invoke-UseCase {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Description, 

        [parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]$UsecaseBlock
    )

    Log-Info "Invoke-Usecase: $Name"

    if ($Global:listAvailableUsecases) {
        $parentUsecase = $Name
        if ((Get-PSCallStack)[1].Arguments.Contains($parentUsecase)) {
            "  `t" * ([math]::Floor((Get-PSCallStack).Count / 3)) + "|-- " + $Name
        }
        else {
            "`t" + $Name
        }
        if ($UsecaseBlock.ToString().Contains("Invoke-Usecase")) {
            Invoke-Command -ScriptBlock $UsecaseBlock -ErrorAction SilentlyContinue
        }
        return
    }

    if (($Global:exclusionList).Contains($Name)) {
        Log-Info ("Skipping Usecase: $Name")
        return
    }

    Log-Info ("[START] Usecase: $Name`n") 
    if ($Global:wttLogFileName) {
        StartTest "CanaryGate:$Name"
    }

    if ($Description) {
        Log-Info ("[DESCRIPTION] $Description`n")
    }

    try {
        if ($Global:dryRun) {
            $result = $true 
        }
        else {
            $result = Invoke-Command -ScriptBlock $UsecaseBlock
        }

        if ($result -and (-not $UsecaseBlock.ToString().Contains("Invoke-Usecase"))) {
            Log-Info ($result)
        }
        else {
            Log-Info ($result)
        }
        if ($Global:wttLogFileName) {
            EndTest "CanaryGate:$Name" $true
        }
        Log-Info ("[END] [RESULT = PASS] Usecase: $Name`n")
        return $result | Out-Null
    }
    catch [System.Exception] {        
        Log-Exception ($_.Exception)
        Log-Info ("###### <FAULTING SCRIPTBLOCK> ######")
        Log-Info ("$UsecaseBlock")
        Log-Info ("###### </FAULTING SCRIPTBLOCK> ######")
        Log-Error ("[END] [RESULT = FAIL] Usecase: $Name`n")
        if ($Global:wttLogFileName) {
            EndTest "CanaryGate:$Name" $false
        }

        if (-not $Global:ContinueOnFailure) {
            throw $_.Exception
        }
        return $false
    }
}

function GetAzureStackEndpoints {
    [CmdletBinding()]
    param( 
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EnvironmentDomainFQDN,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ArmEndpoint

    ) 

    $aadTenantId = $AADTenantId
    $endptres = Invoke-RestMethod "${armEndpoint}/metadata/endpoints?api-version=1.0" -ErrorAction Stop    
    $ActiveDirectoryEndpoint = $($endptres.authentication.loginEndpoint).TrimEnd("/") + "/"
    $ActiveDirectoryServiceEndpointResourceId = $($endptres.authentication.audiences[0])
    $ResourceManagerEndpoint = $armEndpoint
    $GalleryEndpoint = $endptres.galleryEndpoint
    $GraphEndpoint = $endptres.graphEndpoint
    $AzureKeyVaultDnsSuffix = "vault.$EnvironmentDomainFQDN".ToLowerInvariant()
    $AzureKeyVaultServiceEndpointResourceId = $("https://vault.$EnvironmentDomainFQDN".ToLowerInvariant()) 
    $StorageEndpointSuffix = $EnvironmentDomainFQDN

    $asEndpointsObj = New-Object -TypeName PSObject
    $asEndpointsObj | Add-Member -Type NoteProperty  -TypeName System.Management.Automation.PSCustomObject -Name ActiveDirectoryEndpoint -Value $ActiveDirectoryEndpoint
    $asEndpointsObj | Add-Member -Type NoteProperty  -TypeName System.Management.Automation.PSCustomObject -Name ActiveDirectoryServiceEndpointResourceId -Value $ActiveDirectoryServiceEndpointResourceId
    $asEndpointsObj | Add-Member -Type NoteProperty  -TypeName System.Management.Automation.PSCustomObject -Name ResourceManagerEndpoint -Value $ResourceManagerEndpoint
    $asEndpointsObj | Add-Member -Type NoteProperty  -TypeName System.Management.Automation.PSCustomObject -Name GalleryEndpoint -Value $GalleryEndpoint
    $asEndpointsObj | Add-Member -Type NoteProperty  -TypeName System.Management.Automation.PSCustomObject -Name GraphEndpoint -Value $GraphEndpoint
    $asEndpointsObj | Add-Member -Type NoteProperty  -TypeName System.Management.Automation.PSCustomObject -Name StorageEndpointSuffix -Value $StorageEndpointSuffix
    $asEndpointsObj | Add-Member -Type NoteProperty  -TypeName System.Management.Automation.PSCustomObject -Name AzureKeyVaultDnsSuffix -Value $AzureKeyVaultDnsSuffix
    $asEndpointsObj | Add-Member -Type NoteProperty  -TypeName System.Management.Automation.PSCustomObject -Name AzureKeyVaultServiceEndpointResourceId -Value $AzureKeyVaultServiceEndpointResourceId

    return $asEndpointsObj
}

function NewSubscriptionsQuota {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $AdminUri,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $SubscriptionId,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $AzureStackToken,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $ArmLocation  
    )    

    $getSubscriptionsQuota = @{
        Uri         = "{0}/subscriptions/{1}/providers/Microsoft.Subscriptions.Admin/locations/{2}/quotas?api-version=2015-11-01" -f $AdminUri, $SubscriptionId, $ArmLocation
        Method      = "GET"
        Headers     = @{ "Authorization" = "Bearer " + $AzureStackToken }
        ContentType = "application/json"
    }
    $subscriptionsQuota = Invoke-RestMethod @getSubscriptionsQuota

    $subscriptionsQuota.value.Id        
}

function NewStorageQuota {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $AdminUri,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $SubscriptionId,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $AzureStackToken,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $ArmLocation  
    )    

    $quotaName = "ascanarystoragequota"
    $capacityInGb = 1000
    $numberOfStorageAccounts = 200
    $ApiVersion = "2015-12-01-preview"

    $uri = "{0}/subscriptions/{1}/providers/Microsoft.Storage.Admin/locations/{2}/quotas/{3}?api-version={4}" -f $AdminUri, $SubscriptionId, $ArmLocation, $quotaName, $ApiVersion
    $RequestBody = @"
    {
        "name":"$quotaName",
        "location":"$ArmLocation",
        "properties": { 
            "capacityInGb": $capacityInGb, 
            "numberOfStorageAccounts": $numberOfStorageAccounts
        }
    }
"@
    $headers = @{ "Authorization" = "Bearer " + $AzureStackToken }
    $storageQuota = Invoke-RestMethod -Method Put -Uri $uri -Body $RequestBody -ContentType 'application/json' -Headers $headers
        
    $storageQuota.Id        
}

function NewComputeQuota {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $AdminUri,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $SubscriptionId,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $AzureStackToken,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $ArmLocation  
    )  

    $quotaName = "ascanarycomputequota"
    $vmCount = 100
    $memoryLimitMB = 102400
    $coresLimit = 100
    $ApiVersion = "2015-12-01-preview"

    $uri = "{0}/subscriptions/{1}/providers/Microsoft.Compute.Admin/locations/{2}/quotas/{3}?api-version={4}" -f $AdminUri, $SubscriptionId, $ArmLocation, $quotaName, $ApiVersion
    $RequestBody = @"
    {
        "name":"$quotaName",
        "type":"Microsoft.Compute.Admin/quotas",
        "location":"$ArmLocation",
        "properties":{
            "virtualMachineCount":$vmCount,
            "memoryLimitMB":$memoryLimitMB,
            "coresLimit":$coresLimit
        }
    }
"@
    $headers = @{ "Authorization" = "Bearer " + $AzureStackToken }
    $computeQuota = Invoke-RestMethod -Method Put -Uri $uri -Body $RequestBody -ContentType 'application/json' -Headers $headers
        
    $computeQuota.Id        
}

function NewNetworkQuota {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $AdminUri,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $SubscriptionId,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $AzureStackToken,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $ArmLocation  
    ) 

    $quotaName = "ascanarynetworkquota"
    $publicIpsPerSubscription = 50
    $vNetsPerSubscription = 50
    $gatewaysPerSubscription = 1
    $connectionsPerSubscription = 2
    $loadBalancersPerSubscription = 50
    $nicsPerSubscription = 100
    $securityGroupsPerSubscription = 50
    $ApiVersion = "2015-06-15"
    
    $uri = "{0}/subscriptions/{1}/providers/Microsoft.Network.Admin/locations/{2}/quotas/{3}?api-version={4}" -f $AdminUri, $SubscriptionId, $ArmLocation, $quotaName, $ApiVersion
    $id = "/subscriptions/{0}/providers/Microsoft.Network.Admin/locations/{1}/quotas/{2}" -f $SubscriptionId, $ArmLocation, $quotaName
    $RequestBody = @"
    {
        "id":"$id",
        "name":"$quotaName",
        "type":"Microsoft.Network.Admin/quotas",
        "location":"$ArmLocation",
        "properties":{
            "maxPublicIpsPerSubscription":$publicIpsPerSubscription,
            "maxVnetsPerSubscription":$vNetsPerSubscription,
            "maxVirtualNetworkGatewaysPerSubscription":$gatewaysPerSubscription,
            "maxVirtualNetworkGatewayConnectionsPerSubscription":$connectionsPerSubscription,
            "maxLoadBalancersPerSubscription":$loadBalancersPerSubscription,
            "maxNicsPerSubscription":$nicsPerSubscription,
            "maxSecurityGroupsPerSubscription":$securityGroupsPerSubscription,
        }
    }
"@
    $headers = @{ "Authorization" = "Bearer " + $AzureStackToken}
    $networkQuota = Invoke-RestMethod -Method Put -Uri $uri -Body $RequestBody -ContentType 'application/json' -Headers $headers
        
    $networkQuota.Id       
}

function NewKeyVaultQuota {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $AdminUri,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $SubscriptionId,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $AzureStackToken,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]    
        [string] $ArmLocation  
    ) 

    $uri = "{0}/subscriptions/{1}/providers/Microsoft.Keyvault.Admin/locations/{2}/quotas?api-version=2017-02-01-preview" -f $AdminUri, $SubscriptionId, $ArmLocation
    $headers = @{ "Authorization" = "Bearer " + $AzureStackToken }
    $kvQuota = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -ContentType 'application/json' -ErrorAction Stop
        
    $kvQuota.Value.Id
}

function NewAzureStackToken {
    [CmdletBinding()]
    param(         
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AADTenantID, 
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EnvironmentDomainFQDN,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$Credentials,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ArmEndpoint

    )
    
    $endpoints = GetAzureStackEndpoints -EnvironmentDomainFQDN $EnvironmentDomainFQDN -ArmEndPoint $ArmEndpoint
    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
    
    $contextAuthorityEndpoint = ([System.IO.Path]::Combine($endpoints.ActiveDirectoryEndpoint, $AADTenantID)).Replace('\', '/')
    $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext($contextAuthorityEndpoint, $false)
    $userCredential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential($Credentials.UserName, $Credentials.Password)
    return ($authContext.AcquireToken($endpoints.ActiveDirectoryServiceEndpointResourceId, $clientId, $userCredential)).AccessToken  
}

function NewAzureStackDefaultQuotas {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceLocation,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AADTenantID, 
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EnvironmentDomainFQDN,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$Credentials,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ArmEndpoint
    ) 

    $aadTenantId = $AADTenantId
    $serviceQuotas = @()
    $asToken = NewAzureStackToken -AADTenantId $AADTenantId -EnvironmentDomainFQDN $EnvironmentDomainFQDN -Credentials $Credentials -ArmEndpoint $ArmEndpoint
    #$serviceQuotas += NewSubscriptionsQuota -AdminUri $armEndpoint -SubscriptionId $SubscriptionId -AzureStackToken $asToken -ArmLocation $ResourceLocation
    $serviceQuotas += NewStorageQuota -AdminUri $armEndPoint -SubscriptionId $SubscriptionId -AzureStackToken $asToken -ArmLocation $ResourceLocation
    $serviceQuotas += NewComputeQuota -AdminUri $armEndPoint -SubscriptionId $SubscriptionId -AzureStackToken $asToken -ArmLocation $ResourceLocation
    $serviceQuotas += NewNetworkQuota -AdminUri $armEndPoint -SubscriptionId $SubscriptionId -AzureStackToken $asToken -ArmLocation $ResourceLocation
    $serviceQuotas += NewKeyVaultQuota -AdminUri $armEndPoint -SubscriptionId $SubscriptionId -AzureStackToken $asToken -ArmLocation $ResourceLocation
    
    $serviceQuotas    
}

function NewAzureStackDSCScriptResource {
    [CmdletBinding()]
    param( 
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DSCScriptResourceName,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DestinationPath,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$DSCScript     
    )

    if (-not $DSCScript) {
        $DSCScript = "Configuration ASCheckNetworkConnectivityUtil 
        {    
            Node localhost 
            {
                Script TestNetworkConnectivity 
                {
                    SetScript = {
                        Test-NetConnection -ComputerName www.microsoft.com -InformationLevel Detailed         
                    }
                    GetScript = { @{} }
                    TestScript = { `$false }
                }
                LocalConfigurationManager 
                {
                    ConfigurationMode = 'ApplyOnly'
                    RebootNodeIfNeeded = `$false
                }
            }
        }"
    }
    if (-not (Test-Path -Path $DestinationPath)) {
        New-Item -Path $DestinationPath -ItemType Directory -Force
    }
    $destinationDSCScriptPath = Join-Path -Path $DestinationPath -ChildPath $DSCScriptResourceName
    $DSCScript | Out-File -FilePath $destinationDSCScriptPath -Encoding utf8 -ErrorAction Stop
    $dscZipPath = Join-Path -Path ($DestinationPath | Split-Path) -ChildPath "DSCResource.ZIP"
    [Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
    $ZipLevel = [System.IO.Compression.CompressionLevel]::Optimal
    [System.IO.Compression.ZipFile]::CreateFromDirectory($DestinationPath, $dscZipPath, $ZipLevel, $false)  

    $dscZipPath   
}

function NewAzureStackCustomScriptResource {
    [CmdletBinding()]
    param( 
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CustomScriptResourceName,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DestinationPath,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$CustomScript     
    )

    if (-not $CustomScript) {
        $CustomScript = "Write-Output `"Disable firewall`"
                        netsh advfirewall set privateprofile state off;

                        Set-WSManQuickConfig -Force
                        winrm quickconfig -q -force
                        Set-NetFirewallRule -DisplayName `"Windows Remote Management (HTTP-In)`" -Profile `"Public`" -Action `"Allow`" -RemoteAddress `"Any`" -Confirm:`$false

                        Write-Output `"Checking for data disks on the VM`"
                        `$dataDisks = Get-Disk | Where-Object {(-not(`$_.IsBoot)) -and (-not(`$_.IsSystem))}

                        if (`$dataDisks) 
                        {
                            Write-Output `"Found data disk(s) attached to the VM`" | Tee-Object -FilePath (`$env:USERPROFILE + `"\CheckDataDiskUtil.log`")
                            `$dataDisks | Select Number, FriendlyName | Format-Table -AutoSize | Tee-Object -FilePath (`$env:USERPROFILE + `"\CheckDataDiskUtil.log`")
                        }
                        else
                        {
                            `"Found no data disk(s) attached to the VM`" | Out-File -FilePath (`$env:USERPROFILE + `"\CheckDataDiskUtil.log`") 
                            Write-Error `"Found no data disk(s) attached to the VM`"
                        }"
    }
    if (-not (Test-Path -Path $DestinationPath)) {
        New-Item -Path $DestinationPath -ItemType Directory -Force
    }
    $destinationCustomScriptPath = Join-Path -Path $DestinationPath -ChildPath $CustomScriptResourceName
    $CustomScript | Out-File -FilePath $destinationCustomScriptPath -Encoding utf8 -ErrorAction Stop 

    $destinationCustomScriptPath    
}

function NewAzureStackDataVHD {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [int]$VHDSizeInGB
    )

    $vhdSizeInBytes = $VHDSizeInGB * 1024
    $tmpPath = Split-Path -Path $FilePath
    "CREATE VDISK FILE=`"$FilePath`" MAXIMUM=$vhdSizeInBytes" | Out-File -FilePath "$tmpPath\CreateASDataDisk.txt" -Encoding ascii
    cmd /c diskpart /s "$tmpPath\CreateASDataDisk.txt"

    if (Test-Path $FilePath) {
        Remove-Item -Path "$tmpPath\CreateASDataDisk.txt" -Force
    }
    else {
        throw [System.Exception]"Failed to create the VHD file"    
    }

    return $FilePath        
}

function GetAzureStackBlobUri {
    [CmdletBinding()]
    param(        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResourceGroupName,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BlobContent,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StorageAccountName,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$StorageContainerName
    )

    try {
        if (-not (Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName)) {
            throw [System.Exception]"Storage account $StorageAccountName does not exist"
        }
        $asStorageAccountKey = Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
        if ($asStorageAccountKey) {
            $storageAccountKey = $asStorageAccountKey.Key1
        }
        $asStorageContext = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $storageAccountKey -ErrorAction Stop
        if (-not ($blobUri = (Get-AzureStorageBlob  -Blob $BlobContent -Container $StorageContainerName -Context $asStorageContext -ErrorAction Stop).ICloudBlob.uri.AbsoluteUri)) {
            throw [System.Exception]"Failed to retrieve the blob content Uri"
        }

        return $blobUri        
    }
    catch [System.Exception] {
        throw $_.Exception.Message    
    }
}

function DownloadFile {
    param
    (
        [Parameter(Mandatory = $true)]
        [String] $FileUrl,
        [Parameter(Mandatory = $true)]
        [String] $OutputFolder
    )
    $retries = 20
    $lastException = $null
    $success = $false
    
    while ($success -eq $false -and $retries -ge 0) {
        $success = $true
        try {
            $outputFile = Join-Path $OutputFolder (Split-Path -Path $FileUrl -Leaf)
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($FileUrl, $outputFile) | Out-Null
        }
        catch {
            $success = $false            
            $lastException = $_
        }
        $retries--
        if ($success -eq $false) {
            Start-Sleep -Seconds 10                        
        }
    }

    if ($success -eq $false) {
        Write-Output "Timed out trying to download $FileUrl"
        throw $lastException
    }

    return $outputFile
}

function CopyImage {
    param
    (
        [Parameter(Mandatory = $true)]
        [String] $ImagePath,
        [Parameter(Mandatory = $true)]
        [String] $OutputFolder
    )

    if (Test-Path $ImagePath) {
        Copy-Item $ImagePath $OutputFolder
        $outputfile = Join-Path $OutputFolder (Split-Path $ImagePath -Leaf)
    }
    elseif ($ImagePath.StartsWith("http")) {
        $outputfile = DownloadFile -FileUrl $ImagePath -OutputFolder $OutputFolder
    }
    if (([System.IO.FileInfo]$outputfile).Extension -eq ".zip") {
        Expand-Archive -Path $outputfile -DestinationPath $OutputFolder -Force   
    }

    return (Get-ChildItem -Path $OutputFolder -File | Where-Object {$_.Extension -eq ".vhd" -or $_.Extension -eq ".vhdx"})[0].FullName
}

function Get-RemoteSession {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        $ComputerName,

        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$SecureCredential,

        [parameter(Mandatory = $false, Position = 2)]
        [string]$ErrorMessage = "Unable to establish a remote session: $ComputerName"
    )

    $sw = [system.diagnostics.stopwatch]::startNew(); 
    while (-not($session = New-PSSession -ComputerName $ComputerName -Credential $SecureCredential -ErrorAction SilentlyContinue)) {
        if (($sw.ElapsedMilliseconds -gt 240000) -and (-not($session))) {
            $sw.Stop(); 
            throw [System.Exception]$ErrorMessage
        }; 
        Start-Sleep -Seconds 15
    };
    $session
}

function Invoke-RemoteScript {
    param(
        [parameter(Mandatory = $true, ParameterSetName = "NameCred")]
        [ValidateNotNullOrEmpty()]
        $ComputerName,

        [parameter(Mandatory = $true, ParameterSetName = "NameCred")]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$SecureCredential,

        [parameter(Mandatory = $true, ParameterSetName = "Session")]
        [ValidateNotNullOrEmpty()]
        [PSSession]$Session,

        [parameter(Mandatory = $false, ParameterSetName = "NameCred")]
        [parameter(ParameterSetName = "Session")]
        [string]$ErrorMessage = "Unable to establish a remote session: $ComputerName",

        [parameter(Mandatory = $true, ParameterSetName = "NameCred")]
        [ValidateNotNullOrEmpty()]
        [parameter(ParameterSetName = "Session")]
        [ScriptBlock]$Script,

        [parameter(Mandatory = $false, ParameterSetName = "NameCred")]
        [parameter(ParameterSetName = "Session")]
        [object[]]$ArgumentList,

        [parameter(Mandatory = $false, ParameterSetName = "NameCred")]
        [parameter(ParameterSetName = "Session")]
        $ErrorVariable = $null
    )

    if ($PSCmdlet.NameCred) {
        $Session = Get-RemoteSession -ComputerName $ComputerName -SecureCredential $SecureCredential -ErrorMessage $ErrorMessage
    }
    $Result = Invoke-Command -Session $session -Script $Script -ArgumentList $ArgumentList -ErrorVariable $ErrorVariable
    
    if ($PSCmdlet.Session) {
        return $Result
    }
    else {
        return $Session, $Result
    }
}

#########################################
#                                       #
#                                       #
#                                       #
#           Parallelization Code        #
#                                       #
#                                       #
#                                       #
#                                       #
#########################################







function Remove-Dependency {
    param(
        [string]$JobName
    )
    try {
        Enter-Lock
        $deps = $Global:Dependendents[$JobName]
        Out-Log "Dep: $deps"

        foreach ( $dep in $deps) {

            $preqs = $Global:DependsOn[$dep]
            $preqs.Remove($JobName)
            $Global:DependsOn[$dep] = $preqs

            if ($preqs.Count -eq 0) {
                Start-ParallelJob $dep
            }
        }
    }
    catch {
        Out-Log "Updating dependents failed... $_"
    }
    finally {
        Exit-lock
    }
}

function Atomic-Decrement {
    param(
        [string]$Variable,
        [System.Threading.Mutex]$Mutex
    )
    try {
        Enter-Lock -Mutex $Mutex
        $val = Get-Variable -Name Variable -ValueOnly
        $val -= 1
        Set-Variable -Name Variable -Value $val
    }
    catch {
        Out-Log $_
    }
    finally {
        Exit-Lock  -Mutex $Mutex
    }

}

function Start-ParallelJob {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    Out-Log "Starting job... $Name"
    
    [ScriptBlock]$wrapper = {
        param(
            [Parameter(Position = 0)]
            [ValidateNotNullOrEmpty()]
            [PSCustomObject]$Job
        )

        [string]$JobName = $Job.Name
        [ScriptBlock]$Script = $Job.Script
        [PSCustomObject]$Data = $Job.Data

        Enter-Lock
        $Global:Scheduled.Remove($JobName)
        $Global:Running.Add($JobName)
        Exit-Lock

        Write-Debug "Hello"
        Write-Verbose "Hello"
        Out-Log "Hello"
        try {
            Out-Log "Invoking for $JobName"
            Invoke-Command $Script -ArgumentList $Data
        }
        catch {
            Out-Log $_
        }
    
        # decrement dependency counts for each dependent, if we reach 0
        # then we can start the next job.
        Out-Log "Removing dependencies for $JobName"
        Remove-Dependency -JobName $JobName

        # Signal that this job has completed
        Out-Log "Removing $JobName"
        
        Enter-Lock
        $Global:Running.Remove($JobName)
        Exit-Lock

        Out-Log "job finished... $JobName"
    }

    [PSCustomObject]$job = $Global:jobs[$Name]
    if ($job) {
        try {
            $jerb = Invoke-Command -JobName $Name -ScriptBlock $wrapper -ArgumentList $job -AsJob
            Start-Sleep -s 2
            Receive-Job $jerb
        }
        catch {
            $fullError = $_.Exception
            $error = "Could not invoke command: $fullError"
            Out-Log $error
            throw $error
        }
    }
    else {
        Out-Log "job is null!"
    }
}

# Run any parallel work
function Start-ParallelJobs {
    $ErrorActionPreference = 'Stop'
    
    Out-Log "Start-ParallelJobs"

    # find jobs with no dependencies and schedule them
    
    Enter-Lock

    foreach ($key in $Global:DependsOn.Keys) {
        $count = $Global:DependsOn[$key].Count
        if ($count -eq 0) {
            $Global:Scheduled.Add($key)
        }
    }
    Exit-Lock
    
    
    
    # Wait for jobs to finish
    [bool]$workToDo = ($Global:Scheduled.Count -gt 0)
    while ($workToDo) {
        Start-Sleep -m 100 | Out-Null

        Enter-Lock
        # start parallel jobs
        foreach ($job in $Global:Scheduled) {
            Out-Log $job
            Start-ParallelJob $job
        }

        $workToDo = ($Global:Running.Count -gt 0) -or ($Global:Scheduled.Count -gt 0)
        Exit-Lock
    }

    # Goes over each job that I scheduled, print out errors

    Out-Log "all parallel jobs completed.."
}

function Add-Job {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Job,
        
        [parameter(Mandatory = $false, Position = 3)]
        [string[]]$DependsOn = $null
    )

    # Make sure shared data-structures cannot be trashed
    Enter-Lock

    Out-Log "Add-Job: $Name"

    try {

        # Save DependsOn
        $Global:DependsOn.Add($Name, {$DependsOn}.Invoke())
        assert($DependsOn.Count -eq $Global:DependsOn[$Name].Count)

        # Add me as dependents of jobs I am required to wait on
        foreach ($i in $DependsOn) {
            $arr = $Global:Dependendents[$i]
            if (-not $arr) {
                $arr = {$Name}.Invoke()
                
            }
            else {
                $arr.Add($Name)
            }
            $Global:Dependendents[$i] = $arr
        }

        $Global:jobs.Add($Name, $Job) | Out-Null
    }
    catch {
        throw
    }
    finally {
        Exit-lock
    }
}

<#
.SYNOPSIS
Add a UseCase to the list of UseCases to run in parallel.  

.DESCRIPTION
Given a Usecase and a list of dependencies we add this Useacase
to the list of parallel usecases.  When all dependencies are met
then this usecase is executed.

.PARAMETER Name
The name of the usecase

.PARAMETER Description
A description of the usecase

.PARAMETER UsecaseBlock
The usecase script block

.PARAMETER DependsOn
A list of usecases this test depends on

.EXAMPLE
Add-UseCase -Name "CreateStorageAccount" -Description "Create a storage account" -DependsOn "CreateAzureStackEnvironment,CreateResourceGroup"

.NOTES

#>
function Add-Usecase {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Description, 

        [parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]$UsecaseBlock,
        
        [parameter(Mandatory = $false, Position = 3)]
        [string[]]$DependsOn = @()
    )

    [ScriptBlock]$script = {
        param(
            [PSCustomObject]$Data
        )
        Invoke-UseCase -Name $Data.Name -Description $Data.Description -UsecaseBlock $Data.UsecaseBlock
    }

    [PSCustomObject]$data = @{
        Name         = $Name
        Description  = $Description
        UsecaseBlock = $UsecaseBlock
    }

    [PSCustomObject]$job = @{
        Name   = $Name
        Script = $script
        Data   = $data
    }

    Add-Job -Name $Name -DependsOn $DependsOn -Job $job | Out-Null
}

<#
.SYNOPSIS
Add an action to the list of parallel work.

.DESCRIPTION
Given an action and a list of dependencies we add this action
to the list of parallel actions.  When all dependencies are met
then this action is executed.

.PARAMETER Name
The name of the action

.PARAMETER ActionBlock
The script block that will be executed

.PARAMETER DependsOn
The list of dependencies for this action.

.EXAMPLE
Add-Action -Name "CreateAzureStackAdminEnvironment" -ActionBlock {
    $asEndpoints = GetAzureStackEndpoints -EnvironmentDomainFQDN $EnvironmentDomainFQDN -ArmEndpoint $AdminArmEndpoint 
    Add-AzureRmEnvironment  -Name ($SvcAdminEnvironmentName) `
    -ActiveDirectoryEndpoint ($asEndpoints.ActiveDirectoryEndpoint) `
    -ActiveDirectoryServiceEndpointResourceId ($asEndpoints.ActiveDirectoryServiceEndpointResourceId) `
    -ResourceManagerEndpoint ($asEndpoints.ResourceManagerEndpoint) `
    -GalleryEndpoint ($asEndpoints.GalleryEndpoint) `
    -GraphEndpoint ($asEndpoints.GraphEndpoint) `
    -GraphAudience ($asEndpoints.GraphEndpoint) `
    -StorageEndpointSuffix ($asEndpoints.StorageEndpointSuffix) `
    -AzureKeyVaultDnsSuffix ($asEndpoints.AzureKeyVaultDnsSuffix) `
    -EnableAdfsAuthentication:$asEndpoints.ActiveDirectoryEndpoint.TrimEnd("/").EndsWith("/adfs", [System.StringComparison]::OrdinalIgnoreCase) `
    -ErrorAction Stop
}

.NOTES
General notes
#>
function Add-Action {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]$ActionBlock,
        
        [parameter(Mandatory = $false, Position = 3)]
        [string[]]$DependsOn = @()
    )

    [ScriptBlock]$script = {
        param(
            [PSCustomObject]$Data
        )
        Invoke-Action -Name $Data.Name -ActionBlock $Data.ActionBlock
    }

    [PSCustomObject]$data = @{
        Name        = $Name
        ActionBlock = $UsecaseBlock
    }

    [PSCustomObject]$job = @{
        Name   = $Name
        Script = $script
        Data   = $data
    }

    Add-Job -Name $Name -DependsOn $DependsOn -Job $job | Out-Null
}

