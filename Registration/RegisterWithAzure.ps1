# Copyright (c) Microsoft Corporation. All rights reserved.
# See LICENSE.txt in the project root for license information.

<#

.SYNOPSIS

This script can be used to register Azure Stack POC with Azure. To run this script, you must have a public Azure subscription of any type.
There must also be an account that is an owner or contributor of the subscription. 

.DESCRIPTION

RegisterToAzure runs local scripts to connect your Azure Stack to Azure. After connecting with Azure, you can test marketplace syndication.

The script will follow four steps:
Configure bridge identity: configures Azure Stack so that it can call to Azure via your Azure subscription
Get registration request: get Azure Stack environment information to create a registration for this azure stack in azure
Register with Azure: uses Azure powershell to create an "Azure Stack Registration" resource on your Azure subscription
Activate Azure Stack: final step in connecting Azure Stack to be able to call out to Azure

.PARAMETER azureSubscriptionId

Azure subscription ID that you want to register your Azure Stack with. This parameter is mandatory.

.PARAMETER azureDirectoryTenantName

Name of your AAD Tenant which your Azure subscription is a part of. This parameter is mandatory.

.PARAMETER azureCredential

Powershell object that contains credential information such as user name and password. If not supplied script will request login via gui

.PARAMETER azureEnvironment

Environment name for use in retrieving tenant details and running several of the activation scripts. Defaults to "AzureCloud".

.PARAMETER enableSyndication

Switch ($true/$false) whether to enable downloading items from the Azure marketplace on this environment. Defaults to $true.

.PARAMETER reportUsage

Switch ($true/$false) whether to enable pushing usage data to Azure on this environment. Defaults to $false.

.EXAMPLE

This script must be run from the Host machine of the POC.
.\RegisterWithAzure.ps1 -azureSubscriptionId "5e0ae55d-0b7a-47a3-afbc-8b372650abd3" -azureDirectoryTenantId "contoso.onmicrosoft.com" -azureAccountId "serviceadmin@contoso.onmicrosoft.com" -azureCredentialPassword "password"


.NOTES
 Ensure that you have an Azure subscription and it is registered for Microsoft.AzureStack namespace in Azure.
 Namespace can be registered with the following command:
 Register-AzureRmResourceProvider -ProviderNamespace 'microsoft.azurestack' 
#>


[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, ParameterSetName="CredentialActivation")]
    [PSCredential] $AzureCredential,

    [Parameter(Mandatory=$false, ParameterSetName="ServicePrincipalActivation",Position=0)]
    [Switch] $UsingServicePrincipal,

    [Parameter(Mandatory=$true, ParameterSetName="ServicePrincipalActivation",Position=1)]
    [String] $CertificatePassword,

    [Parameter(Mandatory=$true, ParameterSetName="ServicePrincipalActivation")]
    [string] $CertFilePath,

    [Parameter(Mandatory=$true, ParameterSetName="ServicePrincipalActivation")]
    [String] $AppId,

    [Parameter(Mandatory=$true)]
    [String] $AzureSubscriptionId,

    [Parameter(Mandatory=$true)]
    [String] $AzureDirectoryTenantName,

    [Parameter(Mandatory=$false)]
    [ValidateSet("AzureCloud", "AzureChinaCloud", "AzureUSGovernment", "AzureGermanCloud")]
    [String] $AzureEnvironment = "AzureCloud",

    [Parameter(Mandatory=$false)]
    [Switch] $EnableSyndication = $true,

    [Parameter(Mandatory=$false)]
    [Switch] $ReportUsage = $false
)

#requires -Module AzureRM.Profile
#requires -Module AzureRM.Resources
#requires -RunAsAdministrator

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$VerbosePreference     = [System.Management.Automation.ActionPreference]::Continue

Import-Module C:\CloudDeployment\ECEngine\EnterpriseCloudEngine.psd1 -Force
Set-Location  C:\CloudDeployment\Setup\Activation\Bridge

#
# Pre-req: Version check
#

$versionInfo = [xml] (Get-Content -Path C:\CloudDeployment\Configuration\Version\version.xml) 
$minVersion  = "1.0.170501.1"
if($versionInfo.Version -lt $minVersion)
{
    Write-Error -Message "Script only applicable for Azure Stack builds $minVersion or later"
}
else
{
    Write-Verbose -Message "Running registration on build $($versionInfo.Version)" -Verbose
}

if ($UsingServicePrincipal)
{
    $password = (ConvertTo-SecureString -String $CertificatePassword -AsPlainText -Force)
    $cert = Import-PfxCertificate -Password $password -FilePath $CertFilePath -CertStoreLocation Cert:\LocalMachine\my -Verbose -ErrorAction Stop
    $clientId = $AppId
}


#
# Obtain refresh token for Azure identity
#

Import-Module C:\CloudDeployment\Setup\Common\AzureADConfiguration.psm1 -ErrorAction Stop
$AzureDirectoryTenantId = Get-TenantIdFromName -azureEnvironment $azureEnvironment -tenantName $azureDirectoryTenantName

if(-not $UsingServicePrincipal){

    if(-not $azureCredential)
    {
        Write-Verbose "Prompt user to enter Azure Credentials to get refresh token"
        $tenantDetails = Get-AzureADTenantDetails -AzureEnvironment $azureEnvironment -AADDirectoryTenantName $azureDirectoryTenantName
    }
    else
    {
        Write-Verbose "Using provided Azure Credentials to get refresh token"
        $tenantDetails = Get-AzureADTenantDetails -AzureEnvironment $azureEnvironment -AADDirectoryTenantName $azureDirectoryTenantName -AADAdminCredential $azureCredential
    }

    $refreshToken = (ConvertTo-SecureString -string $tenantDetails["RefreshToken"] -AsPlainText -Force)
}

#
# Step 1: Configure Bridge identity
#

if ($UsingServicePrincipal)
{
    .\Configure-BridgeIdentity.ps1 -ClientId $clientId -ClientCertThumbprint $cert.Thumbprint -AzureDirectoryTenantName $AzureDirectoryTenantName -AzureEnvironment $AzureEnvironment -ServicePrincipal -Verbose
    Write-Verbose "Configure Bridge identity completed with service principal"
}
else
{
    .\Configure-BridgeIdentity.ps1 -RefreshToken $refreshToken -AzureAccountId $tenantDetails["UserName"] -AzureDirectoryTenantName $azureDirectoryTenantName -AzureEnvironment $azureEnvironment -Verbose
    Write-Verbose "Configure Bridge identity completed with refresh token"
}

#
# Step 2: Create new registration request
#

$bridgeAppConfigFile = "\\SU1FileServer\SU1_Infrastructure_1\ASResourceProvider\Config\AzureBridge.IdentityApplication.Configuration.json"
$registrationOutputFile = "c:\temp\registration.json"

Write-Verbose "Calling New-RegistrationRequest.ps1"
.\New-RegistrationRequest.ps1 -BridgeAppConfigFile $bridgeAppConfigFile -RegistrationRequestOutputFile $registrationOutputFile -Verbose
Write-Verbose "New registration request completed"

#
# Step 3: Register Azure Stack with Azure
#

Disable-AzureRmDataCollection
New-Item -ItemType Directory -Force -Path "C:\temp"
$registrationRequestFile = "c:\temp\registration.json"
$registrationOutputFile = "c:\temp\registrationOutput.json"

$timestamp = [DateTime]::Now.ToString("yyyyMMdd-HHmmss")
$logPath = (New-Item -Path "$env:SystemDrive\CloudDeployment\Logs\" -ItemType Directory -Force).FullName
$logFile = Join-Path -Path $logPath -ChildPath "Register-AzureStack.${timestamp}.txt"
try { Start-Transcript -Path $logFile -Force | Out-String | Write-Verbose -Verbose } catch { Write-Warning -Message $_.Exception.Message }

if ($UsingServicePrincipal)
{
    Login-AzureRmAccount -EnvironmentName $AzureEnvironment -ServicePrincipal -CertificateThumbprint $cert.Thumbprint -ApplicationId $appId  -TenantId $AzureDirectoryTenantId -Verbose

    .\Register-AzureStack.ps1 -BillingModel PayAsYouUse -EnableSyndication -ReportUsage -SubscriptionId $AzureSubscriptionId -AzureAdTenantId $AzureDirectoryTenantId `
        -ClientCert $cert -ClientId $appId  -AzureEnvironmentName $AzureEnvironment -RegistrationRequestFile $registrationRequestFile -RegistrationOutputFile $registrationOutputFile `
        -Location "westcentralus" -ServicePrincipal -Verbose
    Write-Verbose "Register Azure Stack with Azure completed with service principal"
}
else
{
    .\Register-AzureStack.ps1 -BillingModel PayAsYouUse -EnableSyndication -ReportUsage -SubscriptionId $azureSubscriptionId -AzureAdTenantId $AzureDirectoryTenantId `
                                -RefreshToken $refreshToken -AzureAccountId $tenantDetails["UserName"] -AzureEnvironmentName $azureEnvironment -RegistrationRequestFile $registrationRequestFile `
                                -RegistrationOutputFile $registrationOutputFile -Location "westcentralus" -Verbose
    Write-Verbose "Register Azure Stack with Azure completed with refresh token"
}
try { Stop-Transcript -Verbose } catch { Write-Warning "$_" }    

#
# workaround to enable syndication and usage
#

$activationDataFile = "c:\temp\regOutput2.json"
$reg = Get-Content $registrationOutputFile | ConvertFrom-Json

$newProps = @{
    ObjectId          = $reg.properties.ObjectId
    ProvisioningState = $reg.properties.provisioningState
    enablesyndication = $enableSyndication
    reportusage       = $reportUsage
}

$reg.properties = $newProps
$reg | ConvertTo-Json -Depth 4 | Out-File -FilePath $activationDataFile

Write-Verbose "Activation file is at : $activationDataFile"

#
# Step 4: Activate Azure Stack
#
$regResponse = Get-Content -path  $activationDataFile
$bytes = [System.Text.Encoding]::UTF8.GetBytes($regResponse)
$activationCode = [Convert]::ToBase64String($bytes)
$azureResourceManagerEndpoint = (Get-AzureRmEnvironment $AzureEnvironment).ResourceManagerUrl

try
{
    .\Activate-Bridge.ps1 -activationCode $activationCode -AzureResourceManagerEndpoint $azureResourceManagerEndpoint -Verbose
}
catch
{
    $exceptionMessage = $_.Exception.Message

    if($exceptionMessage.Contains("Application is currently being upgraded"))
    {
        Write-Warning "Activate-Bridge: Known issue with redundant service fabric upgrade call" 
    }
    else
    {
        Write-Error -Message "Activate-Bridge: Error : $($_.Exception)"
    }
}

Write-Verbose "Azure Stack activation completed"
