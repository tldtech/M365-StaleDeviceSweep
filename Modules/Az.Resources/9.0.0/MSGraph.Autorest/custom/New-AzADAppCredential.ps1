
# ----------------------------------------------------------------------------------
#
# Copyright Microsoft Corporation
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------------

<#
.Synopsis
Creates key credentials or password credentials for an application.
.Description
Creates key credentials or password credentials for an application.
.Link
https://learn.microsoft.com/powershell/module/az.resources/new-azadappcredential
#>

function New-AzADAppCredential {
    [OutputType([Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.IMicrosoftGraphKeyCredential], [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.IMicrosoftGraphPasswordCredential])]
    [CmdletBinding(DefaultParameterSetName = 'ApplicationObjectIdWithPasswordParameterSet', PositionalBinding = $false, SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(ParameterSetName = 'ApplicationObjectIdWithPasswordParameterSet', Mandatory, HelpMessage = "The object Id of application.")]
        [Parameter(ParameterSetName = 'ApplicationObjectIdWithCertValueParameterSet', Mandatory, HelpMessage = "The object Id of application.")]
        [Parameter(ParameterSetName = 'ApplicationObjectIdWithKeyCredentialParameterSet', Mandatory, HelpMessage = "The object Id of application.")]
        [Parameter(ParameterSetName = 'ApplicationObjectIdWithPasswordCredentialParameterSet', Mandatory, HelpMessage = "The object Id of application.")]
        [Alias('Id')]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Body')]
        [System.String]
        ${ObjectId},

        [Parameter(ParameterSetName = 'ApplicationIdWithCertValueParameterSet', Mandatory, HelpMessage = "The application Id.")]
        [Parameter(ParameterSetName = 'ApplicationIdWithPasswordParameterSet', Mandatory, HelpMessage = "The application Id.")]
        [Parameter(ParameterSetName = 'ApplicationIdWithKeyCredentialParameterSet', Mandatory, HelpMessage = "The application Id.")]
        [Parameter(ParameterSetName = 'ApplicationIdWithPasswordCredentialParameterSet', Mandatory, HelpMessage = "The application Id.")]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Body')]
        [System.Guid]
        ${ApplicationId},

        [Parameter(ParameterSetName = 'DisplayNameWithPasswordParameterSet', Mandatory, HelpMessage = "The display name of application.")]
        [Parameter(ParameterSetName = 'DisplayNameWithCertValueParameterSet', Mandatory, HelpMessage = "The display name of application.")]
        [Parameter(ParameterSetName = 'DisplayNameWithKeyCredentialParameterSet', Mandatory, HelpMessage = "The display name of application.")]
        [Parameter(ParameterSetName = 'DisplayNameWithPasswordCredentialParameterSet', Mandatory, HelpMessage = "The display name of application.")]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Body')]
        [System.String]
        ${DisplayName},

        [Parameter(ParameterSetName = 'ApplicationObjectWithPasswordParameterSet', Mandatory, ValueFromPipeline, HelpMessage = "The application object, could be used as pipeline input.")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithCertValueParameterSet', Mandatory, ValueFromPipeline, HelpMessage = "The application object, could be used as pipeline input.")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithKeyCredentialParameterSet', Mandatory, ValueFromPipeline, HelpMessage = "The application object, could be used as pipeline input.")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithPasswordCredentialParameterSet', Mandatory, ValueFromPipeline, HelpMessage = "The application object, could be used as pipeline input.")]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.IMicrosoftGraphApplication]
        ${ApplicationObject},

        [Parameter(ParameterSetName = 'ApplicationObjectIdWithCertValueParameterSet', Mandatory, HelpMessage = "The value of the 'asymmetric' credential type. It represents the base 64 encoded certificate.")]
        [Parameter(ParameterSetName = 'ApplicationIdWithCertValueParameterSet', Mandatory, HelpMessage = "The value of the 'asymmetric' credential type. It represents the base 64 encoded certificate.")]
        [Parameter(ParameterSetName = 'DisplayNameWithCertValueParameterSet', Mandatory, HelpMessage = "The value of the 'asymmetric' credential type. It represents the base 64 encoded certificate.")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithCertValueParameterSet', Mandatory, HelpMessage = "The value of the 'asymmetric' credential type. It represents the base 64 encoded certificate.")]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Body')]
        [System.String]
        ${CertValue},

        [Parameter(ParameterSetName = 'ApplicationObjectIdWithKeyCredentialParameterSet', Mandatory, HelpMessage = "key credentials associated with the application.")]
        [Parameter(ParameterSetName = 'ApplicationIdWithKeyCredentialParameterSet', Mandatory, HelpMessage = "key credentials associated with the application.")]
        [Parameter(ParameterSetName = 'DisplayNameWithKeyCredentialParameterSet', Mandatory, HelpMessage = "key credentials associated with the application.")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithKeyCredentialParameterSet', Mandatory, HelpMessage = "key credentials associated with the application.")]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphKeyCredential[]]
        ${KeyCredentials},

        [Parameter(ParameterSetName = 'ApplicationObjectIdWithPasswordCredentialParameterSet', Mandatory, HelpMessage = "Password credentials associated with the application.")]
        [Parameter(ParameterSetName = 'ApplicationIdWithPasswordCredentialParameterSet', Mandatory, HelpMessage = "Password credentials associated with the application.")]
        [Parameter(ParameterSetName = 'DisplayNameWithPasswordCredentialParameterSet', Mandatory, HelpMessage = "Password credentials associated with the application.")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithPasswordCredentialParameterSet', Mandatory, HelpMessage = "Password credentials associated with the application.")]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Body')]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPasswordCredential[]]
        ${PasswordCredentials},

        [Parameter(ParameterSetName = 'ApplicationObjectIdWithCertValueParameterSet', HelpMessage = "The effective start date of the credential usage. The default start date value is today. For an 'asymmetric' type credential, this must be set to on or after the date that the X509 certificate is valid from.")]
        [Parameter(ParameterSetName = 'ApplicationIdWithCertValueParameterSet', HelpMessage = "The effective start date of the credential usage. The default start date value is today. For an 'asymmetric' type credential, this must be set to on or after the date that the X509 certificate is valid from.")]
        [Parameter(ParameterSetName = 'DisplayNameWithCertValueParameterSet', HelpMessage = "The effective start date of the credential usage. The default start date value is today. For an 'asymmetric' type credential, this must be set to on or after the date that the X509 certificate is valid from.")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithCertValueParameterSet', HelpMessage = "The effective start date of the credential usage. The default start date value is today. For an 'asymmetric' type credential, this must be set to on or after the date that the X509 certificate is valid from.")]
        [Parameter(ParameterSetName = 'ApplicationObjectIdWithPasswordParameterSet', HelpMessage = "The effective start date of the credential usage. The default start date value is today. For an 'asymmetric' type credential, this must be set to on or after the date that the X509 certificate is valid from.")]
        [Parameter(ParameterSetName = 'ApplicationIdWithPasswordParameterSet', HelpMessage = "The effective start date of the credential usage. The default start date value is today. For an 'asymmetric' type credential, this must be set to on or after the date that the X509 certificate is valid from.")]
        [Parameter(ParameterSetName = 'DisplayNameWithPasswordParameterSet', HelpMessage = "The effective start date of the credential usage. The default start date value is today. For an 'asymmetric' type credential, this must be set to on or after the date that the X509 certificate is valid from.")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithPasswordParameterSet', HelpMessage = "The effective start date of the credential usage. The default start date value is today. For an 'asymmetric' type credential, this must be set to on or after the date that the X509 certificate is valid from.")]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Body')]
        [System.DateTime]
        ${StartDate},

        [Parameter(ParameterSetName = 'ApplicationObjectIdWithCertValueParameterSet', HelpMessage = "The effective end date of the credential usage. The default end date value is one year from today. For an 'asymmetric' type credential, this must be set to on or before the date that the X509 certificate is valid.")]
        [Parameter(ParameterSetName = 'ApplicationIdWithCertValueParameterSet', HelpMessage = "The effective end date of the credential usage. The default end date value is one year from today. For an 'asymmetric' type credential, this must be set to on or before the date that the X509 certificate is valid.")]
        [Parameter(ParameterSetName = 'DisplayNameWithCertValueParameterSet', HelpMessage = "The effective end date of the credential usage. The default end date value is one year from today. For an 'asymmetric' type credential, this must be set to on or before the date that the X509 certificate is valid.")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithCertValueParameterSet', HelpMessage = "The effective end date of the credential usage. The default end date value is one year from today. For an 'asymmetric' type credential, this must be set to on or before the date that the X509 certificate is valid.")]
        [Parameter(ParameterSetName = 'ApplicationObjectIdWithPasswordParameterSet', HelpMessage = "The effective end date of the credential usage. The default end date value is one year from today. For an 'asymmetric' type credential, this must be set to on or before the date that the X509 certificate is valid.")]
        [Parameter(ParameterSetName = 'ApplicationIdWithPasswordParameterSet', HelpMessage = "The effective end date of the credential usage. The default end date value is one year from today. For an 'asymmetric' type credential, this must be set to on or before the date that the X509 certificate is valid.")]
        [Parameter(ParameterSetName = 'DisplayNameWithPasswordParameterSet', HelpMessage = "The effective end date of the credential usage. The default end date value is one year from today. For an 'asymmetric' type credential, this must be set to on or before the date that the X509 certificate is valid.")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithPasswordParameterSet', HelpMessage = "The effective end date of the credential usage. The default end date value is one year from today. For an 'asymmetric' type credential, this must be set to on or before the date that the X509 certificate is valid.")]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Body')]
        [System.DateTime]
        ${EndDate},

        [Parameter(ParameterSetName = 'ApplicationObjectIdWithCertValueParameterSet', HelpMessage = "Custom Key Identifier. The format should be base64: ```$Bytes=[System.Text.Encoding]::Unicode.GetBytes(`$key);`$key=[Convert]::ToBase64String(`$Bytes)``")]
        [Parameter(ParameterSetName = 'ApplicationIdWithCertValueParameterSet', HelpMessage = "Custom Key Identifier. The format should be base64: ```$Bytes=[System.Text.Encoding]::Unicode.GetBytes(`$key);`$key=[Convert]::ToBase64String(`$Bytes)``")]
        [Parameter(ParameterSetName = 'DisplayNameWithCertValueParameterSet', HelpMessage = "Custom Key Identifier. The format should be base64: ```$Bytes=[System.Text.Encoding]::Unicode.GetBytes(`$key);`$key=[Convert]::ToBase64String(`$Bytes)``")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithCertValueParameterSet', HelpMessage = "Custom Key Identifier. The format should be base64: ```$Bytes=[System.Text.Encoding]::Unicode.GetBytes(`$key);`$key=[Convert]::ToBase64String(`$Bytes)``")]
        [Parameter(ParameterSetName = 'ApplicationObjectIdWithPasswordParameterSet', HelpMessage = "Custom Key Identifier. The format should be base64: ```$Bytes=[System.Text.Encoding]::Unicode.GetBytes(`$key);`$key=[Convert]::ToBase64String(`$Bytes)``")]
        [Parameter(ParameterSetName = 'ApplicationIdWithPasswordParameterSet', HelpMessage = "Custom Key Identifier. The format should be base64: ```$Bytes=[System.Text.Encoding]::Unicode.GetBytes(`$key);`$key=[Convert]::ToBase64String(`$Bytes)``")]
        [Parameter(ParameterSetName = 'DisplayNameWithPasswordParameterSet', HelpMessage = "Custom Key Identifier. The format should be base64: ```$Bytes=[System.Text.Encoding]::Unicode.GetBytes(`$key);`$key=[Convert]::ToBase64String(`$Bytes)``")]
        [Parameter(ParameterSetName = 'ApplicationObjectWithPasswordParameterSet', HelpMessage = "Custom Key Identifier. The format should be base64: ```$Bytes=[System.Text.Encoding]::Unicode.GetBytes(`$key);`$key=[Convert]::ToBase64String(`$Bytes)``")]
        [Parameter(HelpMessage = "Custom Key Identifier. The format should be base64: ```$Bytes=[System.Text.Encoding]::Unicode.GetBytes(`$key);`$key=[Convert]::ToBase64String(`$Bytes)``")]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Body')]
        [System.String]
        ${CustomKeyIdentifier},

        [Parameter()]
        [Alias("AzContext", "AzureRmContext", "AzureCredential")]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Azure')]
        [System.Management.Automation.PSObject]
        # The credentials, account, tenant, and subscription used for communication with Azure.
        ${DefaultProfile},
    
        [Parameter(DontShow)]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        # Wait for .NET debugger to attach
        ${Break},
    
        [Parameter(DontShow)]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Runtime')]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Runtime.SendAsyncStep[]]
        # SendAsync Pipeline Steps to be appended to the front of the pipeline
        ${HttpPipelineAppend},
    
        [Parameter(DontShow)]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Runtime')]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Runtime.SendAsyncStep[]]
        # SendAsync Pipeline Steps to be prepended to the front of the pipeline
        ${HttpPipelinePrepend},
    
        [Parameter(DontShow)]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Runtime')]
        [System.Uri]
        # The URI for the proxy server to use
        ${Proxy},
    
        [Parameter(DontShow)]
        [ValidateNotNull()]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Runtime')]
        [System.Management.Automation.PSCredential]
        # Credentials for a proxy server to use for the remote call
        ${ProxyCredential},
    
        [Parameter(DontShow)]
        [Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Category('Runtime')]
        [System.Management.Automation.SwitchParameter]
        # Use the default credentials for the proxy
        ${ProxyUseDefaultCredentials}
    )
    
    process {
        if (!$PSBoundParameters['PasswordCredentials'] -and !$PSBoundParameters['KeyCredentials'] ) {
            if ($PSBoundParameters['CertValue']) {
                $credential = New-Object -TypeName "Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphKeyCredential" `
                                         -Property @{'Key' = ([System.Convert]::FromBase64String($PSBoundParameters['CertValue']));
                                            'Usage'       = 'Verify'; 
                                            'Type'        = 'AsymmetricX509Cert'
                                         }
            } else {
                $credential = New-Object -TypeName "Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphPasswordCredential"
            }
            if ($PSBoundParameters['CustomKeyIdentifier']) {
                $credential.CustomKeyIdentifier = [System.Convert]::FromBase64String($PSBoundParameters['CustomKeyIdentifier'])
                $null = $PSBoundParameters.Remove('CustomKeyIdentifier')
            }
            if ($PSBoundParameters['StartDate']) {
                $credential.StartDateTime = $PSBoundParameters['StartDate']
                $null = $PSBoundParameters.Remove('StartDate')
            }
            if ($PSBoundParameters['EndDate']) {
                $credential.EndDateTime = $PSBoundParameters['EndDate']
                $null = $PSBoundParameters.Remove('EndDate')
            }
            $credential.KeyId = (New-Guid).ToString()
            if ($PSBoundParameters['CertValue']) {
                $kc = $credential
                $null = $PSBoundParameters.Remove('CertValue')
            } else {
                $pc = $credential
            }
        } elseif ($PSBoundParameters['PasswordCredentials']) {
            $pc = $PSBoundParameters['PasswordCredentials']
            $null = $PSBoundParameters.Remove('PasswordCredentials')
        } else {
            $kc = $PSBoundParameters['KeyCredentials']
            $null = $PSBoundParameters.Remove('KeyCredentials')
        }

        $param = @{}
        switch ($PSCmdlet.ParameterSetName) {
            { $_ -in 'ApplicationObjectIdWithPasswordParameterSet', 'ApplicationObjectIdWithKeyCredentialParameterSet', 'ApplicationObjectIdWithPasswordCredentialParameterSet', 'ApplicationObjectIdWithCertValueParameterSet'} {
                $id = $PSBoundParameters['ObjectId']
                if ($kc) {
                    $app = Get-AzADApplication -ObjectId $id
                }
                $null = $PSBoundParameters.Remove('ObjectId')
                break
            }
            { $_ -in 'ApplicationIdWithPasswordParameterSet', 'ApplicationIdWithKeyCredentialParameterSet', 'ApplicationIdWithPasswordCredentialParameterSet', 'ApplicationIdWithCertValueParameterSet'} {
                $param['ApplicationId'] = $PSBoundParameters['ApplicationId']
                $app = Get-AzADApplication @param
                if ($app) {
                    $id = $app.Id
                    $null = $PSBoundParameters.Remove('ApplicationId')  
                }
                else {
                    Write-Error "application with application id '$($PSBoundParameters['ApplicationId'])' does not exist."
                    return
                }
                break
            }
            { $_ -in 'DisplayNameWithPasswordParameterSet', 'DisplayNameWithKeyCredentialParameterSet', 'DisplayNameWithPasswordCredentialParameterSet', 'DisplayNameWithCertValueParameterSet'} {
                $param['DisplayName'] = $PSBoundParameters['DisplayName']
                [System.Array]$app = Get-AzADApplication @param
                if (0 -eq $app.Count) {
                    Write-Error "application with display name '$($PSBoundParameters['DisPlayName'])' does not exist."
                    return
                }
                elseif (1 -eq $app.Count) {
                    $id = $app[0].Id
                    $null = $PSBoundParameters.Remove('DisplayName')
                }
                else {
                    Write-Error "More than one application found with display name '$($PSBoundParameters['DisplayName'])'. Please use the Get-AzADApplication cmdlet to get the object id of the desired application."
                    return
                }
                break
            }
            { $_ -in 'ApplicationObjectWithPasswordParameterSet', 'ApplicationObjectWithKeyCredentialParameterSet', 'ApplicationObjectWithPasswordCredentialParameterSet', 'ApplicationObjectWithCertValueParameterSet'} {
                $id = $PSBoundParameters['ApplicationObject'].Id
                if ($kc) {
                    $app = Get-AzADApplication -ObjectId $id
                }
                $null = $PSBoundParameters.Remove('ApplicationObject')
                break
            }
            default {
                break
            }
        }  
        if ($pc) {
            $PSBoundParameters['ApplicationId'] = $id
            foreach ($credential in $pc) {
                $PSBoundParameters['PasswordCredential'] = $credential
                Az.MSGraph.internal\Add-AzADApplicationPassword @PSBoundParameters
            }
            $null = $PSBoundParameters.Remove('ApplicationId')
            if ($PSBoundParameters['PasswordCredential']) {
                $null = $PSBoundParameters.Remove('PasswordCredential')
            }
        }
        if ($kc) {
            [System.Array]$kcList = $app.KeyCredentials
            $PSBoundParameters['Id'] = $id
            foreach ($k in $kc) {
                $kcList += $k
            }
            $PSBoundParameters['KeyCredentials'] = $kcList
            Az.MSGraph.internal\Update-AzADApplication @PSBoundParameters
        }
    }
}
# SIG # Begin signature block
# MIIoLAYJKoZIhvcNAQcCoIIoHTCCKBkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB2j1DcN+UgXgfI
# yUjF68F71xHiVsbalZnP8WhiRAaimaCCDXYwggX0MIID3KADAgECAhMzAAAEhV6Z
# 7A5ZL83XAAAAAASFMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjUwNjE5MTgyMTM3WhcNMjYwNjE3MTgyMTM3WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDASkh1cpvuUqfbqxele7LCSHEamVNBfFE4uY1FkGsAdUF/vnjpE1dnAD9vMOqy
# 5ZO49ILhP4jiP/P2Pn9ao+5TDtKmcQ+pZdzbG7t43yRXJC3nXvTGQroodPi9USQi
# 9rI+0gwuXRKBII7L+k3kMkKLmFrsWUjzgXVCLYa6ZH7BCALAcJWZTwWPoiT4HpqQ
# hJcYLB7pfetAVCeBEVZD8itKQ6QA5/LQR+9X6dlSj4Vxta4JnpxvgSrkjXCz+tlJ
# 67ABZ551lw23RWU1uyfgCfEFhBfiyPR2WSjskPl9ap6qrf8fNQ1sGYun2p4JdXxe
# UAKf1hVa/3TQXjvPTiRXCnJPAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUuCZyGiCuLYE0aU7j5TFqY05kko0w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwNTM1OTAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBACjmqAp2Ci4sTHZci+qk
# tEAKsFk5HNVGKyWR2rFGXsd7cggZ04H5U4SV0fAL6fOE9dLvt4I7HBHLhpGdE5Uj
# Ly4NxLTG2bDAkeAVmxmd2uKWVGKym1aarDxXfv3GCN4mRX+Pn4c+py3S/6Kkt5eS
# DAIIsrzKw3Kh2SW1hCwXX/k1v4b+NH1Fjl+i/xPJspXCFuZB4aC5FLT5fgbRKqns
# WeAdn8DsrYQhT3QXLt6Nv3/dMzv7G/Cdpbdcoul8FYl+t3dmXM+SIClC3l2ae0wO
# lNrQ42yQEycuPU5OoqLT85jsZ7+4CaScfFINlO7l7Y7r/xauqHbSPQ1r3oIC+e71
# 5s2G3ClZa3y99aYx2lnXYe1srcrIx8NAXTViiypXVn9ZGmEkfNcfDiqGQwkml5z9
# nm3pWiBZ69adaBBbAFEjyJG4y0a76bel/4sDCVvaZzLM3TFbxVO9BQrjZRtbJZbk
# C3XArpLqZSfx53SuYdddxPX8pvcqFuEu8wcUeD05t9xNbJ4TtdAECJlEi0vvBxlm
# M5tzFXy2qZeqPMXHSQYqPgZ9jvScZ6NwznFD0+33kbzyhOSz/WuGbAu4cHZG8gKn
# lQVT4uA2Diex9DMs2WHiokNknYlLoUeWXW1QrJLpqO82TLyKTbBM/oZHAdIc0kzo
# STro9b3+vjn2809D0+SOOCVZMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGgwwghoIAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAASFXpnsDlkvzdcAAAAABIUwDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKxyMTM28pWGEUM8lucc2GnW
# sex13uYauP7zpbF5QKM4MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAfDMfNNKoYNPeFjdTZW7GoYmNqhp6BjSZgpyK3IS9o89q9ITPCN7U0YHA
# Xix6EglQc9YL4X2BszJhwf+vt2i2W5FFTWifjidhV7hwOIsepa1cVN9vUlGe/BAC
# sSDLVvFV9pTk7Q+kozkJF/DTBq3zgx4D9kFWv4GCCPKidLDbuDhLFaGh4mrKoImT
# cEs06LbXI/trLQq/QrYrtZYwJHeAaYDfKhFXgmK5F8gGOO+ko42aZ3itULDHssNN
# lm1gJZqQ1xs15kmCOCmsZn205ihTR+/LpmpscCk/JPeQ39py9hNZNpXB4FcP1OMJ
# tAS1+psMRcXyyae3YFA1qzUoaUVrHqGCF5YwgheSBgorBgEEAYI3AwMBMYIXgjCC
# F34GCSqGSIb3DQEHAqCCF28wghdrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCAAyoy4IiMVPl8VXYCSAunRRotpaGZlh6kwHF5AQdQW/AIGaPCDMUMv
# GBIyMDI1MTExMTAyNTg0NC41M1owBIACAfSggdGkgc4wgcsxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVy
# aWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjozNzAzLTA1
# RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# Ee0wggcgMIIFCKADAgECAhMzAAACCkeyFNnusrMPAAEAAAIKMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI1MDEzMDE5NDI1
# N1oXDTI2MDQyMjE5NDI1N1owgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjozNzAzLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBALLs3PASlvsGnACT0snTRerfRNxONzA1nzRPEC0BuFJo
# naTCckDUC78Oj398QGMAe/oya23d+Y8N4gmdDtUF4irxFx+NyOts8iDfADm/kxB+
# U81IE069xdE/59mcDLQQsPN+ckecKRk2xBRnsYXsvFQtMo5hjZgnDhOuZweiGRjo
# OMJnLGGqYZDDB1uOg9ZFti7+jMV6b/J8k/KNUGqXXTrxtxWHnwDxzkIPpNY38ve7
# 43L7s7z4O96vqoFPjgTLul89kxnUeLvK8Iu/ksbNIHqjY4PkYhnLvPiSHxRgd3OO
# f1bH5BnbbfdIlAq1mGkju4d/egxODTNqdB/PuaC515+YYGtASDWjHef7dOLOHQP3
# NWY1A/2wWOw9C00Zn0gP0fwD6QUifHiatLEDZLIYw5BzGUYzfSS0gozeKoK4URT0
# IdUyk33j/V+XhPo+icn7+hYmoWVq1i4wq/Zny6KmucVwDEKk6wMhUE70rW8d4AyJ
# BBSVwT0IPnfojVgueY7aodqA8+ZeF04asdScJS2inbV6W6QeHvmr/nMf46c16Snm
# 52mNA1kK+JgBl0ewueRTQ19QCvqvVSoNxKrXJ/lGLCKYHxKOx2YeWXiA+OapWLT+
# uaczWgARCbc/JZxNBCJtguK4o3tjiKjlslNXCb69FFuknlQv8PfcL//uqcdt6hYF
# AgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUAq8XQQSPgDI99jxb+quwC9+1nCQwHwYD
# VR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZO
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBc
# BggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0
# cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMC
# B4AwDQYJKoZIhvcNAQELBQADggIBALCTc9bQLKM5qpcIw66xN17t6nYLA//FXUne
# j0oCIpJ2rxrZRHlEIdiGcmx56bB4xQfaQ15+mcCHYGfwfaikPO0MmSPw5hF38pDK
# wTXY3Bpjco7ABbxGDw51e/l9Rkiw5aCmuQJAzRWgUd1dgTGQk3cTMFtQJTDfJviA
# AU8rnpP7pw+kjwwkskJBcc0yC2LZBmFf0qR9EB98VgwVymxsj6jOILkGuuTffrVw
# kUeGAQlHQnjaeplMZKBSkMYdJkBEao1wBXmH45AMt4XandRHH8/oxxSDWcnaAw9g
# GwP5vB30HRz9chn0y3e6OUQs+mSKOMJ1JnGHO7YzdJlYmvnu5j4UL4uym8g4fU6m
# h9qeHckYOiw1wAS73JQxYqwQEyeAPpVZBJBhnpf0XzTMKh5nBOrSL0C6OdjPPHlb
# Z8SBl6NG7orUYIBKbO02VgmUAKOpp9ZGh9OqQmFX8na/3tfeu4O9+m465ChS1UDB
# esOwbY04G69Wyjkp1bniEFKzP/j45EHiouerj8Y21qNQeispEocY6AWjwMppcb5Q
# 0A3CEY3EdsgtJrn0/ETEyAKMFE/fzbzIYqyq5ITPMs1afPlp/1mZ4fjzT1/Ai20j
# jUmS6Jj1fqGYyYti/w5jfi+84r7PLGRL70FQtUA/qC37JodoGWuWfwaLj90GvbLp
# Kuv/nqDQMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG
# 9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEy
# MDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIw
# MTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az
# /1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V2
# 9YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oa
# ezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkN
# yjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7K
# MtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRf
# NN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SU
# HDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoY
# WmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5
# C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8
# FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TAS
# BgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1
# Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUw
# UzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIB
# hjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fO
# mhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9w
# a2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggr
# BgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3
# DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEz
# tTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJW
# AAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G
# 82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/Aye
# ixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI9
# 5ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1j
# dEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZ
# KCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xB
# Zj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuP
# Ntq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvp
# e784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCA1Aw
# ggI4AgEBMIH5oYHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScw
# JQYDVQQLEx5uU2hpZWxkIFRTUyBFU046MzcwMy0wNUUwLUQ5NDcxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVANEA
# xUmUDpsqr3dWe7dSQmCbkeVhoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwDQYJKoZIhvcNAQELBQACBQDsvJydMCIYDzIwMjUxMTEwMTcxNzE3
# WhgPMjAyNTExMTExNzE3MTdaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOy8nJ0C
# AQAwCgIBAAICF/oCAf8wBwIBAAICEmswCgIFAOy97h0CAQAwNgYKKwYBBAGEWQoE
# AjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkq
# hkiG9w0BAQsFAAOCAQEAjeBPIY37kuSAZjhDEzQvu0kMd9xWQbfcX/K7e3GuIOVL
# xA2VLNhGQsfRm4uJuBrw5PclYd+Q6j4D+8TiIgsmaHlnptcWXtISWbNa3ehM/Mht
# btjsNm1YMYgiZQRWSfhrkEownHSn+bONi5uRx9RAzGLS1TnChj9bKTq8QYeeroJj
# Qxl3Qp/NLzSFRF5ZPgatiKsky4ZrL5yRrIhaMvnmtUjuKY+Rti1PqyiAkYlsSnwl
# 3viD0D4DqRdRRl3vMa7Iv+xY6WFoT1g/Mw0KegNgJphrFx40DARL/i8mQsQr3Wd6
# CdtwFvcT8jbAqxQcpWWKL1FuqdgyAs9Dk66v+11s+DGCBA0wggQJAgEBMIGTMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAACCkeyFNnusrMPAAEAAAIK
# MA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# LwYJKoZIhvcNAQkEMSIEIN8APDmFJ7EFK2dtmvr1OqZBhBrOMePVvrvHptOdQwsx
# MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgTZrL/LR6kr9fdnTcpNyWioTy
# 70hdG107sx7HSHD35JowgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAgpHshTZ7rKzDwABAAACCjAiBCBH8Q2r++7Me/J6RvKqLeSxesHO
# hHpBcwamZNRR0YjkJzANBgkqhkiG9w0BAQsFAASCAgAD0FCB4yXoMdd7mvrtT8Ze
# XZd5sQee2SrtbfCqtSJtHs1TjbfEAZVhKfP/ZaAs0XwmVRBBWOcUbejSlql11uFn
# MxN5zYt39Sf02kX6J3qU01DsMtjIzhKGu/Ot9aksUB7BhLmQ3J3ENN2mVMri0IfP
# rK++hdbRkVbwtXQ+uIZaKGnI1USHCMHp7D7jDL4rM/LJ99F14kHKcrqRWhj1Ix5O
# PuXMaGPFNDIUyyLNYPOIe6dle/vSakYGJXbug3hn5xNvUN9kBadkQxu0LDGv2eG+
# b0/yNxLk5HKXGK5hKGtLhjx2aJotaV6Emm0gzb9+p5y71jfUeBpv8heZwBycXGsP
# 3wU6S3Pxi/SEHf2rmKkVxrCDXSa1lGlPvFrxpYbvkthF9l7bQn0m9RZnDTj059Qu
# C/Zkjh5KSPJJIM2ul8SDPoW/D9vQ/y1k6pmGLneLWUpx4CZztQ1uiPMPVdO02pW9
# OnxIBPRL+/JCpEfNk+d1k88l16+L7kfsayd80TinqE2f3VDiXT3QtYip1ypX63pZ
# GLXg4R7nPdHIboA0vx/cXRtKsysYAErtvuS9Up6XwUO/ijPgV8+uBYGDcyeIWDnJ
# ytx/rulqEcf/mCTXHeFWlcXNBUUW1s+Jg2ROrOkYUdY5nwwTesDKEs1DWYT0KxVu
# Mrp0tFsAwGUtvFYHj7jr8A==
# SIG # End signature block
