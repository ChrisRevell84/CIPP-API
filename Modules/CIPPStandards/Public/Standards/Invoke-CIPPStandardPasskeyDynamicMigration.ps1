function Invoke-CIPPStandardPasskeyDynamicMigration {

<#
.FUNCTIONALITY
Internal

.COMPONENT
(APIName) PasskeyDynamicMigration

.SYNOPSIS
(Label) Microsoft Automatic Passkey Migration

.DESCRIPTION
(Helptext) Controls Microsoft's temporary automatic passkey migration. Select Temporarily opt out while planning a managed rollout, or Allow Microsoft migration when the tenant is ready.

(DocsDescription) Configures optOutSettings.passkeyDynamicMigration in the Microsoft Entra authentication methods policy.

.NOTES

CAT
Entra (AAD) Standards

TAG

EXECUTIVETEXT
Controls Microsoft's automatic passkey migration so the organisation can follow a planned passkey deployment rather than relying on Microsoft's automatic rollout.

ADDEDCOMPONENT
{"type":"autoComplete","multiple":false,"creatable":false,"required":true,"label":"Microsoft Automatic Passkey Migration","name":"standards.PasskeyDynamicMigration.state","options":[{"label":"Temporarily opt out","value":"optout"},{"label":"Allow Microsoft migration","value":"allow"}]}

IMPACT
Medium Impact

ADDEDDATE
2026-08-25

POWERSHELLEQUIVALENT
Graph API: PATCH /beta/policies/authenticationMethodsPolicy

RECOMMENDEDBY

UPDATECOMMENTBLOCK
Run the Tools\Update-StandardsComments.ps1 script to update this comment block

.LINK
https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sms-voice-retirement

#>

    param(
        $Tenant,
        $Settings
    )

    $SelectedState = if ($Settings.state.value) {
        $Settings.state.value
    }
    else {
        $Settings.state
    }

    if ([string]::IsNullOrWhiteSpace($SelectedState)) {

        Write-LogMessage `
            -API 'Standards' `
            -Tenant $Tenant `
            -Message 'PasskeyDynamicMigration: No state configured.' `
            -Sev Info

        return
    }

    $DesiredValue = switch ($SelectedState) {

        'optout' {
            $true
        }

        'allow' {
            $false
        }

        default {

            Write-LogMessage `
                -API 'Standards' `
                -Tenant $Tenant `
                -Message "PasskeyDynamicMigration: Invalid state '$SelectedState'." `
                -Sev Error

            return
        }
    }

    $GraphUri =
        'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy'

    try {

        # -----------------------------------------------------
        # GET CURRENT STATE
        # -----------------------------------------------------

        $CurrentPolicy =
            New-GraphGetRequest `
                -Uri $GraphUri `
                -TenantId $Tenant `
                -SkipValueExtraction

    }
    catch {

        $ErrorMessage =
            Get-NormalizedError `
                -Message $_.Exception.Message

        Write-LogMessage `
            -API 'Standards' `
            -Tenant $Tenant `
            -Message "Could not retrieve PasskeyDynamicMigration state. Error: $ErrorMessage" `
            -Sev Error

        return
    }

    if ($null -eq $CurrentPolicy.optOutSettings) {

        $CurrentValue =
            $null
    }
    else {

        $CurrentValue =
            $CurrentPolicy.
            optOutSettings.
            passkeyDynamicMigration
    }

    $IsCompliant =
        $null -ne $CurrentValue -and
        $CurrentValue -eq $DesiredValue


    # ---------------------------------------------------------
    # REMEDIATE
    # ---------------------------------------------------------

    if ($Settings.remediate -eq $true) {

        if ($IsCompliant) {

            Write-LogMessage `
                -API 'Standards' `
                -Tenant $Tenant `
                -Message "PasskeyDynamicMigration already configured as $DesiredValue." `
                -Sev Info
        }
        else {

            try {

                $Body = @{
                    optOutSettings = @{
                        passkeyDynamicMigration =
                            $DesiredValue
                    }
                } |
                ConvertTo-Json -Depth 5 -Compress


                $null =
                    New-GraphPostRequest `
                        -TenantId $Tenant `
                        -Uri $GraphUri `
                        -Type patch `
                        -Body $Body `
                        -ContentType 'application/json'


                Write-LogMessage `
                    -API 'Standards' `
                    -Tenant $Tenant `
                    -Message "PasskeyDynamicMigration set to $DesiredValue." `
                    -Sev Info


                # -------------------------------------------------
                # VERIFY
                # -------------------------------------------------

                $Verify =
                    New-GraphGetRequest `
                        -Uri $GraphUri `
                        -TenantId $Tenant `
                        -SkipValueExtraction


                $VerifiedValue =
                    $Verify.
                    optOutSettings.
                    passkeyDynamicMigration


                $IsCompliant =
                    $VerifiedValue -eq $DesiredValue


                if (-not $IsCompliant) {

                    Write-LogMessage `
                        -API 'Standards' `
                        -Tenant $Tenant `
                        -Message "PasskeyDynamicMigration verification failed. Expected: $DesiredValue Received: $VerifiedValue" `
                        -Sev Error
                }

            }
            catch {

                $ErrorMessage =
                    Get-NormalizedError `
                        -Message $_.Exception.Message

                Write-LogMessage `
                    -API 'Standards' `
                    -Tenant $Tenant `
                    -Message "Could not set PasskeyDynamicMigration. Error: $ErrorMessage" `
                    -Sev Error
            }
        }
    }


    # ---------------------------------------------------------
    # ALERT
    # ---------------------------------------------------------

    if (
        $Settings.alert -eq $true -and
        -not $IsCompliant
    ) {

        $CurrentDisplay =
            if ($null -eq $CurrentValue) {
                'Not configured'
            }
            else {
                [string]$CurrentValue
            }


        $AlertObject = [PSCustomObject]@{
            Current =
                $CurrentDisplay

            Expected =
                [string]$DesiredValue
        }


        Write-StandardsAlert `
            -Message 'Microsoft Automatic Passkey Migration is not configured as required.' `
            -Object $AlertObject `
            -Tenant $Tenant `
            -StandardName 'PasskeyDynamicMigration' `
            -StandardId $Settings.standardId
    }


    # ---------------------------------------------------------
    # REPORT
    # ---------------------------------------------------------

    if ($Settings.report -eq $true) {

        $CurrentDisplay =
            if ($null -eq $CurrentValue) {
                'NotConfigured'
            }
            else {
                [string]$CurrentValue
            }


        Set-CIPPStandardsCompareField `
            -FieldName 'standards.PasskeyDynamicMigration' `
            -FieldValue $CurrentDisplay `
            -Tenant $Tenant


        Add-CIPPBPAField `
            -FieldName 'PasskeyDynamicMigration' `
            -FieldValue ([bool]$IsCompliant) `
            -StoreAs bool `
            -Tenant $Tenant
    }
}
