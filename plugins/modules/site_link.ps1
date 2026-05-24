#!powershell

# Copyright (c) 2026, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'cost'
            Option = @{ type = 'int' }
            Attribute = 'Cost'
        }
        [PSCustomObject]@{
            Name = 'replication_frequency'
            Option = @{ type = 'int' }
            Attribute = 'ReplicationFrequencyInMinutes'
        }
        [PSCustomObject]@{
            Name = 'sites_included'
            Option = @{ type = 'list'; elements = 'str' }
            Attribute = 'SitesIncluded'
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                $desired = $Module.Params.sites_included
                $currentDNs = @($ADObject.SitesIncluded)
                $currentNames = @($currentDNs | ForEach-Object {
                        $_ -replace '^CN=([^,]+),.*$', '$1'
                    } | Sort-Object)
                $desiredSorted = @($desired | Sort-Object)

                $Module.Diff.before['sites_included'] = $currentNames
                $Module.Diff.after['sites_included'] = $desiredSorted

                $diff = Compare-Object -ReferenceObject $currentNames -DifferenceObject $desiredSorted
                if ($diff) {
                    $siteChanges = @{}
                    $toAdd = @($diff | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object { $_.InputObject })
                    $toRemove = @($diff | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { $_.InputObject })
                    if ($toAdd.Count) { $siteChanges['Add'] = $toAdd }
                    if ($toRemove.Count) { $siteChanges['Remove'] = $toRemove }
                    $SetParams.SitesIncluded = $siteChanges
                }
            }
        }
        [PSCustomObject]@{
            Name = 'intersite_transport_protocol'
            Option = @{
                type = 'str'
                choices = 'IP', 'SMTP'
                default = 'IP'
            }
            Attribute = 'InterSiteTransportProtocol'
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                $transportMap = @{
                    0 = 'IP'
                    1 = 'SMTP'
                }
                $current = $transportMap[[int]$ADObject.InterSiteTransportProtocol]
                $desired = $Module.Params.intersite_transport_protocol

                $Module.Diff.before['intersite_transport_protocol'] = $current
                $Module.Diff.after['intersite_transport_protocol'] = $current

                if ($current -ne $desired) {
                    $Module.Warn("intersite_transport_protocol cannot be changed after creation (current: $current, requested: $desired)")
                }
            }
        }
    )
    ModuleNoun = 'ADReplicationSiteLink'
    DefaultPath = {
        param($Module, $Params)

        $configNC = (Get-ADRootDSE @Params -Properties configurationNamingContext).configurationNamingContext
        $protocol = if ($Module.Params.intersite_transport_protocol) {
            $Module.Params.intersite_transport_protocol
        }
        else { 'IP' }
        "CN=$protocol,CN=Inter-Site Transports,CN=Sites,$configNC"
    }
}
Invoke-AnsibleADObject @setParams
