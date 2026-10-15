$ErrorActionPreference='Stop'
. "$PSScriptRoot/lab-adapter-inventory.ps1"
$adapters=@(
    [pscustomobject]@{Name='vEthernet (nat)';ifIndex=10},
    [pscustomobject]@{Name='Ethernet 4';ifIndex=10},
    [pscustomobject]@{Name='ccipvm';ifIndex=22}
)
$interfaces=@(
    [pscustomobject]@{InterfaceAlias='vEthernet (nat)';InterfaceIndex=10},
    [pscustomobject]@{InterfaceAlias='vEthernet (nat)';InterfaceIndex=10},
    [pscustomobject]@{InterfaceAlias='ccipvm';InterfaceIndex=22}
)
$visible=@(Resolve-ConnectedLabAdapters $adapters $interfaces)
if($visible.Count -ne 2 -or $visible[0].Name -ne 'vEthernet (nat)' -or $visible[1].Name -ne 'ccipvm'){throw 'A reused index selected an unrelated adapter'}
$mismatch=@(Resolve-ConnectedLabAdapters $adapters @([pscustomobject]@{InterfaceAlias='vEthernet (nat)';InterfaceIndex=99}))
if($mismatch.Count){throw 'An index/alias mismatch was adopted'}
'Compartment index collision regression passed without network changes'
