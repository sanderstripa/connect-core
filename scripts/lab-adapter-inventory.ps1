# Pure inventory join. Interface indices can be reused by adapters in other
# Windows compartments; only the matching current-stack alias is authoritative.
function Resolve-ConnectedLabAdapters([object[]]$Adapters,[object[]]$Interfaces) {
    foreach($candidate in $Adapters){
        $matches=@($Interfaces | Where-Object { $_.InterfaceIndex -eq $candidate.ifIndex -and $_.InterfaceAlias -eq $candidate.Name })
        if($matches.Count){$candidate}
    }
}
