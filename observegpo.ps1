$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.',',DC='))"
$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$Searcher.SearchScope = "Subtree"

$Searcher.filter = "(objectCategory=groupPolicyContainer)"
$result = $Searcher.FindAll()

Write-Host "Total GPOs found: $($result.Count)"
$count = 0

$finalResult = @()

$result | % {
    $observations = @()
    $name = $_.properties.name
    $searcher.Filter = "(&(objectCategory=organizationalUnit)(gplink=*$($name)*))"
    $linkedOUs = $searcher.FindAll()
    
    if ($linkedOUs.Count -gt 0) {
        $linkedOUs | % {
            $observations += "The GPO is linked to OU $($_.properties.distinguishedname)."
        }
    } else {
         $observations += "The GPO is not linked to an OU."
    }

    $path = $_.properties.gpcfilesyspath
    $null = $pathcontents = get-childitem -path $path -recurse
    $pathcontents | % {
        if ($_.psiscontainer){
        
        
        }
        else{
            write-host $_.Extension
            switch ($_.Extension){
                ".ini" {
                    #process and make some conclusion about what it is
                    $observations += "There was an ini file"
                }
                ".pol" {
                    #process and make some conclusion about what it is
                    $observations += "There was a pol file"

                }
                ".inf" {
                    #process and make some conclusion about what it is
                    $observations += "There was an inf file"
                }
                 ".cmtx" {
                    #process and make some conclusion about what it is
                    $observations += "There was a cmtx file"
                }
        
            }

            if($_.Name -eq "GptTmpl")
            {
                #process and make some conclusion about what it is
                $observations += "There was a GptTmpl file"
            }
        }
    }
    
    $out = @{
    displayname = $_.properties.displayname
    name = $_.properties.name
    distinguishedname = $_.properties.distinguishedname
    location = $_.properties.gpcfilesyspath
    whencreated = $_.properties.whencreated
    childitems = $pathcontents.fullname
    observations = $observations
    } 
    
    $finalresult += $out  
}

$finalresult | % {"===GPO===";$_.displayname;"=Observered=";$_.observations;"========="}


    

