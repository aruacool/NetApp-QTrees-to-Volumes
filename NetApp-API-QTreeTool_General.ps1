<# Nadav's Tool to transfer QTrees into Volumes 05/06/2024
 To DO:
 1) Transfer ACLs with robocopy
 2) Look at worst case scenarios
 3) Check NetApp python script
 4) Copy export policy
 5) Log all QTree Objects, and also all QTrees handled. + all steps in the conversion
 6) Add Symlinks from old path to the new one
 7) Create rollback mechanism
 8) Change the flow, create a new volume, copy everything to it (with robocopy or w/e), rename the QTree, change the junction, and delete the QTree

 Done List:
 1 - DONE
 2 - Tested most cases
 3 - DONE
 4 - No Need - NO NFS
 5 - DONE
 6 - DONE
 7 - DONE - some data loss on testing


 \\testsvm\testqtree
 GONNA TEST ON THIS
#>

# commvault API key
$global:APIKey = "apikey"
$global:logPath = "pathforlog\log.json"
$global:logOpenFiles = "pathforopensessions\OpenSessions"
$global:timeOut = 30 # Times out checking for updates once an important API call was made

# fucntion to Test if the credentials of an ADUser are correct for Initialize-Creds
function Test-ADUser
{
    param(
        $creds
    )

    try{
        $test = get-aduser "knownexistinguser" -Credential $creds
        return $true
    }
    catch
    {
        return $false
    }
}

# function to add your credentials to NetApp for usage in the API
function Initialize-Creds
{
    $credsPath = "$env:userprofile\Documents\Scripts\Create-Share-credentials.xml"
    if((Test-Path -Path $credsPath -PathType Leaf) -and (Test-ADUser (Import-Clixml $credsPath)) )
    {
        $global:creds = (Import-Clixml $credsPath)
    }
    else
    {
        $directory = Split-Path $credsPath
        if( -not (Test-Path $directory -PathType Container)){
            New-Item -ItemType Directory -Force -Path $directory | Out-Null
        }
       $credentials = Get-Credential
       $credentials | Export-Clixml $credsPath -force
       $global:creds = (Import-Clixml $credsPath)
    }
}

function Get-QTrees
{
    return (Send-Netapp -apiPath "http://netapp-node/api/storage/qtrees?name=*&fields=*" -queryType "GET").records
}

function Get-QTree
{
    param(
        $VolumeUUID,
        $QTreeName,
		$QTreeID = $null
    )
	
	if($QTreeID -ne $null)
	{
		return (Send-NetApp -apiPath "https://netapp-node/api/storage/qtrees/$VolumeUUID/$($QTreeID)?fields=*" -queryType "GET")
	}
	else
	{
		return (Send-NetApp -apiPath "https://netapp-node/api/storage/qtrees?name=$QTreeName&volume.uuid=$volumeUUID&fields=*" -queryType "GET").records
	}
}

function Get-VolumeFormat
{
    param(
        $VolumeName,
        $SVMName,
        $SizeInBytes,
        $exportPolicy = $null
    )

    $ShareName = "$($VolumeName)_Temp"
    $VolumeName = $VolumeName -replace "-","_"

    if($exportPolicy -eq $null)
    {
        $finalString = '{ "name": "'+$VolumeName+'", "smart_container": true, "svm": { "name": "'+$SVMName+'" }, "nas": { "nfs_access": [], "cifs_access": [ { "access": "Full_Control", "user_or_group": "Everyone" } ], "application_components": [ { "name": "'+$VolumeName+'", "total_size": '+$SizeInBytes+', "share_count": 1, "storage_service": { "name": "value" }, "export_policy": { "name": "none" } } ],"cifs_share_name": "'+"$ShareName"+'", "protection_type": { "remote_rpo": "none" } }, "template": { "name": "nas" } }'
    }
    else
    {
        $finalString = '{ "name": "'+$VolumeName+'", "smart_container": true, "svm": { "name": "'+$SVMName+'" }, "nas": { "nfs_access": [], "cifs_access": [ { "access": "Full_Control", "user_or_group": "Everyone" } ], "application_components": [ { "name": "'+$VolumeName+'", "total_size": '+$SizeInBytes+', "share_count": 1, "storage_service": { "name": "value" }, "export_policy": { "name": "'+$exportPolicy+'" } } ],"cifs_share_name": "'+"$ShareName"+'", "protection_type": { "remote_rpo": "none" } }, "template": { "name": "nas" } }'
    }
    return $finalString

}

function New-NetAppVolume
{
    param(
        $VolumeName,
        $SVMName,
        $SizeInBytes,
        $exportPolicy = $null
    )
    $result = Send-NetApp "http://netapp-node/api/application/applications" -queryType "POST" -body $(Get-VolumeFormat "$VolumeName" "$SVMName" "$($SizeInBytes)" $exportPolicy)
    return $result
}

function New-NetAppQTree
{
    param(
        $QTreeName,
        $VolumeUUID,
        $SVMUUID,
        $Quota
    )

    $job = Send-NetApp "/api/storage/qtrees" -queryType "POST" -body "{ `"export_policy`": { `"name`": `"default`", `"id`": 34359738369 }, `"user`": {}, `"group`": {}, `"name`": `"$QTreeName`", `"volume`": { `"uuid`": `"$VolumeUUID`" }, `"svm`": { `"uuid`": `"$SVMUUID`" }, `"security_style`": `"ntfs`" }"
    $global:timeOut = 60
    $timer = 0
        while($true)
        {
            $timer++
            if($timer -eq $global:timeOut)
            {
                Write-Host "QTree Creation Failed, Aborting"
                return "FAIL"
            }
            $jobStatus = (Get-NetAppJob $job.job.uuid)
            if($jobStatus.state -eq "success")
            {
                break
            }
            else
            {
                Write-Host "Creating QTree, Status : $($jobStatus.state), waiting..."
            }
		    Start-Sleep -Seconds 1
        }
    $newQTree = Get-QTree -VolumeUUID $VolumeUUID -QTreeName $QTreeName
    $job = Send-NetApp "/api/storage/quota/rules" -queryType "POST" -body "{ `"space`": { `"hard_limit`": $Quota }, `"qtree`": { `"name`": `"$QTreeName`" }, `"svm`": { `"uuid`": `"$SVMUUID`" }, `"volume`": { `"uuid`": `"$VolumeUUID`" }, `"type`": `"tree`" }"
    $timer = 0
        while($true)
        {
            $timer++
            if($timer -eq $global:timeOut)
            {
                Write-Host "QTree Quota Failed, Aborting"
                return "FAIL"
            }
            $jobStatus = (Get-NetAppJob $job.job.uuid)
            if($jobStatus.state -eq "success" -or $jobStatus.message -eq "duplicate entry")
            {
                break
            }
            else
            {
                Write-Host "Creating QTree Quota, Status : $($jobStatus.state), waiting..."
            }
		    Start-Sleep -Seconds 1
        }

    return "SUCCESS"
}


function Add-IgnoreCertificates
{
    if ("TrustAllCertsPolicy" -as [type]) {} else {
        Add-Type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
}

function Get-CommvaultSubclients
{

    param(
        $APIKey
    )


    $clientID = "3041" # commvaultClientName
    $commvaultDNSName = "CommvaultDNSName"


    # Ignore certificate Issues

    Add-IgnoreCertificates

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authtoken", "339e6d100cc8f7be530d673562146ba944ebbf7db34ec93112d53cb8fa28be311a0565a3e39fa8677634fc21907123c7e4c1a476d09862e01f67ea9bedfd91c26a625c7ecbd72a75149e8f085b07fa92072223d434ab1f3a447cdca6649c200f9b095a6f0ab32dcdaa0f9460961446d15ae933bc42749f62d2beecce60dfa8763955f5a00ecfd3c6a28d59fd14e7c2b9fba52da0257f3ed099576c102b93ef6fd5108013f64da7f7241434f743c2453cbfb1575affeb6a774ce3821fc06a56885e5fac319d14d43f482e80ee74c4d3e6d57a096fa9bb8e3cabb3fe5840db4e491168f19681a2b094a")
    $URI = "https://$($commvaultDNSName).esl.corp.elbit.co.il/commandcenter/api/Subclient?clientID=$($clientID)"
    $response = Invoke-RestMethod $URI -Method 'GET' -Headers $headers
    $subClients = @()

    foreach( $subclient in $response.DocumentElement.subClientProperties )
    {

        $subClients += $subclient.subClientEntity
    }

    return $subClients
}

function Get-CommvaultSubclient
{

    param(
        $APIKey,
        $SubclientID
    )


    $clientID = "3041" # commvaultClientName
    $commvaultDNSName = "CommvaultDNSName"


    # Ignore certificate Issues

    Add-IgnoreCertificates

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authtoken", $APIKey)
    $URI = "https://$($commvaultDNSName).esl.corp.elbit.co.il/commandcenter/api/Subclient/$SubclientID"
    $response = Invoke-RestMethod $URI -Method 'GET' -Headers $headers
    

    return $response.App_GetSubClientPropertiesResponse.subClientProperties
}

function Set-CommvaultSubclient
{
    param(
        [Parameter(Mandatory=$true)][ValidateSet("ADD", "OVERWRITE", "DELETE")]
        $OperationType,
        $path,
        $subclient,
        $APIKey
    )

    $clientID = "3041" # commvaultClientName
    $commvaultDNSName = "CommvaultDNSName"

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/xml")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authtoken", $APIKey)

    $body = @"
    {
        `"subClientProperties`": {
        `"content`": [
          {
            `"path`": `"$path`"
          }
        ],
        `"fsContentOperationType`": `"$OperationType`"
      },
      `"association`": {
        `"entity`": [
          {
            `"subclientId`": $($subclient.subclientId),
            `"clientId`": $($subclient.clientId),
            `"applicationId`": $($subclient.applicationId),
            `"backupsetId`": $($subclient.backupsetId),
            `"instanceId`": $($subclient.instanceId),
            `"subclientName`": `"$($subclient.subclientName)`",
            `"backupsetName`": `"$($subclient.backupsetName)`"
          }
        ]
      }
    }
"@ 

    $temp = Invoke-RestMethod "https://$($commvaultDNSName)/commandcenter/api/Subclient/$($subclient.subclientId)" -Method 'POST' -Headers $headers -Body $body


    $subClientInfo = (Get-CommvaultSubclient -APIKey $APIKey -SubclientID $($subclient.subclientId))


    
    if((($path -in $subClientInfo.content.path) -and ($OperationType -eq "ADD")) -or (($path -notin $subClientInfo.content.path) -and ($OperationType -eq "DELETE")) -or (($path -eq $subClientInfo.content.path) -and ($OperationType -eq "OVERWRITE")))
    { 
        $result = $true
    } 
    else
    {
        $result = $false
    }


    return $result


}

function New-CommVaultSubclient
{

    param(
        $APIKey,
        [Parameter(Mandatory=$true)][ValidateSet("SVMPrefix-archive1",
                                                 "SVMPrefix-archive2",
                                                  "SVMPrefix-subs",
                                                  "SVMPrefix2-cifs1",
                                                  "SVMPrefix2-cifs2",
                                                  "SVMPrefix2-ng-dev-nas",
                                                  "SVMPrefix2-ng-nas",
                                                  "SVMPrefix2-somebad01")]
        $SVM,
        $SubclientName,
        $NASPath
    )



    $clientID = "3041" # commvaultClientName
    $clientName = "commvaultClientName"
    $commvaultDNSName = "CommvaultDNSName"
    $applicationID = "13"
    $DRSVM = "$($SVM)-dr"
    $backupsetID = ((Get-CommvaultSubclients -APIKey $APIKey | Select-Object -Property backupsetName, backupsetID -Unique) | Where-Object { $_.backupsetName -eq "SVMPrefix2-cifs2-dr" }).backupsetID
    
    if($backupsetID -eq $null -or $backupsetID -eq "")
    { return $false; Write-Host "bad backup set" }



    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authtoken", $APIKey)

    $body = @"
    {
      `"subClientProperties`": {
        `"contentOperationType`": 2,
        `"subClientEntity`": {
          `"clientId`": $clientID,
          `"clientName`": `"$clientName`",
          `"applicationId`": $applicationID,
          `"backupsetId`": $backupsetID,
          `"backupsetName`": `"$DRSVM`",
          `"subclientName`": `"$SubclientName`"
        },
        `"commonProperties`": {
          `"enableBackup`": true,
          `"numberOfBackupStreams`": 4
        },
        `"planEntity`": {
          `"planId`": 3
        },
        `"content`": [
          {
            `"path`": `"$NASPath`"
          }
        ],
        `"fsSubClientProp`": {
          `"useGlobalFilters`": `"USE_CELL_LEVEL_POLICY`"
        },
        `"useLocalContent`": true,
        `"useLocalArchivalRules`": false
      }
    }
"@

    $response = Invoke-RestMethod "https://$commvaultDNSName/commandcenter/api/Subclient" -Method 'POST' -Headers $headers -Body $body

    $afterCreationSubclients = Get-CommvaultSubclients -APIKey $APIKey

    $find = $afterCreationSubclients | Where-Object { $_.subclientName -eq "$SubclientName" }

    if($find -ne $null)
    {
        return $true
    }
    else
    {
        return $false
    }

}

# function to send an API command to the NetApp Server
function Send-Netapp
{
    param(
        [Parameter(mandatory=$true)]
        [string]$apiPath,
        [Parameter(mandatory=$true)]
        [string]$queryType,
        [Parameter(mandatory=$false)]
        [string] $body
    )

    if($apiPath.substring(0,7) -eq "https:/") #replace https to http
    {
        $apiPath = $apiPath.Replace("https","http")
    }
    if($apiPath.Substring(0,3) -eq "api")
    {
        $apiPath = "http://netapp-node/" + $apiPath
    }
    if($apiPath.Substring(1,3) -eq "api")
    {
        $apiPath = "http://netapp-node" + $apiPath
    }
    
    if($global:creds -eq $null) { Initialize-Creds }
    if($queryType -eq "GET")
    {
        Invoke-RestMethod -Uri $apiPath -Credential $global:creds
    }
    elseif($queryType -eq "DELETE")
    {
        (Invoke-RestMethod -Uri $apiPath -Credential $global:creds -Method $queryType)
    }
    elseif($queryType -eq "POST" -or $queryType -eq "PATCH")
    {
        (Invoke-RestMethod -Uri $apiPath -Credential $global:creds -Method $queryType -Body $body)
    }
}

# function to get the share path of a QTree / Volume using API
function Get-Share
{
    param(
        [string]$volumeUUID,
        $QTreeID = $null,
        $QTreeObject = $null
    )

    if(($volumeUUID -ne $null)-and ($QTreeID -ne $null))
    {
        $QTreeObject = Get-QTree -VolumeUUID $volumeUUID -QTreeID $QTreeID
    }

    if($QTreeObject -ne $null)
    {
        $QTreeShare = $($(Send-NetApp -apiPath "https://netapp-node/api/protocols/cifs/shares?path=$($QTreeObject.path)&svm.uuid=$($QTreeObject.svm.uuid)&return_records=true&return_timeout=15" -queryType "GET").records.name)
        if(($QTreeShare -eq "") -or ($QTreeShare -eq $null))
        {
            $volumePath = (Send-Netapp -apiPath "https://netapp-node/api/storage/volumes/$($QTreeObject.volume.uuid)?is_constituent=false&fields=nas.path" -queryType "GET").nas.path
            $QTreeShare = "$($(Send-NetApp -apiPath "https://netapp-node/api/protocols/cifs/shares?path=$($volumePath)&svm.uuid=$($QTreeObject.svm.uuid)&return_records=true&return_timeout=15" -queryType "GET").records.name)\$($QTreeObject.name)"
        }
        return "\\$($QTreeObject.svm.name)\$QTreeShare"
    }
	else
	{
        $volumeObject = (Send-Netapp -apiPath "https://netapp-node/api/storage/volumes/$($volumeUUID)?is_constituent=false&fields=*,nas.path" -queryType "GET")
        $volumePath = $volumeObject.nas.path
        $ShareName = $($(Send-NetApp -apiPath "https://netapp-node/api/protocols/cifs/shares?path=$($volumePath)&svm.uuid=$($volumeObject.svm.uuid)&return_records=true&return_timeout=15" -queryType "GET").records.name)
		$attempt = "\\$($volumeObject.svm.name)\$ShareName"
		
        return $attempt
	}
}

function Get-ShareByJunction
{
    param(
        $QTreeObject
    )
    
    $share = (Send-NetApp -apiPath "https://netapp-node/api//protocols/cifs/shares?volume.uuid=$($QTreeObject.volume.uuid)&fields=path,name" -queryType "GET").records | Where-Object { $_.path -eq $QTreeObject.path }
    $ipList = (Send-Netapp -apiPath "https://netapp-node/api/network/ip/interfaces?fields=ip.address%2Cservices%2Cservice_policy&svm.uuid=$($QTreeObject.svm.uuid)&services=data_cifs&return_timeout=120" -queryType "GET").records.ip
    $path = "\\$($ipList[0].address)\$($share.name)"
    return $path
}

# function to get a Volume's SVM by a QTree object using API
function Get-QTreeSVM
{
    param(
        $qtreeObject
    )
    $svm = (Send-Netapp -apiPath "http://netapp-node/api/storage/volumes/$($qtreeObject.volume.uuid)" -queryType "GET").svm
    $name = $qtreeObject.name
    
    if($name -eq $null -or $name -eq "")
    {
        Write-Host "ERROR, Invalid QTree under ($($qtreeObject.volume.name)), No name"
    }
    return $svm
}

function Get-NetAppVolume
{
    param(
        $VolumeName,
        $SVMUUID
    )
    return $(Send-NetApp "https://netapp-node/api/storage/volumes?is_constituent=false&name=$VolumeName&svm.uuid=$SVMUUID" -queryType "GET")
}

# function to remove a QTree using the API
function Remove-QTree
{
    param(
        [string]$volumeUUID,
        [string]$QTreeID,
        [boolean]$saveData = $false
    )

    if($saveData -eq $false)
    {
        Send-Netapp "http://netapp-node/api/storage/qtrees/$volumeUUID/$($QTreeID)?return_timeout=0" -queryType "DELETE"
    }
    else
    {
		
        $QTreeObject = Get-QTree -VolumeUUID $volumeUUID -QTreeID $QTreeID
        $QTreeShare = Get-Share -QTreeObject $QTreeObject
        $QTreeName = $QTreeObject.name

        $volumeSharePath = Get-Share -volumeUUID $volumeUUID
        New-Item -Path "$volumeSharePath\$($QtreeName)_TEMP" -ItemType Directory
        robocopy "$volumeSharePath\$QtreeName" "$volumeSharePath\$($QtreeName)_TEMP" /e /move /SEC /SECFIX #need to chnge to copy with /copy:DATS to copy ACLs too, and then delete the origin
        Rename-Item -Path "$volumeSharePath\$($QtreeName)_TEMP" -NewName "$($QtreeName)"
    }

}

function Remove-Volume
{
    param(
        $volumeUUID
    )

    Send-Netapp -apiPath "http://netapp-node/api/storage/volumes/$volumeUUID" -queryType "DELETE"
}

function Get-NetappJob
{
    param(
        $uuid
    )
    return Send-Netapp -apiPath "http://netapp-node/api/cluster/jobs/$($uuid)?fields=code%2Cdescription%2Cend_time%2Cerror%2C_links%2Cmessage%2Cstart_time%2Cstate%2Csvm%2Cuuid%2Carguments&return_timeout=120" -queryType "GET"
}

function Get-QTreeUsedSpace
{
    param(
        $QTreeObject
    )

    $QTreeID = $QTreeObject.id
    $VolumeUUID = $QTreeObject.volume.uuid

    return (Send-Netapp -apiPath "https://netapp-node/api/storage/quota/reports?max_records=1&fields=type%2Cspace%2Cfiles&volume.uuid=$VolumeUUID&qtree.id=$QTreeID&type=tree&return_timeout=$($global:timeOut)" -queryType "GET").records.space.used.total
}

function Update-NetAppJunction
{
    param(
        $volumeUUID,
        $path
    )
    Send-Netapp -apiPath "/api/storage/volumes/$volumeUUID" -queryType "PATCH" -body "{ `"nas`": { `"path`": `"$path`" } }"
}

function Get-Quota
{
    param(
        $QTreeObject
    )
    $VolumeUUID = $QtreeObject.volume.uuid
    $QTreeID = $QTreeObject.id
    $QuotaResults = $(Send-NetApp "https://netapp-node/api/storage/quota/rules?volume.uuid=$VolumeUUID&qtree.id=$QTreeID&fields=space" -queryType "GET")

    if($QuotaResults.records.Count -eq 0) { return 0 }

    if($QuotaResults.records[0].space.hard_limit -eq $null) { return 0 }

    return $QuotaResults.records[0].space.hard_limit

}

function Format-Action
{
    param(
        $QTree,
        $Quota,
        $Stage,
        $NewVolume = $null
    )

    $action = [pscustomobject]@{
        QTree = $QTree
        Quota = $Quota
        Stage = $Stage
    }

    if($NewVolume -ne $null)
    {
       $action = [pscustomobject]@{
            QTree = $QTree
            Quota = $Quota
            Stage = $Stage
            NewVolume = $($NewVolume | ConvertTo-Json)
        }
    }

    return $action
}

function Log-Action 
{
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Action,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    # Add a timestamp to the action in dd-MM-yyyy HH:mm:ss format
    $Action | Add-Member -MemberType NoteProperty -Name Timestamp -Value (Get-Date -Format "dd-MM-yyyy HH:mm:ss") -Force

    # Read existing actions from the JSON file
    if (Test-Path $FilePath) {
        $actions = Get-Content $FilePath -Raw | ConvertFrom-Json
    } else {
        $actions = @()
    }

    # Ensure $actions is always an array
    $actions = @($actions)


    # Check if an entry with the same QTree.volume.uuid and QTree.id exists
    $index = $actions.IndexOf(($actions | Where-Object { $_.QTree.volume.uuid -eq $Action.QTree.volume.uuid -and
        $_.QTree.id -eq $Action.QTree.id  }))

    if ($index -ne -1) {
        # Replace the existing entry
        $actions[$index] = $Action
    } else {
        # Add the new action to the list
        $actions += $Action
    }

    # Sort actions by timestamp (convert to DateTime for accurate sorting)
    $sortedActions = $actions | Sort-Object { [datetime]::ParseExact($_.Timestamp, "dd-MM-yyyy HH:mm:ss", $null) }

    # Write the updated list back to the JSON file
    $sortedActions | ConvertTo-Json -Depth 20 | Set-Content $FilePath
}

function Remove-Action
{
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$action,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    # Read existing actions from the JSON file
    if (Test-Path $FilePath) {
        $actions = Get-Content $global:logPath -Raw | ConvertFrom-Json
    } else {
        $actions = @()
    }

    # Ensure $actions is always an array
    $actions = @($actions)


    $actions = $actions | Where-Object { ($_.QTree.volume.uuid -ne $action.QTree.volume.uuid) -and ($_.QTree.id -ne $action.QTree.id) }
    if($actions -eq $action) { $actions = @() }

    # Sort actions by timestamp (convert to DateTime for accurate sorting)
    $sortedActions = $actions | Sort-Object { [datetime]::ParseExact($_.Timestamp, "dd-MM-yyyy HH:mm:ss", $null) }

    # Write the updated list back to the JSON file
    $sortedActions | ConvertTo-Json | Set-Content $FilePath
}

function Read-Actions 
{
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    # Check if the file exists
    if (Test-Path $FilePath) {
        # Read the JSON content from the file
        $jsonContent = Get-Content $FilePath -Raw
        # Convert the JSON content to a PowerShell object
        $actions = $jsonContent | ConvertFrom-Json

        foreach($action in $actions)
        {
            try
            {
                if($action.NewVolume.records[0].getType().name -eq "String")
                {
                    $jsonFormattedString = $action.NewVolume.records -replace '@{', '{' -replace ';', '",' -replace '=', ':"' -replace '}', '"}' -replace ':"{',':{' -replace '}",','},' -replace '}"}','}}'
                    $action.NewVolume.records = $jsonFormattedString | ConvertFrom-Json
                }
            } catch {}
            try
            {
                if($action.NewVolume.getType().name -eq "String")
                {
                    $action.NewVolume = $action.NewVolume | ConvertFrom-Json
                }
            } catch {}
        }
        # Ensure $actions is always an array
        $actions = @($actions)
        return $actions
    } else {
        Write-Error "The file at path $FilePath does not exist."
        return @()
    }
}

function Check-Sessions
{
    param
    (
        $QtreeObject
    )

    $SVMUUID = $QtreeObject.svm.uuid
    $VOLUUID = $QtreeObject.volume.uuid
    $QTreeName = $QtreeObject.name
    
    $sessions = (Send-Netapp -apiPath "https://netapp-node/api/protocols/cifs/session/files?svm.uuid=$SVMUUID&path=*$($QTreeName)*&volume.uuid=$VOLUUID&fields=*&return_records=true&return_timeout=15" -queryType "GET").records
    return $sessions
}

function Start-Robocopy
{
    param(
        $Source,
        $Destination
    )

    $results = robocopy "$Source" "$Destination" /e /SEC /SECFIX /z /mir /mt:128

    $FailedFiles = $results[-10][59]

    #$results # for debug

    if($FailedFiles -eq "0"){ return $true }
    else { return $false }

}

<#
Stage 0 = Creation function started, no actions taken
Stage 1 = NetApp Volume Successfuly created
Stage 2 = Data was copied over to volume successfuly
Stage 3 = QTree removed and junction changed

Error Stages
Stage 101 = Theres open sessions
Stage 102 = Can't find QTree share
Stage 901 = Bad QTree ID
Stage 902 = No Quota
#>
function Convert-ToVolume
{
    param(
        $QTreeObject,
        $changeJunction = $false
    )

    # Checking if the QTree object exists in the action logs
    $actions = Read-Actions -FilePath $global:logPath
    $actions = @($actions)
    $index = $actions.IndexOf(($actions | Where-Object { $_.QTree.volume.uuid -eq $QTreeObject.volume.uuid -and
        $_.QTree.id -eq $QTreeObject.id  }))

    if ($index -ne -1)
    {
        $currentAction = $actions[$index]
        $Stage = $currentAction.Stage
        $Quota = $currentAction.Quota
        if(($Stage -ge 1) -and ($Stage -le 110)) { $NewVolume = $currentAction.NewVolume }
    }
    else
    {
        $Quota = Get-Quota $QTreeObject
        Log-Action -FilePath $global:logPath -Action $(Format-Action -QTree $QTreeObject -Quota $Quota -Stage 0)
        $Stage = 0
    }

    #Create the new volume and categorize potential problems
    if($Stage -eq 0)
    {
        # Testing if the QTreeObject is bad or no Quota
        
        if($QTreeObject.id -eq $null -or $QTreeObject.id -eq "")
        {
            Log-Action -FilePath $global:logPath -Action $(Format-Action -QTree $QTreeObject -Quota $Quota -Stage 901)
            Write-Host "QTree name empty, Aborting conversion"
            return
        }
        if($Quota -eq 0) {
            Log-Action -FilePath $global:logPath -Action $(Format-Action -QTree $QTreeObject -Quota $Quota -Stage 902)
            Write-Host "Quota is 0, Aborting"
            return
        }

        try
        {
            $job = New-NetAppVolume -VolumeName ($QTreeObject.name) -SVMName ($QTreeObject.svm.name) -SizeInBytes $Quota -exportPolicy $($QTreeObject.export_policy.name)
        }
        catch { Write-Host "Volume creation API query failed, $_"; return }
    
        # Wait for a successful result
        $timer = 0
        while($true)
        {
            $timer++
            if($timer -eq $global:timeOut)
            {
                Write-Host "Volume Creation Failed, Aborting."
                return
            }
            $jobStatus = (Get-NetAppJob $job.job.uuid)
            if($jobStatus.state -eq "success")
            {
                break
            }
            else
            {
                Write-Host "Creating Volume, Status : $($jobStatus.state), waiting..."
            }
		    Start-Sleep -Seconds 5
        }

        $NewVolume = $null

        $timer = 0
        while($true)
        {
            $timer++
            if($timer -eq $global:timeOut)
            {
                Write-Host "Can't find volume, Aborting."
                return
            }
            $NewVolume = $(Send-NetApp "https://netapp-node/api/storage/volumes?is_constituent=false&name=$($QTreeObject.name -replace "-","_")&svm.uuid=$($QTreeObject.svm.uuid)" -queryType "GET") # same as get-netappvolume
            if($NewVolume -ne $null)
            {
                break
            }
            else
            {
                Write-Host "Finding Created Volume..."
            }
		    Start-Sleep -Seconds 5
        }



        $Stage = 1 # Proceed to the next step
        Log-Action -FilePath $global:logPath -Action $(Format-Action -QTree $QTreeObject -Quota $Quota -Stage 1 -NewVolume $NewVolume)
    }

    if($Stage -eq 1)
    {
        # Finding Share path
        $QTreeShare = Get-Share -QTreeObject $QTreeObject 
        $NewVolumeShare = Get-Share $NewVolume.records[0].uuid

        if(-not (Test-Path -Path $QTreeShare))
        {
            Write-Host "Can't find QTree $($QTreeObject.name) share"
            Log-Action -FilePath $global:logPath -Action $(Format-Action -QTree $QTreeObject -Quota $Quota -Stage 102)
            return
        }

        # Starting robocopy process
        $result = Start-Robocopy -Source "$QTreeShare" -Destination "$NewVolumeShare"
        Start-Sleep -Seconds 1

        if($result -eq $false)
        {
            Write-Host "robocopy Failed"
            return
        }

        # Checking if any sessions are up
        if((Check-Sessions $QTreeObject) -ne $null)
        {
            Write-Host "Open sessions, Writing to log"
            (Check-Sessions $QTreeObject).path | Out-File -FilePath "$($global:logOpenFiles)\$($QTreeObject.volume.name).$($QTreeObject.name).txt"
            #return
        }

        if($changeJunction)
        {
            $Stage = 2
            Log-Action -FilePath $global:logPath -Action $(Format-Action -QTree $QTreeObject -Quota $Quota -Stage 2 -NewVolume $NewVolume)
        }
    }

    if($Stage -eq 2)
    {
        $QTreeShare = "$(Get-Share -QTreeObject $QTreeObject)"

        # Remove QTree and wait for it to be deleted
        Remove-QTree -volumeUUID $($QTreeObject.volume.uuid) -QTreeID ($QTreeObject.id) -saveData $false
        while(Test-Path $QTreeShare) { Start-Sleep -Seconds 1 }
        
        Update-NetAppJunction -volumeUUID ($NewVolume.records[0]).uuid -path ($QTreeObject.nas.path)

        $Stage = 3
        
        $CommvaultSVM = "$($QTreeObject.svm.name)-dr"
        $CommvaultsubClientName = $QTreeObject.volume.name
        
        $subclients = Get-CommvaultSubclients -APIKey $global:APIKey

        $subclient = $subclients | Where-Object { ($_.backupsetName -eq $CommvaultSVM) -and ($_.subclientName -eq $CommvaultsubClientName) }

        if($subclient -eq $null) { $Stage = 301 }

        $commvaultResult = Set-CommvaultSubclient -OperationType ADD -path "/$($CommvaultSVM)$($QTreeObject.nas.path)" -subclient $subclient -APIKey $APIKey

        if($commvaultResult -eq $false) { $Stage = 302 }

        
        Log-Action -FilePath $global:logPath -Action $(Format-Action -QTree $QTreeObject -Quota $Quota -Stage 3 -NewVolume $NewVolume)
    }



}


function Start-Rollback
{
	param (
		$volumeUUID,
        $QTreeID,
        $action = $null
	)
    if($action -eq $null)
    {
	    $action = Read-Actions -FilePath $global:logPath | Where-Object { ($_.QTree.volume.uuid -eq $volumeUUID) -and ($_.QTree.id -eq $QTreeID) }
    }
    if(($action -eq $null) -or ($action.Count -ge 2))
    {
        Write-Host "Action not found, or more than one was found."
        return
    }
    
    $QTreeObject = $action.QTree
    $CurrentVolume = $action.NewVolume
    $Stage = $action.Stage
    $Quota = $action.Quota
    $global:timeOut = 60

    if($Stage -eq 3)
    {
        $job = Update-NetAppJunction -volumeUUID $CurrentVolume.records[0].uuid -path "/$($CurrentVolume.records[0].name)"
        $timer = 0
        while($true)
        {
            $timer++
            if($timer -eq $global:timeOut)
            {
                Write-Host "Junction change failed, Aborting"
                return
            }
            $jobStatus = (Get-NetAppJob $job.job.uuid)
            if($jobStatus.state -eq "success")
            {
                break
            }
            else
            {
                Write-Host "Changing Junction, Status : $($jobStatus.state), waiting..."
            }
		    Start-Sleep -Seconds 1
        }
        
        if((New-NetAppQTree -QTreeName $($QTreeObject.name) -VolumeUUID $($QTreeObject.volume.uuid) -SVMUUID $($QTreeObject.svm.uuid) -Quota $Quota) -eq "FAIL") { return }
        $NewQTree = Get-QTree -VolumeUUID $($QTreeObject.volume.uuid) -QTreeName $($QTreeObject.name)
        $CurrentVolumeShare = Get-Share -volumeUUID $($CurrentVolume.records[0].uuid)
        robocopy "$CurrentVolumeShare" "\\$($($CurrentVolumeShare).Split("\")[2])$($($NewQTree.path) -replace "/","\")"  /e /move /SEC /SECFIX
        Remove-Volume -volumeUUID $($CurrentVolume.records[0].uuid)
        Remove-Action -FilePath $global:logPath -action $action

        $Stage = 0

        $CommvaultSVM = "$($QTreeObject.svm.name)-dr"
        $CommvaultsubClientName = $QTreeObject.volume.name
        
        $subclients = Get-CommvaultSubclients -APIKey $global:APIKey

        $subclient = $subclients | Where-Object { ($_.backupsetName -eq $CommvaultSVM) -and ($_.subclientName -eq $CommvaultsubClientName) }

        if($subclient -eq $null) { $Stage = 905 }

        $commvaultResult = Set-CommvaultSubclient -OperationType DELETE -path "/$($CommvaultSVM)$($QTreeObject.nas.path)" -subclient $subclient -APIKey $APIKey

        if($commvaultResult -eq $false) { $Stage = 906 }

        Log-Action -FilePath $global:logPath -Action $(Format-Action -QTree $QTreeObject -Quota $Quota -Stage $Stage)

    }
}

# Main Script

Initialize-Creds

$qtrees = Get-QTrees | Where-Object { ($_.path -ne $null) -and ($_.security_style -ne "unix") } # Get all QTrees in the netapp-node NetApp node that aren't NFS.

<#
$lowQuotaQTrees = @()
$total = $qtrees.count
$counter = 0
foreach ( $Qtree in $qtrees)
{
    $counter++
    Write-Host "Step $counter out of $total"
    if(((Get-QTreeUsedSpace $QTree)) -eq 0 ) # If the QTree's used space is less than 10GB
    {
        $lowQuotaQTrees += $QTree
    }
}
#>

#$specificQTree = $qtrees | Where-Object { $_.name -eq "Orphaned_QTree_Test" } # Get the testing QTree 
$specificQTrees = @()
$specificQTrees += ($qtrees | Where-Object { $_.name -eq "test1" })[0]
$specificQTrees += $qtrees | Where-Object { $_.name -eq "test2" }
$specificQTrees += $qtrees | Where-Object { $_.name -eq "test3" }

foreach($specificQTree in $specificQTrees)
{
    Convert-ToVolume -QTreeObject $specificQTree
}


$actions = Read-Actions -FilePath $global:logPath

#Start-Rollback -action $actions[1]

if ($specificQTree.GetType().Name -eq "PSCustomObject") # one object only safety
{
	#Convert-ToVolume -QTreeObject $specificQTree -changeJunction $true

}
