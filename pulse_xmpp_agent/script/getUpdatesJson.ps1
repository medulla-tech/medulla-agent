# launch the research of updates if it's not defined
if($null -eq $Updates){
    $UpdateSession = New-Object -ComObject "Microsoft.Update.Session"
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $Updates = $UpdateSearcher.Search("IsInstalled=1").Updates
}

# Remove updates.json file if it's exists
$jsonfile = "..\INFOSTMP\updates.json"
if(Test-Path $jsonfile){
    Remove-Item $jsonfile
}

# Get Some info from reg keys
$displayVersion = (New-Object -ComObject WScript.shell).RegRead('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DisplayVersion')
$currentBuild = (New-Object -ComObject WScript.shell).RegRead('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuild')
$productName = (New-Object -ComObject WScript.shell).RegRead('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName')


# Overwrite the json file
"{" >> $jsonfile
"""MACHINE_INFOS"":{" >> $jsonfile
"""displayVersion"":""$displayVersion""," >> $jsonfile
"""currentBuild"":""$currentBuild""," >> $jsonfile
"""productName"":""$productName""}," >> $jsonfile
"""PACKAGE_LIST"":[" >> $jsonfile

Foreach($update in $Updates){
    "{" >> $jsonfile;
    """PackageName"":""$($update.title)""," >> $jsonfile;
    """list_KB"":[" >> $jsonfile;


    foreach($kb in $update.KBArticleIDs){
        """KB$($kb)""," >> $jsonfile
    }
    "]," >> $jsonfile
    """list_Categories"":[" >> $jsonfile

    foreach($categorie in $update.Categories){
        "{" >> $jsonfile
        """categorieName"":""$($categorie.name)""," >> $jsonfile
        """CategoryID"":""$($categorie.CategoryID)""," >> $jsonfile
        """CategoryType"":""$($categorie.Type)""" >> $jsonfile
        "}," >> $jsonfile

    }
    "]" >> $jsonfile
    "}," >> $jsonfile
}
"]" >> $jsonfile
"}" >> $jsonfile
