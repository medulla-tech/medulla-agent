 

' Default Site path, change if necessary
$IISFolderPath = "C:\Python27\Lib\site-packages\pulse_xmpp_agent\INFOSTMP\wsusscn2.cab"


' Download wsusscn2.cab
Start-BitsTransfer -Source "http://go.microsoft.com/fwlink/?linkid=74689" -Destination "$IISFolderPath"


' creation d'un hash du fichier
'(Get-FileHash C:\Python27\Lib\site-packages\pulse_xmpp_agent\INFOSTMP\wsusscn2.cab).Hash

Set UpdateSession = CreateObject("Microsoft.Update.Session")
Set UpdateServiceManager = CreateObject("Microsoft.Update.ServiceManager")
Set UpdateService = UpdateServiceManager.AddScanPackageService("Offline Sync Service", "$IISFolderPath")
Set UpdateSearcher = UpdateSession.CreateUpdateSearcher()

WScript.Echo "Searching for updates..." & vbCRLF

UpdateSearcher.ServerSelection = 3 ' ssOthers

UpdateSearcher.ServiceID = UpdateService.ServiceID

Set SearchResult = UpdateSearcher.Search("IsInstalled=0")

Set Updates = SearchResult.Updates

If searchResult.Updates.Count = 0 Then
    WScript.Echo "There are no applicable updates."
    WScript.Quit
End If

WScript.Echo "List of applicable items on the machine when using wssuscan.cab:" & vbCRLF

For I = 0 to searchResult.Updates.Count-1
    Set update = searchResult.Updates.Item(I)
    WScript.Echo I + 1 & "> " & update.Title
Next

WScript.Quit

