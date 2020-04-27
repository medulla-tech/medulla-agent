[string]$UserName = "pulse"
$Profiles = Get-WmiObject -Class Win32_UserProfile
foreach ($profile in $profiles) {
 $objSID = New-Object System.Security.Principal.SecurityIdentifier($profile.sid)
 $objuser = $objsid.Translate([System.Security.Principal.NTAccount])
 $profilename = $objuser.value.split("\")[1]
 if($profilename -match $UserName) {
      $profilefound = $true
      try {
       $profile.delete()
       Write-Host "The profile $profilename is successfully deleted"
      } catch {
       Write-Host "Failed"
      }
  }
 }


if(!$profilefound) { write-Host "No profile" }
