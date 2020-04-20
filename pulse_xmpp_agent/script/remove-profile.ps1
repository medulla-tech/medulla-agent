[cmdletbinding()]
param(
 [string]$UserName = "pulse"
)

Begin {}

Process {

 $Profiles = Get-WmiObject -Class Win32_UserProfile
 foreach ($profile in $profiles) {
  $objSID = New-Object System.Security.Principal.SecurityIdentifier($profile.sid)
  $objuser = $objsid.Translate([System.Security.Principal.NTAccount])
  $profilename = $objuser.value.split("\")[1]
  if ($profilename -match $UserName) {
   $profilefound = $true
   try {
    $profile.delete()
    Write-Host "The profile $profilename is successfully deleted"
   } catch {
    Write-Host "Failed to delete the profile $profilename"
   }
  }
 }

 if(!$profilefound) { write-Warning "No profiles found containing $profilename" }
}
end {}
