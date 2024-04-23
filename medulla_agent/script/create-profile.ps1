Function New-Profile {
    <#
    .SYNOPSIS
    Creates the profile for a user on the current host if one does not already exist.

    .PARAMETER Account
    [String] The string representation of an account to create the profile for. This is mutually exclusive to Account.

    .PARAMETER Identity
    [System.Security.Principal.IdentityReference] The IdentityReference object of an account to create the profile
    for. This is mutually exclusive to Account.

    .PARAMETER BaseName
    [String] Optionally define the base name for the profile directory to create.

    .EXAMPLE
    New-Profile -Account my-user
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true, ParameterSetName="string")]
        [String]$Account,
        [Parameter(Mandatory=$true, ParameterSetName="identity")]
        [System.Security.Principal.IdentityReference]$Identity,
        [Parameter()][String]$BaseName
    )

    Add-Type -Namespace PInvoke -Name Userenv -UsingNamespace System.Text -MemberDefinition @'
[DllImport("Userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern int CreateProfile(
    [MarshalAs(UnmanagedType.LPWStr)] string pszUserSid,
    [MarshalAs(UnmanagedType.LPWStr)] string pszUserName,
    [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszProfilePath,
    UInt32 cchProfilePath);
'@

    if ($PSCmdlet.ParameterSetName -eq "string") {
        $Identity = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $Account
    }

    $account_sid = $Identity.Translate([System.Security.Principal.SecurityIdentifier])
    $account_name = $account_sid.Translate([System.Security.Principal.NTAccount])
    if (-not $BaseName) {
        $account_split = $account_name.Value.Split('\', 2)
        $BaseName = $account_split[-1]
    }

    $profile_path = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | `
        Where-Object { $_.PSChildName -eq $account_sid.Value }

    if ($null -ne $profile_path) {
        Write-Verbose -Message "The profile for $($account_name.Value) already exists"
        $profile_path = $profile_path.ProfileImagePath
    } else {
        if ($PSCmdlet.ShouldProcess($account_name.Value, "Create profile")) {
            # MAX_PATH is 260 chars
            $raw_path = New-Object -TypeName System.Text.StringBuilder -ArgumentList 260
            $res = [PInvoke.Userenv]::CreateProfile($account_sid.Value, $BaseName, $raw_path, $raw_path.Capacity)
            if ($res -ne 0) {
                $exp = [System.Runtime.InteropServices.Marshal]::GetExceptionForHR($res)
                Write-Error -Message "Failed to create user profile for $($account_name.Value): $($exp.Message)"
            } else {
                $profile_path = $raw_path.ToString()
            }
        }
    }

    return $profile_path
}
