# SPDX-FileCopyrightText: 2026 medulla <support@medulla-tech.io>
# SPDX-License-Identifier: GPL-3.0-or-later

#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Script de desinstallation de l'agent Medulla pour Windows.

.DESCRIPTION
    Ce script supprime tous les composants installes par l'agent Medulla :
      - Tache planifiee  : "Medulla Agent"
      - Services Windows : medullaagent, medullanetnotify, sshd, ssh-agent
                          (et leurs equivalents herites pulseagent / pulsenetworknotify)
      - Agent GLPI       : desinstallation via MSI
      - Modules pip      : pulse_xmpp_agent, pulse_machine_plugins, kiosk-interface, syncthing2
      - Python 3         : installe dans C:\Program Files\Python3 par l'installateur Medulla
      - Repertoires      : C:\Program Files\Medulla (et variantes heritees Pulse)
      - DLL libcurl      : cygcurl-4.dll dans System32
      - Certificats CA   : certificats racine et chaine Medulla
      - Cles de registre : toutes les cles HKLM ecrites par l'installateur

.PARAMETER RemovePython
    Desinstalle Python 3 installe par l'agent Medulla (defaut : $true).
    Mettre a $false si Python est partage avec d'autres applications.

.PARAMETER RemoveGLPI
    Desinstalle l'agent GLPI (inventaire) (defaut : $true).
    Mettre a $false pour conserver l'agent GLPI.

.PARAMETER RemoveTightVNC
    Desinstalle TightVNC (defaut : $true).
    Mettre a $false pour conserver TightVNC.

.PARAMETER Silent
    Supprime les confirmations interactives.

.EXAMPLE
    .\uninstall-medulla-agent.ps1

.EXAMPLE
    .\uninstall-medulla-agent.ps1 -RemovePython:$false -RemoveGLPI:$false -RemoveTightVNC:$false -Silent
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [bool]$RemovePython    = $true,
    [bool]$RemoveGLPI      = $true,
    [bool]$RemoveTightVNC  = $true,
    [switch]$Silent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# --- Chemins d'installation ---
$MedullaDir   = "$env:ProgramFiles\Medulla"
$MedullaDir32 = "${env:ProgramFiles(x86)}\Medulla"
$PulseDir     = "$env:ProgramFiles\Pulse"         # Heritage
$PulseDir32   = "${env:ProgramFiles(x86)}\Pulse"  # Heritage
$PythonDir    = "C:\Program Files\Python3"
$Python27Dir  = "C:\Python27"                      # Heritage Python 2.7

# --- Journal de desinstallation ---
$LogDir  = "$env:SystemRoot\Temp"
$LogFile = Join-Path $LogDir ("medulla-uninstall-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".log")

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'OK')]
        [string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'OK'    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }
}

# --- Fonctions utilitaires ---

function Stop-AndRemoveService {
    <#
    .SYNOPSIS Arrete et supprime un service Windows.
    #>
    param([string]$ServiceName)

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Write-Log "Service '$ServiceName' introuvable, ignore." 'WARN'
        return
    }

    if ($svc.Status -ne 'Stopped') {
        Write-Log "Arret du service '$ServiceName'..."
        & sc.exe stop $ServiceName | Out-Null
        # Attente de l'arret effectif (max 30 secondes)
        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue).Status -ne 'Stopped') {
            if ((Get-Date) -gt $deadline) {
                Write-Log "Delai d'attente depasse pour l'arret de '$ServiceName'." 'WARN'
                break
            }
            Start-Sleep -Milliseconds 500
        }
    }

    Write-Log "Suppression du service '$ServiceName'..."
    $output = & sc.exe delete $ServiceName 2>&1
    Write-Log "sc.exe delete $ServiceName : $output" 'OK'
}

function Remove-ProgramByDisplayName {
    <#
    .SYNOPSIS
        Desinstalle un programme en recherchant son entree dans le registre
        (Programmes et fonctionnalites) et en executant son UninstallString.
    #>
    param([string]$DisplayName)

    $searchPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $entry = $null
    foreach ($path in $searchPaths) {
        $entry = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                 Where-Object { $null -ne $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like "*$DisplayName*" } |
                 Select-Object -First 1
        if ($entry) { break }
    }

    if ($null -eq $entry) {
        Write-Log "Programme '$DisplayName' introuvable dans le registre, ignore." 'WARN'
        return
    }

    Write-Log "Desinstallation de '$($entry.DisplayName)' (version : $($entry.DisplayVersion))..."
    $uninstallStr = $entry.UninstallString

    if ($uninstallStr -match 'msiexec') {
        # Desinstallation MSI
        $guid = if ($uninstallStr -match '\{[0-9A-Fa-f\-]+\}') { $Matches[0] } else { $null }
        if ($guid) {
            $proc = Start-Process -FilePath 'msiexec.exe' `
                        -ArgumentList "/x $guid /quiet /norestart" `
                        -Wait -PassThru
            if ($proc.ExitCode -in 0, 1605, 3010) {
                Write-Log "Desinstallation de '$DisplayName' reussie (code : $($proc.ExitCode))." 'OK'
            } else {
                Write-Log "Desinstallation de '$DisplayName' - code de retour : $($proc.ExitCode)" 'WARN'
            }
        } else {
            Write-Log "Impossible d'extraire le GUID MSI pour '$DisplayName'." 'ERROR'
        }
    } else {
        # Desinstallation EXE silencieuse
        $proc = Start-Process -FilePath 'cmd.exe' `
                    -ArgumentList "/c $uninstallStr /S /SILENT /quiet" `
                    -Wait -PassThru
        Write-Log "Desinstallation EXE de '$DisplayName' - code de retour : $($proc.ExitCode)." 'OK'
    }
}

function Remove-DirectorySafely {
    param([string]$Path)
    if (Test-Path $Path) {
        Write-Log "Suppression du repertoire : $Path"
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Write-Log "Repertoire supprime : $Path" 'OK'
        } catch {
            Write-Log "Erreur lors de la suppression de '$Path' : $_" 'ERROR'
        }
    } else {
        Write-Log "Repertoire introuvable (ignore) : $Path" 'WARN'
    }
}

function Remove-RegistryKeyHKLM {
    <#
    .SYNOPSIS Supprime une cle de registre sous HKLM en vue 64 bits.
    #>
    param([string]$SubKey)

    try {
        $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        $key = $hive.OpenSubKey($SubKey, $false)
        if ($null -ne $key) {
            $key.Close()
            $hive.DeleteSubKeyTree($SubKey, $false)
            Write-Log "Cle registre supprimee : HKLM\$SubKey" 'OK'
        } else {
            Write-Log "Cle registre introuvable (ignoree) : HKLM\$SubKey" 'WARN'
        }
        $hive.Close()
    } catch {
        Write-Log "Erreur suppression cle registre 'HKLM\$SubKey' : $_" 'ERROR'
    }
}

# ================================================================================
Write-Log "================================================"
Write-Log " Desinstallation de l'Agent Medulla - Demarrage"
Write-Log "================================================"
Write-Log "Journal : $LogFile"
Write-Log ""

# --- Etape 1 : Suppression de la tache planifiee ---
Write-Log "--- Etape 1 : Suppression de la tache planifiee ---"

$scheduledTaskName = "Medulla Agent"
if (Get-ScheduledTask -TaskName $scheduledTaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $scheduledTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Log "Tache planifiee '$scheduledTaskName' supprimee." 'OK'
} else {
    Write-Log "Tache planifiee '$scheduledTaskName' introuvable, ignoree." 'WARN'
}

Write-Log ""

# --- Etape 2 : Arret et suppression des services Windows ---
Write-Log "--- Etape 2 : Arret et suppression des services ---"

# Services installes par l'agent Medulla (courants + heritage Pulse)
$servicesToRemove = @(
    'medullaagent',       # Service principal de l'agent Medulla
    'medullanetnotify',   # Service de notification reseau Medulla
    'sshd',              # Serveur OpenSSH (installe par le plugin updateopenssh)
    'ssh-agent',         # Agent SSH (installe par le plugin updateopenssh)
    'pulseagent',        # Heritage : ancienne denomination Pulse
    'pulsenetworknotify', # Heritage : ancienne denomination Pulse
    'tvnserver',          # TightVNC Server
    'tvnservice'          # TightVNC Service (variante)
)

foreach ($svcName in $servicesToRemove) {
    Stop-AndRemoveService -ServiceName $svcName
}

Write-Log ""

# --- Etape 3 : Arret des processus residuels ---
Write-Log "--- Etape 3 : Arret des processus residuels ---"

$processesToKill = @('python', 'pythonw', 'syncthing')
foreach ($procName in $processesToKill) {
    $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if ($procs) {
        $count = ($procs | Measure-Object).Count
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Log "Processus '$procName' arretes : $count instance(s)." 'OK'
    } else {
        Write-Log "Aucun processus '$procName' actif." 'WARN'
    }
}

Write-Log ""

# --- Etape 4 : Desinstallation de l'agent GLPI (inventaire) ---
Write-Log "--- Etape 4 : Desinstallation de l'agent GLPI (inventaire) ---"

if ($RemoveGLPI) {
    Remove-ProgramByDisplayName -DisplayName "GLPI Agent"
} else {
    Write-Log "Desinstallation de l'agent GLPI ignoree (-RemoveGLPI:`$false)." 'WARN'
}

Write-Log ""

# --- Etape 4b : Desinstallation de TightVNC ---
Write-Log "--- Etape 4b : Desinstallation de TightVNC ---"

if ($RemoveTightVNC) {
    Remove-ProgramByDisplayName -DisplayName "TightVNC"
} else {
    Write-Log "Desinstallation de TightVNC ignoree (-RemoveTightVNC:`$false)." 'WARN'
}

Write-Log ""

# --- Etape 5 : Desinstallation des modules Python Medulla ---
Write-Log "--- Etape 5 : Desinstallation des modules pip Medulla ---"

$pip3 = Join-Path $PythonDir 'Scripts\pip3.exe'
if (Test-Path $pip3) {
    $pipPackages = @(
        'pulse-xmpp-agent',
        'pulse-machine-plugins',
        'kiosk-interface',
        'syncthing2',
        'pulse_xmpp_agent',   # Variante avec underscore
        'kiosk_interface'     # Variante avec underscore
    )
    foreach ($pkg in $pipPackages) {
        Write-Log "Desinstallation du module pip : $pkg"
        $output = & $pip3 uninstall -y $pkg 2>&1
        Write-Log ("pip uninstall $pkg : " + ($output -join ' ')) 'OK'
    }
} else {
    Write-Log "pip3.exe introuvable dans '$PythonDir\Scripts\'. Modules pip non desinstalles." 'WARN'
}

Write-Log ""

# --- Etape 6 : Desinstallation de Python 3 ---
Write-Log "--- Etape 6 : Desinstallation de Python 3 ---"

if ($RemovePython) {
    # Desinstallation propre via le registre (Python 3.x installe dans C:\Program Files\Python3)
    Remove-ProgramByDisplayName -DisplayName "Python 3"

    # Suppression forcee du repertoire residuel si l'uninstalleur est absent ou incomplet
    Remove-DirectorySafely -Path $PythonDir

    # Heritage Python 2.7 (desinstallation via MSI si present)
    Remove-ProgramByDisplayName -DisplayName "Python 2.7"
    Remove-DirectorySafely -Path $Python27Dir
} else {
    Write-Log "Desinstallation de Python ignoree (-RemovePython:`$false)." 'WARN'
}

Write-Log ""

# --- Etape 7 : Suppression des repertoires d'installation ---
Write-Log "--- Etape 7 : Suppression des repertoires d'installation ---"

Remove-DirectorySafely -Path $MedullaDir
Remove-DirectorySafely -Path $MedullaDir32
Remove-DirectorySafely -Path $PulseDir    # Heritage
Remove-DirectorySafely -Path $PulseDir32  # Heritage

Write-Log ""

# --- Etape 8 : Suppression de la DLL libcurl ---
Write-Log "--- Etape 8 : Suppression de la DLL libcurl (cygcurl-4.dll) ---"

$libcurlFiles = @(
    "$env:SystemRoot\System32\cygcurl-4.dll",
    "$env:SystemRoot\SysWOW64\cygcurl-4.dll"
)
foreach ($dll in $libcurlFiles) {
    if (Test-Path $dll) {
        try {
            Remove-Item -Path $dll -Force -ErrorAction Stop
            Write-Log "DLL supprimee : $dll" 'OK'
        } catch {
            Write-Log "Erreur lors de la suppression de '$dll' : $_" 'ERROR'
        }
    } else {
        Write-Log "DLL introuvable (ignoree) : $dll" 'WARN'
    }
}

Write-Log ""

# --- Etape 9 : Suppression des certificats CA Medulla ---
Write-Log "--- Etape 9 : Suppression des certificats CA Medulla ---"

foreach ($storeName in @('Root', 'CA')) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        $storeName,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $certsToRemove = $store.Certificates | Where-Object {
            $_.Subject         -imatch 'medulla' -or
            $_.Issuer          -imatch 'medulla' -or
            $_.FriendlyName    -imatch 'medulla'
        }
        foreach ($cert in $certsToRemove) {
            Write-Log "Suppression certificat [$storeName] : Subject='$($cert.Subject)' Thumbprint=$($cert.Thumbprint)"
            $store.Remove($cert)
            Write-Log "Certificat supprime : $($cert.Thumbprint)" 'OK'
        }
        if (($certsToRemove | Measure-Object).Count -eq 0) {
            Write-Log "Aucun certificat Medulla trouve dans le magasin '$storeName'." 'WARN'
        }
    } catch {
        Write-Log "Erreur acces magasin de certificats '$storeName' : $_" 'ERROR'
    } finally {
        $store.Close()
    }
}

Write-Log ""

# --- Etape 10 : Nettoyage des cles de registre ---
Write-Log "--- Etape 10 : Nettoyage des cles de registre ---"

# Toutes les cles HKLM ecrites par l'installateur Medulla (vues 64 bits)
$registryKeys = @(
    # -- Entrees Programmes et fonctionnalites (cles courantes) --
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Agent',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Agent dependencies',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla network notify',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla SSH',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla CherryPy',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla CA Cert',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla RDP',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Syncthing',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Filetree Generator',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla PAExec',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Vim',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla kiosk launcher',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla kiosk interface',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Extract Drivers',
    # -- Cle de configuration de l'agent (PRODUCT_DIR_REGKEY) --
    'SOFTWARE\Medulla\Medulla Agent',
    'SOFTWARE\Medulla',
    # -- Heritage : anciennes cles Pulse --
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Pulse Agent',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Pulse Agent dependencies',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PAExec',
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Pulse CherryPy'
)

foreach ($key in $registryKeys) {
    Remove-RegistryKeyHKLM -SubKey $key
}

# Cles de registre TightVNC (optionnel)
if ($RemoveTightVNC) {
    $tightVncKeys = @(
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\TightVNC',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{8B9B2A58-9431-4195-B98A-43BCDC16C95F}_is1',
        'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{9A52C3B1-9980-4B5B-B2B6-E22BC1B6C76A}_is1'
    )
    foreach ($key in $tightVncKeys) {
        Remove-RegistryKeyHKLM -SubKey $key
    }
} else {
    Write-Log "Nettoyage des cles TightVNC ignore (-RemoveTightVNC:`$false)." 'WARN'
}

Write-Log ""
Write-Log "================================================"
Write-Log " Desinstallation de l'Agent Medulla - TERMINEE"
Write-Log " Journal complet : $LogFile"
Write-Log "================================================"

# SIG # Begin signature block
# MIInmgYJKoZIhvcNAQcCoIInizCCJ4cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBK17v8v7YG2Vit
# 7mErpYM/kXO384C93shL0Z+j32uoxKCCITIwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0GCSqG
# SIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEzODQg
# MjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C0Cit
# eLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce2vnS
# 1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0daE6ZM
# swEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6TSXBC
# Mo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoAFdE3
# /hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7OhD26j
# q22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM1bL5
# OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z8ujo
# 7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05huzU
# tw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNYmtwm
# KwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP/2NP
# TLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATANBgkq
# hkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95RysQDK
# r2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HLIvda
# qpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5BtfQ/g+
# lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnhOE7a
# brs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIhdXNS
# y0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV9zeK
# iwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/jwVYb
# KyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYHKi8Q
# xAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmCXBVm
# zGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l/aCn
# HwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZWeE4w
# gga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0Zo
# dLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi
# 6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNg
# xVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiF
# cMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJ
# m/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvS
# GmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1
# ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9
# MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7
# Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bG
# RinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6
# X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxj
# aaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0
# hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0
# F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnT
# mpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKf
# ZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzE
# wlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbh
# OhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOX
# gpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EO
# LLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wG
# WqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWg
# AwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# MB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEy
# NTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3
# zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8Tch
# TySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWj
# FDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2Uo
# yrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjP
# KHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KS
# uNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7w
# JNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vW
# doUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOg
# rY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K
# 096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCf
# gPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zy
# Me39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsG
# AQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# dDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZ
# D9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/
# ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu
# +WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4o
# bEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2h
# ECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasn
# M9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol
# /DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgY
# xQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3oc
# CVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcB
# ZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzCCB0AwggUo
# oAMCAQICEARvoM3TU+1ea7/ZhpWAu9QwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENB
# MTAeFw0yNTEwMjAwMDAwMDBaFw0yNjEwMTkyMzU5NTlaMIHIMRMwEQYLKwYBBAGC
# NzwCAQMTAkZSMR8wHQYLKwYBBAGCNzwCAQIMDsOObGUtZGUtRnJhbmNlMRYwFAYL
# KwYBBAGCNzwCAQETBVBhcmlzMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlv
# bjEUMBIGA1UEBRMLOTMzIDI2NyA1MjgxCzAJBgNVBAYTAkZSMQ4wDAYDVQQHEwVQ
# YXJpczESMBAGA1UEChMJTkFUU1UgU0FTMRIwEAYDVQQDEwlOQVRTVSBTQVMwggGi
# MA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCewwck94i/Ato6ovKoEUwfBrV5
# e7x4dk05s1BPbcxTO4vuPrCLwL4oG9Giy3tb+IdXYl/JQ7YrYcfzkU+mH7xrR4nJ
# On2/ZlU4Myfl6dfIhqe2CyU/lcHzRGAhMhenP2TR3ikCTj53ys6eyQpC06f+V0jx
# dH9DtvghCkgjALdYPH+8j0644SMwxGr8acUFR5ID33NZtTJSFGAgzt+KMYOX8/Hk
# Pl6MSDgfX0iV4U41k6ElQfcL7nfnawXCIUxzvTdc0lf5FnLJ5gOPL1Ek2GUt2iyf
# 3avGXY7zlVAtYYt17JZ0XvvtdgxYvISqQDK4lbplySgUI7XntgyfQzhWizVeG0/v
# cCFWmiTjS7f7gCHX/rNlREauOgC4iMwR9DsThObCPQAikxWxzD1x/yD0U/yRqdKF
# bZRyD/iL7mImrk84YPg5MKW+C/B5XrxUtggfbskQlBLVCgRvZveWxiT9EMx9g6CC
# bV7ASOTtc9vbfbNrwfIA8RcuvO8tKBRr9Peh0x8CAwEAAaOCAgIwggH+MB8GA1Ud
# IwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBSjU6Z9WoZ7Hd7L
# z0fQy92RTBc7zDA9BgNVHSAENjA0MDIGBWeBDAEDMCkwJwYIKwYBBQUHAgEWG2h0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2
# U0hBMzg0MjAyMUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFD
# QTEuY3JsMIGUBggrBgEFBQcBAQSBhzCBhDAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMFwGCCsGAQUFBzAChlBodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNydDAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQDKnUjF
# xO8eX7NVe2+k1UxzoOva78ATP/QLwZ+OzJVSfUndbfoyCVLL7QF+BTy1Ho6QOZ+i
# T/VsnvAasragmGaOI7ovgcr4WnC5580kKjso91t0HgFNNS0L5bGilVtkMA0fOIQ+
# QL2YJ9T27r20OBoW8Sz/liNghWD7jhe02peo2R9VVKo7OH9y/qO0MHVwdXrPX6Ok
# CLv10bOi0ievPlPYWOp3KvitSe6vN5gyatrrlOrf6RSSbcXvAJ/uBW+xISvpm5N0
# uubMDsHnWBUv6c6+IB9MZV0kTWRA1DYDQsTeEGPmVkBbacXsnN4/vD5xtJsBig41
# eoh6hbPfDuHeU32sBYWjHkgKGiOnTmQF0T1iihBrH56yyWnFy8LLoftFz932wkWp
# 8LARsoc7uCLeWEJVVg0tVMY+8vGDuPCjBTb+NvoArbFlzfmC3wcZQexGnuD/X1q3
# 3k0ss7CRZwToEqf/5Lu8MGS576AQTfIXaXUyIz4gI9Jm5YpS10wWYrMzboLALhxP
# j6fmWpOxdstoLUqWPbLvyjCN/zhASDeYdVodBHIJ9DrFJ833CpuhcGbej06M7wtW
# GTQaTSbe4HAQgG8nbMV3lr4dUGkhnCs4/EUyGIr8hxvhRN0Cc1GBWxDYPdsHEQbU
# +K70YuJ1sv7FQlF0E5fKvSflHVXw1vX3wAunhDGCBb4wggW6AgEBMH0waTELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdp
# Q2VydCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIx
# IENBMQIQBG+gzdNT7V5rv9mGlYC71DANBglghkgBZQMEAgEFAKBqMBkGCSqGSIb3
# DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEV
# MC8GCSqGSIb3DQEJBDEiBCBxWgalakwNr4E7FPM81GjZ+ckHFWUVTI9Xz35JMI1o
# hTANBgkqhkiG9w0BAQEFAASCAYBvxSN8tpyrP3BM/txl7qI1+ze3LpQdsDhxEye3
# ugQmuDWI0KEPL9NeEfQCFjj+FpXx6su56tCvhCJxoSyH8q/ZTAMGD9OLdFWwYIQQ
# QiWNVqmylpynMPr7M7YdtXYCcz1BWtv4gtrbtEUiXGq9uXR/tAK3zGKHQiFpG3ih
# AFrx6/bxtyyeQ+HngzQ0u0CSkSOHoIIXA7GYQQK35q3rHjMcpE43+JeoHosOjQf8
# /+g3aMVlQJ8Jxvw+rbgAPoWgLWpXHbIexjKB6hu99Z1923VlF8JInQpcibT+W4YF
# b32zlQbP8wYS550xjg9GtJkpklIu9jwj40VP2VQZQitcjsYCecxr2ZzXOSUTxXa0
# Xb29FstTtll4OtGY7BLnK73CUP8GfMMAfTo/SV6vrYFdrzGqmBjsTwYDXmFgMVFU
# Ng8ovCUwWTRMRMlmwbTAX8Pqt6chESmDlx1NNr3bXyBHgbwOPgbKHZrV2gHORg6m
# osy3rBWUY/6pm5Mqwp+muXO6MSKhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8C
# AQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYg
# U0hBMjU2IDIwMjUgQ0ExAhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUA
# oGkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYw
# NDI0MDY1NzI3WjAvBgkqhkiG9w0BCQQxIgQggzjEnEJsDXF+bq3d5vStRt7K8O/w
# 85iHpLKcHurEsj4wDQYJKoZIhvcNAQEBBQAEggIANzpkKr2bdFmy7VWPztCUJ/MZ
# Ej7LBax6bJLn3A1XNPh8MPgUpXObx2/ECgV+bFP5IfMdhULqMg4u8ZvnXNU725n9
# jvzGCqETULbGD9eP+hsUysvSLnz8O89DW8jeRNaZ9IGS3YC0K65pVCLmIkZBtxeU
# eyhZFk4PhM/VRnAKyZJXs6jTbm9VOF/OApYLnmbqrbDUrOdEkhyBVhuVTaXlsfms
# cliEATx6gZ15ToLeTacCfYaxACsK/z3b2kkDqyk2CvXxKdcwea5l5jdQnRBKzkNh
# yE2jV1gDUE/6mCUufEkcT1XTHBf9zt4Hsz+x6bElFLO8+zs23XWU8T4VbOgXBuGC
# EK9anrvfg0qfBVtQV4QuqJLno1JGIbUwpytYW6c7qmOJgar9HRXX1EknjVwG25ND
# gIcu0ztoymI8HajIow5wol//3i7+Xn7xcDs/l1k114SaDVW7tycdQ4lSSTv1z9GL
# 6ch/9U3JM3VMXA3UXiFUBpZB4i1M9LsTk+6lFeSRvNvQi2TESuBx1VmC6Mn58ZOu
# zhecZsVRXg48wadEgsPGdomQGoflnAFhcEcQCrjpo5lE+46F+RoBbcg8AN7Royvp
# UPgkKteEHUaocXLAndPa6JNT2SDeUL434bhrA3KEUzhi94rwzBF/3SQ07/Vju7QP
# x3CEN4W1d8SK+nCi2oY=
# SIG # End signature block
