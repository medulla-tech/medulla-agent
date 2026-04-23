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
