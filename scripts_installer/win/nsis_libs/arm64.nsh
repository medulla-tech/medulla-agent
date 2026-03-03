; SPDX-FileCopyrightText: 2024 Siveo <support@siveo.net>
; SPDX-License-Identifier: GPL-3.0-or-later

; ARM64 architecture detection macros for NSIS
; Detects Windows on ARM (WoA) via PROCESSOR_ARCHITEW6432 / PROCESSOR_ARCHITECTURE
; Note: NSIS is a 32-bit x86 app, so on ARM64 it runs under x86 emulation.
; In that context, PROCESSOR_ARCHITECTURE = "x86" and PROCESSOR_ARCHITEW6432 = "ARM64".
; We check PROCESSOR_ARCHITEW6432 first (WoW64 real arch), then fall back to PROCESSOR_ARCHITECTURE.

!ifndef ARM64_NSH
!define ARM64_NSH

!include "LogicLib.nsh"

; Macro to check if running on ARM64
; Checks PROCESSOR_ARCHITEW6432 first (real arch for WoW64 processes),
; then falls back to PROCESSOR_ARCHITECTURE (for native ARM64 processes)
!macro _IsARM64 _a _b _t _f
  System::Call 'kernel32::GetEnvironmentVariable(t "PROCESSOR_ARCHITEW6432", t .r0, i ${NSIS_MAX_STRLEN})'
  StrCmp $0 "ARM64" `${_t}` 0
  System::Call 'kernel32::GetEnvironmentVariable(t "PROCESSOR_ARCHITECTURE", t .r0, i ${NSIS_MAX_STRLEN})'
  StrCmp $0 "ARM64" `${_t}` `${_f}`
!macroend

!define IsARM64 `"" IsARM64 ""`

!endif ; ARM64_NSH
