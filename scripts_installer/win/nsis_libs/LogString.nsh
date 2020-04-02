; Logs macros
; Taken from http://stackoverflow.com/questions/9234402/how-to-save-detailprint-command-message-in-file-in-nsis-script

var hFileLog

!define LogInit "!insertmacro Log_Init"

!define LogString "!insertmacro Log_String"

!macro Log_Init logfile
  FileOpen $hFileLog "${logfile}" w
!macroend

!macro Log_String msg
  DetailPrint "${msg}"
  FileWrite $hFileLog "${msg}$\r$\n"
!macroend

!macro Log_Close
  FileWrite $hFileLog 'Done.'
  FileClose $hFileLog
!macroend
