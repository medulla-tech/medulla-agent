if exist C:\Windows\Temp\kiosk.pid goto KILLPID
goto STARTKIOSK

:KILLPID
set /p pid=<C:\Windows\Temp\kiosk.pid
taskkill /PID %pid% /F
del /F /Q C:\Windows\Temp\kiosk.pid
goto STARTKIOSK

:STARTKIOSK
cmd.exe /c start /min "" "C:\Program Files\Python3\pythonw.exe" -m kiosk_interface
