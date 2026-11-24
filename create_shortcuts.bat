@echo off
echo Creating shortcuts...

REM Desktop shortcut
powershell -Command "$WS = New-Object -ComObject WScript.Shell; $SC = $WS.CreateShortcut('%USERPROFILE%\Desktop\PE Analyzer.lnk'); $SC.TargetPath = '%~dp0dist\PE_Static_Analyzer.exe'; $SC.WorkingDirectory = '%~dp0'; $SC.Save()"

REM Start menu shortcut
powershell -Command "$WS = New-Object -ComObject WScript.Shell; $SC = $WS.CreateShortcut('%APPDATA%\Microsoft\Windows\Start Menu\Programs\PE Analyzer.lnk'); $SC.TargetPath = '%~dp0dist\PE_Static_Analyzer.exe'; $SC.WorkingDirectory = '%~dp0'; $SC.Save()"

echo Shortcuts created successfully!
echo - Desktop: PE Analyzer.lnk
echo - Start Menu: PE Analyzer.lnk
pause
