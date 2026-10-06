@echo off
setlocal
cd /d "%~dp0"
if not exist bin mkdir bin
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:winexe /platform:x64 /optimize+ /warnaserror+ /out:bin\PinyinShiftFix.exe /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /win32manifest:src\app.manifest src\PinyinShiftFix.cs src\PatchEngine.cs
exit /b %errorlevel%
