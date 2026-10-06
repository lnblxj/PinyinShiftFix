@echo off
setlocal
cd /d "%~dp0.."
if not exist bin mkdir bin
set "TEST_CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
"%TEST_CSC%" /nologo /platform:x64 /warnaserror+ /out:bin\EngineTests.exe tests\EngineTests.cs src\PatchEngine.cs
if errorlevel 1 exit /b 1
"%TEST_CSC%" /nologo /target:winexe /platform:x64 /warnaserror+ /out:bin\TriggerLab.exe /reference:System.Windows.Forms.dll /reference:System.Drawing.dll tests\TriggerLab.cs tests\NativeIme.cs
exit /b %errorlevel%
