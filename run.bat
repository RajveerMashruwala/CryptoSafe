@echo off
cd /d "%~dp0"
if not exist out mkdir out
javac -encoding UTF-8 -cp "lib/*" -d out CryptoSafe.java || (pause & exit /b 1)
java -cp "out;lib/*" CryptoSafe
pause
