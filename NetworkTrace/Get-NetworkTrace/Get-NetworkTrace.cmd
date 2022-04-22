@echo off

echo Ensure you run this as Administrator!
echo Press CTRL-C if not and restart with Elevation.
echo Otherwise press any Key to start!

set mydate=%date:/=%
set mydate=%mydate:.=%
set mytime=%time::=%
set mytimestamp=%mydate: =_%_%mytime:.=_%

set ETL=%USERPROFILE%\Desktop\networktrace_%mytimestamp%.etl

netsh trace start persistent=yes capture=yes tracefile=%COMPUTERNAME%.etl

echo Reproduce the Issue, then press any key to stop the Packet Capture!
pause

netsh trace stop
echo Now send me the generated file: %ETL%

pause