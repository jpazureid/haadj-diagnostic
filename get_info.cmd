@echo off

REM ************************************************************************************ Get log file path
set _LOG_DIR=%systemdrive%\AADLogs

IF EXIST %_LOG_DIR% (@echo off) ELSE (md %_LOG_DIR%)

echo ********** Getting User information ********** 
REM ************************************************************************************* dsregcmd user
dsregcmd /status > %_LOG_DIR%\dsregcmd_status_user.txt

REM ************************************************************************************* Get certificate information
REM *** certutil -v -silent -store MY > %_LOG_DIR%\cert-machine-my.txt
REM *** certutil -v -silent -store -user MY > %_LOG_DIR%\cert-user-my.txt

REM ************************************************************************************* Get system info
systeminfo > %_LOG_DIR%\systeminfo.txt

REM ************************************************************************************* Get UPN info
whoami /UPN > %_LOG_DIR%\whoami_upn_user.txt
whoami /all > %_LOG_DIR%\whoami_all_user.txt

REM ************************************************************************************* Get SCP from AD
Powershell.exe -ExecutionPolicy Bypass -File get_scp.ps1 > %_LOG_DIR%\SCP_AD.txt

REM ************************************************************************************* Getting GPO information
echo ********** Getting GPO information **********
echo ...
gpresult /V > %_LOG_DIR%\GPResult_V_user.txt
gpresult /H %_LOG_DIR%\GPResult_H_user.html
