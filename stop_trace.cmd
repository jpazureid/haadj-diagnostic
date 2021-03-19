@echo off

REM *************************************************************************
REM *                  Setting environment variables                        *
REM *************************************************************************
set _LOG_DIR=%systemdrive%\AADLogs
set _NGC_TRACES_TMP=%_LOG_DIR%\NGC_trace.txt
set _BIO_TRACES_TMP=%_LOG_DIR%\BIO_trace.txt
set _LSA_TRACES_TMP=%_LOG_DIR%\LSA_trace.txt
set _NTLM_TRACES_TMP=%_LOG_DIR%\NTLM_trace.txt
set _KERB_TRACES_TMP=%_LOG_DIR%\KERB_trace.txt
set _CXH_TRACES_TMP=%_LOG_DIR%\CXH_trace.txt
set _CLOUDAP_TRACES_TMP=%_LOG_DIR%\CLOUDAP_trace.txt
set _TPM_TRACES_TMP=%_LOG_DIR%\TPM_trace.txt
set _WEB_AUTH_TRACES_TMP=%_LOG_DIR%\WEBAUTH_trace.txt
set _AAD_TRACES_TMP=%_LOG_DIR%\AAD_trace.txt

if "%_TRACE_VERSION%" == "" GOTO SIMPLE_VERSION

REM *************************************************************************
REM *                  Full version starts here                             *
REM *************************************************************************
:FULL_VERSION

echo ********** Stopping Full version of trace **********
echo ...

REM *************************************************************************
REM *                  Stopping Network trace                               *
REM *************************************************************************
echo ********** Stopping Network trace **********
echo ...
netsh trace stop

REM *************************************************************************
REM *                  Stopping all ETW log trace                           *
REM *************************************************************************
echo ********** Stopping all ETW log trace **********
echo ...

REM ******************************************************** stop NGC **************************************
logman stop NgcTraceAll -ets

certutil -delreg Enroll\Debug
copy /Y %WINDIR%\CertEnroll.log %_LOG_DIR%\CertEnrollWindir.log
copy /Y %USERPROFILE%\CertEnroll.log %_LOG_DIR%\CertEnrollUserProfile.log
copy /Y %LocalAppData%\CertEnroll.log %_LOG_DIR%\CertEnrollLocalAppData.log
copy /Y %WINDIR%\Ngc*.log %_LOG_DIR%\PregenLog.log

REM **Pregen Pool**
if EXIST %windir%\ngc*.log (xcopy /Y %windir%\ngc*.log %_LOG_DIR%\)
certutil -delreg ngc\Debug
REM ******************************************************** stop NGC **************************************

REM ******************************************************** stop Biometrics **************************************
logman stop BioTraceALl -ets
REM ******************************************************** stop Biometrics **************************************

REM ******************************************************** stop LSA **************************************
logman stop LsaTraceAll -ets
REM ******************************************************** stop LSA **************************************

REM ******************************************************** stop NTLM **************************************
logman stop NtlmTraceAll -ets
REM ******************************************************** stop NTLM **************************************

REM ******************************************************** stop KERB **************************************
logman stop KerbTraceAll -ets
REM ******************************************************** stop KERB **************************************

REM ******************************************************** stop AAD **************************************
logman stop AADTraceAll -ets
REM ******************************************************** stop AAD **************************************

REM ******************************************************** stop Cloud Experience **************************************
logman stop CxhTraceAll -ets
REM ******************************************************** stop Cloud Experience **************************************

REM ******************************************************** stop CloudAP  **************************************
logman stop CloudAPTraceAll -ets
reg delete HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters /v InfoLevel /f
reg delete HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters /v InfoLevel /f
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /f
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /f
reg delete HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /f
REM ******************************************************** stop CloudAP  **************************************

REM ******************************************************** stop WebAuth **************************************
logman stop WebAuthTraceAll -ets
nltest /dbflag:0x0
copy /y %windir%\debug\netlogon.log  %_LOG_DIR%
copy /y %windir%\system32\lsass.log  %_LOG_DIR%
copy /y %windir%\debug\netsetup.log  %_LOG_DIR%

REM ********* WebAuth
wevtutil.exe set-log "Microsoft-Windows-WebAuth/Operational" /enabled:false
wevtutil.exe export-log "Microsoft-Windows-WebAuth/Operational" %_LOG_DIR%\webauth.evtx /overwrite:true

REM ********* WebAuthN
wevtutil.exe export-log "Microsoft-Windows-WebAuthN/Operational" %_LOG_DIR%\webauthN.evtx /overwrite:true
REM ******************************************************** stop WebAuth **************************************

REM ******************************************************** stop TPM **************************************
logman stop TPMTraceAll -ets
REM ******************************************************** stop TPM **************************************

REM ******************************************************** stop WAM **************************************
logman stop WAMTrace -ets
REM ******************************************************** stop WAM **************************************

GOTO SIMPLE_VERSION
REM *************************************************************************
REM *                  Full version ends here                               *
REM *************************************************************************




REM *************************************************************************
REM *                  Simple version starts here                           *
REM *************************************************************************
:SIMPLE_VERSION
if "%_TRACE_VERSION%" == "" echo ********** Stopping simple version of trace ********** 

REM *************************************************************************
REM *            Stop PSR                                                   *
REM *************************************************************************
echo ********** Stopping PSR **********
echo ...
psr.exe /stop >nul

REM *************************************************************************
REM *         Getting event logs and cleaning up                            *
REM *************************************************************************
echo ********** Getting event logs and cleaning up **********
echo ...
REM ****************************************************************************************************************** Get event logs

REM ********* AAD events
echo ********** Getting AAD event logs **********
echo ...
wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:false
wevtutil.exe epl "Microsoft-Windows-AAD/Analytic" %_LOG_DIR%\aad_analytic.evtx /overwrite:true
REM wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:true /rt:false /q:true
wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:false
wevtutil.exe epl "Microsoft-Windows-AAD/Operational" %_LOG_DIR%\aad_oper.evtx /overwrite:true
wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:true

REM ********* Bio events
echo ********** Getting Biometrics event logs **********
echo ...
wevtutil.exe set-log  Microsoft-Windows-Biometrics/Operational /enabled:false
wevtutil.exe epl Microsoft-Windows-Biometrics/Operational %_LOG_DIR%\winbio.evtx /overwrite:true

REM ********* CAPI2 events
echo ********** Getting CAPI2 event logs **********
echo ...
wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" %_LOG_DIR%\capi2.evtx /overwrite:true
wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:false /ms:1048576

REM ********* HelloForBusiness events
echo ********** Getting HelloForBusiness event logs **********
echo ...
wevtutil.exe export-log "Microsoft-Windows-HelloForBusiness/Operational" %_LOG_DIR%\HelloForBusiness.evtx /overwrite:true

REM ********* Kerberos events
echo ********** Getting Kerberos event logs **********
echo ...
wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:false
wevtutil.exe epl "Microsoft-Windows-Kerberos/Operational" %_LOG_DIR%\kerb.evtx /overwrite:true

REM ********* User device events
echo ********** Getting User device event logs **********
echo ...
wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /enabled:false
wevtutil.exe epl "Microsoft-Windows-User Device Registration/Debug" %_LOG_DIR%\usrdevicereg_dbg.evtx /overwrite:true

wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:false
wevtutil.exe epl "Microsoft-Windows-User Device Registration/Admin" %_LOG_DIR%\usrdevicereg_adm.evtx /overwrite:true
wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Admin" /enabled:true

REM ********* Workplace Join events
echo ********** Getting Workplace Join event logs **********
echo ...
wevtutil.exe export-log "Microsoft-Windows-Workplace Join/Admin" %_LOG_DIR%\Workplace_Join.evtx /overwrite:true

REM ********** Getting System, Application and Security event logs **********
echo ********** Getting System, Application and Security event logs **********
echo ...
wevtutil epl system %_LOG_DIR%\SystemEvent.evtx
wevtutil epl Application %_LOG_DIR%\ApplicationEvent.evtx
wevtutil epl Security %_LOG_DIR%\Security.evtx
REM ****************************************************************************************************************** Get event logs


REM *************************************************************************
REM *         Getting All configurations                                    *
REM *************************************************************************
echo ********** Getting dsregcmd information **********
echo ...
REM ****************************************************************************************************************** dsregcmd at end
dsregcmd.exe /status > %_LOG_DIR%\dsregcmd_status_admin_end.txt
dsregcmd.exe /debug /status > %_LOG_DIR%\dsregcmd_debug_status_admin_end.txt
REM ****************************************************************************************************************** dsregcmd at end

echo ********** Getting environment information **********
echo ...
REM ****************************************************************************************************************** Get environment info
set > %_LOG_DIR%\env.txt

REM ****************************************************************************************************************** Get build info
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildLabEx > %_LOG_DIR%\REG_BUILD.txt

REM ****************************************************************************************************************** Get local SCP info
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ" /s > %_LOG_DIR%\SCP_REG_CDJ.txt

REM ****************************************************************************************************************** Getting information
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication" /s > %_LOG_DIR%\REG_authentication.txt 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Winbio" /s > %_LOG_DIR%\REG_winbio.txt 2>&1
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /s > %_LOG_DIR%\REG_wbiosrvc.txt 2>&1
reg query "HKLM\SYSTEM\CurrentControlSet\Control\EAS\Policies" /s > %_LOG_DIR%\REG_eas.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /s > %_LOG_DIR%\REG_policies.txt 2>&1
reg query "HKCU\SOFTWARE\Microsoft\SCEP" /s > %_LOG_DIR%\REG_scep.txt 2>&1
reg query "HKLM\SOFTWARE\Microsoft\SQMClient" /s > %_LOG_DIR%\REG_MachineId.txt 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Policies\PassportForWork" /s > %_LOG_DIR%\REG_NgcPolicyIntune.txt 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /s > %_LOG_DIR%\REG_NgcPolicyGp.txt 2>&1
reg query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock" /s > %_LOG_DIR%\REG_DeviceLockPolicy.txt 2>&1
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin" /s > %_LOG_DIR%\REG_WPJ.txt 2>&1
reg query "HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin" /s > %_LOG_DIR%\REG_CloudDomainJoin.txt 2>&1
reg query "HKLM\Software\Microsoft\IdentityStore" /s > %_LOG_DIR%\REG_idstore_config.txt
reg query "HKLM\Software\Microsoft\IdentityCRL" /s >> %_LOG_DIR%\REG_idstore_config.txt
reg query "HKEY_USERS\.Default\Software\Microsoft\IdentityCRL" /s >> %_LOG_DIR%\REG_idstore_config.txt

cmdkey.exe /list > %_LOG_DIR%\credman.txt
klist.exe > %_LOG_DIR%\klist.txt

wmic datafile where "name='%SystemDrive%\\Windows\\System32\\kerberos.dll' or name='%SystemDrive%\\Windows\\System32\\kdcsvc.dll' or name='%SystemDrive%\\Windows\\System32\\msv1_0.dll' or name='%SystemDrive%\\Windows\\System32\\negoexts.dll' or name='%SystemDrive%\\Windows\\System32\\pku2u.dll' or name='%SystemDrive%\\Windows\\System32\\schannel.dll' or name='%SystemDrive%\\Windows\\System32\\wdigest.dll' or name='%SystemDrive%\\Windows\\System32\\tspkg.dll' or name='%SystemDrive%\\Windows\\System32\\dpapisrv.dll' or name='%SystemDrive%\\Windows\\System32\\idstore.dll' or name='%SystemDrive%\\Windows\\System32\\livessp.dll' or name='%SystemDrive%\\Windows\\System32\\wlidsvc.dll' or name='%SystemDrive%\\Windows\\System32\\idlisten.dll' or name='%SystemDrive%\\Windows\\System32\\basecsp.dll' or name='%SystemDrive%\\Windows\\System32\\scksp.dll' or name='%SystemDrive%\\Windows\\System32\\vaultsvc.dll' or name='%SystemDrive%\\Windows\\System32\\vault.dll' or name='%SystemDrive%\\Windows\\System32\\bcrypt.dll' or name='%SystemDrive%\\Windows\\System32\\bcryptprimitives.dll' or name='%SystemDrive%\\Windows\\System32\\ncrypt.dll' or name='%SystemDrive%\\Windows\\System32\\ncryptprov.dll' or name='%SystemDrive%\\Windows\\System32\\cryptsp.dll' or name='%SystemDrive%\\Windows\\System32\\rsaenh.dll' or name='%SystemDrive%\\Windows\\System32\\winhttp.dll' or name='%SystemDrive%\\Windows\\System32\\wininet.dll'" get Filename, Version | more >> %_LOG_DIR%\\build.txt
wmic qfe list > %_LOG_DIR%\qfes_installed.txt

whoami /UPN > %_LOG_DIR%\whoami_upn_admin.txt
whoami /ALL > %_LOG_DIR%\whoami_all_admin.txt
REM ****************************************************************************************************************** Getting information


REM ****************************************************************************************************************** Get WinHTTP & WinInet Info
echo ********** Getting Proxy information **********
echo ...
netsh winhttp show proxy > %_LOG_DIR%\winhttp_proxy.txt
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /s > %_LOG_DIR%\REG_WinINet01.txt
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /s > %_LOG_DIR%\REG_WinINet02.txt
REM ****************************************************************************************************************** Get WinHTTP & WinInet Info


REM ****************************************************************************************************************** Get certificate information
echo ********** Getting Certificate information **********
echo ...
certutil -v -silent -store MY > %_LOG_DIR%\cert-machine-my.txt
certutil -v -silent -store -user MY > %_LOG_DIR%\cert-user-my.txt

certutil -scinfo -silent > %_LOG_DIR%\scinfo.txt 2>&1
certutil -tpminfo > %_LOG_DIR%\tpminfo.txt 2>&1
Certutil.exe -v -silent -store "Homegroup Machine Certificates" > %_LOG_DIR%\homegroup-machine-store.txt
REM ****************************************************************************************************************** Get certificate information


REM ****************************************************************************************************************** Getting network status
echo ********** Getting network status **********
echo ...
Powershell.exe -ExecutionPolicy Bypass -File Test-DeviceRegConnectivity.ps1 > %_LOG_DIR%\Test-DeviceRegConnectivity_Result.txt
REM ****************************************************************************************************************** Getting network status


REM ****************************************************************************************************************** Getting GPO information
echo ********** Getting GPO information **********
echo ...
gpresult /V > %_LOG_DIR%\GPResult_V_admin.txt
gpresult /H %_LOG_DIR%\GPResult_H_admin.html
REM ****************************************************************************************************************** Getting GPO information



REM *************************************************************************
REM *         Simple version ends here                                      *
REM *************************************************************************


REM *************************************************************************
REM *         Simple version ends here                                      *
REM *************************************************************************
echo.
echo Your logs have been successfully copied to %_LOG_DIR%.
goto cleanup

:cleanup
set _LOG_DIR=
set _TRACE_VERSION=
