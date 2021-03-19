@echo off

REM *************************************************************************
REM *                  Setting environment variables                        *
REM *************************************************************************
echo ********** Setting Environment Valuables for trace **********
echo ...
set _LOG_DIR=%systemdrive%\AADLogs
set _SCRIPT_PATH=%~dp0%
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
set _WAM_TRACES_TMP=%_LOG_DIR%\WAM_trace.txt


REM *************************************************************************
REM *                  Setting log file path                                *
REM *************************************************************************
IF EXIST %_LOG_DIR% ( rd /s /q %_LOG_DIR% )
md %_LOG_DIR%


REM *************************************************************************
REM *                  Getting parameters                                   *
REM *************************************************************************
IF "%1" == "-full" GOTO FULL_VERSION
IF "%1" == "-FULL" GOTO FULL_VERSION

IF "%1" == "-simple" GOTO SIMPLE_VERSION
IF "%1" == "-SIMPLE" GOTO SIMPLE_VERSION
IF "%1" == "" GOTO SIMPLE_VERSION

REM *************************************************************************
REM *                  Full version starts here                             *
REM *************************************************************************
:FULL_VERSION

echo ********** Starting Full version of trace **********
echo ...
REM ***************************************************** Set Envi for stop to use
set _TRACE_VERSION=full

REM ********************************************************** NGC TRACES **
REM *
(
    echo {B66B577F-AE49-5CCF-D2D7-8EB96BFD440C} 0x0
    echo {CAC8D861-7B16-5B6B-5FC0-85014776BDAC} 0x0
    echo {6D7051A0-9C83-5E52-CF8F-0ECAF5D5F6FD} 0x0
    echo {0ABA6892-455B-551D-7DA8-3A8F85225E1A} 0x0
    echo {9DF6A82D-5174-5EBF-842A-39947C48BF2A} 0x0
    echo {9B223F67-67A1-5B53-9126-4593FE81DF25} 0x0
    echo {89F392FF-EE7C-56A3-3F61-2D5B31A36935} 0x0
    echo {CDD94AC7-CD2F-5189-E126-2DEB1B2FACBF} 0x0
    echo {2056054C-97A6-5AE4-B181-38BC6B58007E} 0x0
    echo {786396CD-2FF3-53D3-D1CA-43E41D9FB73B} 0x0
    echo {1D6540CE-A81B-4E74-AD35-EEF8463F97F5} 0xffff
    echo {3A8D6942-B034-48e2-B314-F69C2B4655A3} 0xffffffff
    echo {D5A5B540-C580-4DEE-8BB4-185E34AA00C5} 0x0
    echo {7955d36a-450b-5e2a-a079-95876bca450a} 0x0
    echo {c3feb5bf-1a8d-53f3-aaa8-44496392bf69} 0x0
    echo {78983c7d-917f-58da-e8d4-f393decf4ec0} 0x0
    echo {36FF4C84-82A2-4B23-8BA5-A25CBDFF3410} 0x0
    echo {225b3fed-0356-59d1-1f82-eed163299fa8} 0x0
    echo {9dadd79b-d556-53f2-67c4-129fa62b7512} 0x0
    echo {1B5106B1-7622-4740-AD81-D9C6EE74F124} 0x0
    echo {1d480c11-3870-4b19-9144-47a53cd973bd} 0x0
    echo {39A5AA08-031D-4777-A32D-ED386BF03470} 0x0
    echo {F0DB7EF8-B6F3-4005-9937-FEB77B9E1B43} 0x0
    echo {54164045-7C50-4905-963F-E5BC1EEF0CCA} 0x0
    echo {89a2278b-c662-4aff-a06c-46ad3f220bca} 0x0
    echo {BC0669E1-A10D-4A78-834E-1CA3C806C93B} 0x0
    echo {BEA18B89-126F-4155-9EE4-D36038B02680} 0x0
    echo {5bbca4a8-b209-48dc-a8c7-b23d3e5216fb} 0x00FFFFFF
) >%_NGC_TRACES_TMP%
REM ********************************************************** NGC TRACES **

REM ********************************************************** Bio Traces **
REM *
(
    echo {7955d36a-450b-5e2a-a079-95876bca450a} 0x0
    echo {c3feb5bf-1a8d-53f3-aaa8-44496392bf69} 0x0
    echo {78983c7d-917f-58da-e8d4-f393decf4ec0} 0x0
    echo {36FF4C84-82A2-4B23-8BA5-A25CBDFF3410} 0x0
    echo {34BEC984-F11F-4F1F-BB9B-3BA33C8D0132} 0x0
    echo {225b3fed-0356-59d1-1f82-eed163299fa8} 0x0
    echo {9dadd79b-d556-53f2-67c4-129fa62b7512} 0x0
    echo {1B5106B1-7622-4740-AD81-D9C6EE74F124} 0x0
    echo {1d480c11-3870-4b19-9144-47a53cd973bd} 0x0
    echo {39A5AA08-031D-4777-A32D-ED386BF03470} 0x0
) >%_BIO_TRACES_TMP%
REM ********************************************************** Bio Traces **

REM ********************************************************** LSA Traces **
REM *LSA lsasrv.dll
REM *LSA LsaIso
(
    echo {D0B639E0-E650-4D1D-8F39-1580ADE72784} 0x40141F
    echo {169EC169-5B77-4A3E-9DB6-441799D5CACB} 0xffffff
    echo {DAA76F6A-2D11-4399-A646-1D62B7380F15} 0xffffff
    echo {366B218A-A5AA-4096-8131-0BDAFCC90E93} 0xffffffff
) >%_LSA_TRACES_TMP%
REM ********************************************************** LSA Traces **

REM ********************************************************** NTLM Traces **
REM *NtlmShared
REM *msv1_0.dll
(
    echo {AC69AE5B-5B21-405F-8266-4424944A43E9} 0xffffffff
    echo {5BBB6C18-AA45-49b1-A15F-085F7ED0AA90} 0x15003
) >%_NTLM_TRACES_TMP%
REM ********************************************************** NTLM Traces **

REM ********************************************************** Kerb Traces **
REM *Kerb Comm Trace
REM *Kerb Client Shared
REM *Kerb Client2
REM *Kerb Server
REM *Kps
(
    echo {60A7AB7A-BC57-43E9-B78A-A1D516577AE3} 0xffffff
    echo {FACB33C4-4513-4C38-AD1E-57C1F6828FC0} 0xffffffff
    echo {6B510852-3583-4e2d-AFFE-A67F9F223438} 0x201207
    echo {1BBA8B19-7F31-43c0-9643-6E911F79A06B} 0x23083
    echo {97A38277-13C0-4394-A0B2-2A70B465D64F} 0xff
) >%_KERB_TRACES_TMP%
REM ********************************************************** Kerb Traces **

REM ********************************************************** Cloud Experience**
REM CloudExperienceHost  -chx
(
    echo {d0034f5e-3686-5a74-dc48-5a22dd4f3d5b} 0x0
) >%_CXH_TRACES_TMP%
REM ********************************************************** Cloud Experience**

REM ********************************************************** Cloud AP Traces **
REM *CloudAp
REM *AAD CloudAp
REM *NegoExts
REM *DcLocator
REM *pku2u
(
    echo {EC3CA551-21E9-47D0-9742-1195429831BB} 0xfff
    echo {556045FD-58C5-4A97-9881-B121F68B79C5} 0xFFF
    echo {5AF52B0D-E633-4ead-828A-4B85B8DAAC2B} 0xFFFF
    echo {CA030134-54CD-4130-9177-DAE76A3C5791} 0xfffffff
    echo {2A6FAF47-5449-4805-89A3-A504F3E221A6} 0xFFFF
) >%_CLOUDAP_TRACES_TMP%
REM ********************************************************** Cloud AP Traces **

REM ********************************************************** Web Auth Traces **
REM *
(
    echo {37D2C3CD-C5D4-4587-8531-4696C44244C8} 0x0000FDFF
    echo {FB6A424F-B5D6-4329-B9B5-A975B3A93EAD} 0x000003FF
    echo {6165F3E2-AE38-45D4-9B23-6B4818758BD9} 0x0000FFFF
    echo {EA3F84FC-03BB-540e-B6AA-9664F81A31FB} 0xFFFF
    echo {133A980D-035D-4E2D-B250-94577AD8FCED} 0xFFFFFFFF
    echo {7FDD167C-79E5-4403-8C84-B7C0BB9923A1} 0xFFF
    echo {A74EFE00-14BE-4ef9-9DA9-1484D5473302} 0xFFFFFFFF
    echo {A74EFE00-14BE-4ef9-9DA9-1484D5473301} 0xFFFFFFFF
    echo {A74EFE00-14BE-4ef9-9DA9-1484D5473305} 0xFFFFFFFF
    echo {2A3C6602-411E-4DC6-B138-EA19D64F5BBA} 0xFFFF
    echo {EF98103D-8D3A-4BEF-9DF2-2156563E64FA} 0xFFFF
    echo {B3A7698A-0C45-44DA-B73D-E181C9B5C8E6} 0x7FFFFF
    echo {4E749B6A-667D-4c72-80EF-373EE3246B08} 0x7FFFFF
    echo {20F61733-57F1-4127-9F48-4AB7A9308AE2} 0xFFFFFFFF
    echo {D93FE84A-795E-4608-80EC-CE29A96C8658} 0x7FFFFFFF
    echo {3F8B9EF5-BBD2-4C81-B6C9-DA3CDB72D3C5} 0x7
    echo {B1108F75-3252-4b66-9239-80FD47E06494} 0x2FF
    echo {C10B942D-AE1B-4786-BC66-052E5B4BE40E} 0x3FF
    echo {82c7d3df-434d-44fc-a7cc-453a8075144e} 0x2FF
) >%_WEB_AUTH_TRACES_TMP%
REM ********************************************************** Web Auth Traces **

REM ********************************************************** AAD Traces **
REM *Microsoft-Windows-AAD WAM Provider
(
    echo {4DE9BC9C-B27A-43C9-8994-0915F1A5E24F} 0xffffff
) >%_AAD_TRACES_TMP%
REM ********************************************************** AAD Traces **

REM ********************************************************** TPM Traces **
REM *TpmWppControl
(
    echo {3A8D6942-B034-48E2-B314-F69C2B4655A3} 0xff
) >%_TPM_TRACES_TMP%
REM ********************************************************** TPM Traces **

REM ********************************************************** WAM Traces **
REM *
(
    echo {077b8c4a-e425-578d-f1ac-6fdf1220ff68} 0xffffffffffffffff
    echo {5836994d-a677-53e7-1389-588ad1420cc5} 0xffffffffffffffff
    echo {05f02597-fe85-4e67-8542-69567ab8fd4f} 0xffffffffffffffff
    echo {d0034f5e-3686-5a74-dc48-5a22dd4f3d5b} 0x0
    echo {4DE9BC9C-B27A-43C9-8994-0915F1A5E24F} 0xffffff
    echo {556045FD-58C5-4A97-9881-B121F68B79C5} 0xFFF
    echo {EC3CA551-21E9-47D0-9742-1195429831BB} 0xfff
    echo {63b6c2d2-0440-44de-a674-aa51a251b123} 0xffffffffffffffff
    echo {4180c4f7-e238-5519-338f-ec214f0b49aa} 0xffffffffffffffff
    echo {EB65A492-86C0-406A-BACE-9912D595BD69} 0xffffffffffffffff
    echo {d49918cf-9489-4bf1-9d7b-014d864cf71f} 0xffffffffffffffff
    echo {7acf487e-104b-533e-f68a-a7e9b0431edb} 0xffffffffffffffff
    echo {4E749B6A-667D-4c72-80EF-373EE3246B08} 0x7FFFFF
    echo {bfed9100-35d7-45d4-bfea-6c1d341d4c6b} 0xffffffffffffffff
    echo {ac01ece8-0b79-5cdb-9615-1b6a4c5fc871} 0xffffffffffffffff
    echo {1941f2b9-0939-5d15-d529-cd333c8fed83} 0xffffffffffffffff
    echo {0001376b-930d-50cd-2b29-491ca938cd54} 0xffffffffffffffff
    echo {072665fb-8953-5a85-931d-d06aeab3d109} 0xffffffffffffffff
    echo {f6a774e5-2fc7-5151-6220-e514f1f387b6} 0xffffffffffffffff
    echo {a48e7274-bb8f-520d-7e6f-1737e9d68491} 0xffffffffffffffff
    echo {88cd9180-4491-4640-b571-e3bee2527943} 0xffffffffffffffff    
    echo {833e7812-d1e2-5172-66fd-4dd4b255a3bb} 0xffffffffffffffff
    echo {30ad9f59-ec19-54b2-4bdf-76dbfc7404a6} 0xffffffffffffffff
    echo {d229987f-edc3-5274-26bf-82be01d6d97e} 0xffffffffffffffff
    echo {8cde46fc-ca33-50ff-42b3-c64c1c731037} 0xffffffffffffffff
    echo {25756703-e23b-4647-a3cb-cb24d473c193} 0xffffffffffffffff
    echo {569cf830-214c-5629-79a8-4e9b58ea24bc} 0xffffffffffffffff

) >%_WAM_TRACES_TMP%
REM ********************************************************** WAM Traces **


echo ********** Starting all ETW log trace **********
echo ...
REM ********************************************************** start NGC *******************
logman create trace NgcTraceAll -pf %_NGC_TRACES_TMP% -ft 1:00 -rt -o %_LOG_DIR%\ngctraceall.etl -ets
certutil -setreg -f Enroll\Debug 0xffffffe3
certutil -setreg ngc\Debug 1
REM ********************************************************** start NGC *******************

REM ********************************************************** start Biometrics *******************
logman create trace BioTraceALl -pf %_BIO_TRACES_TMP% -ft 1:00 -rt -o %_LOG_DIR%\biotraceall.etl -ets
REM ********************************************************** start Biometrics *******************

REM ********************************************************** start LSA *******************
logman start LsaTraceAll -pf %_LSA_TRACES_TMP% -o %_LOG_DIR%\lsatrace.etl -ets
REM ********************************************************** start LSA *******************

REM ********************************************************** start NTLM *******************
logman start NtlmTraceAll -pf %_NTLM_TRACES_TMP% -o %_LOG_DIR%\ntlmtraceall.etl -ets
REM ********************************************************** start NTLM *******************

REM ********************************************************** start KERB *******************
logman start KerbTraceAll -pf %_KERB_TRACES_TMP% -o %_LOG_DIR%\kerbtraceall.etl -ets
REM ********************************************************** start KERB *******************

REM ********************************************************** start AAD *******************
logman start AADTraceAll -pf %_AAD_TRACES_TMP% -o %_LOG_DIR%\aadtraceall.etl -ets
REM ********************************************************** start AAD *******************

REM ********************************************************** Pregen Pool *******************
certutil -setreg ngc\Debug 1
REM ********************************************************** Pregen Pool *******************

REM ********************************************************** start Cloud Experience *******************
logman start CxhTraceAll -pf %_CXH_TRACES_TMP% -o %_LOG_DIR%\cxhtraceall.etl -ets
REM ********************************************************** start Cloud Experience *******************

REM ********************************************************** start CLOUDAP *******************
logman start CloudAPTraceAll -pf %_CLOUDAP_TRACES_TMP% -o %_LOG_DIR%\cloudaptraceall.etl -ets
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NegoExtender\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Pku2u\Parameters /v InfoLevel /t REG_DWORD /d 0xFFFF /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v SPMInfoLevel /t REG_DWORD /d 0x40141F /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LogToFile /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v NegEventMask /t REG_DWORD /d 0xF /f
REM ********************************************************** start CLOUDAP *******************

REM ********************************************************** start WEB AUTH *******************
nltest /dbflag:0x2000FFFF
logman start WebAuthTraceAll -pf %_WEB_AUTH_TRACES_TMP% -o %_LOG_DIR%\webauthtraceall.etl -ets

REM ********* WebAuth
wevtutil.exe set-log "Microsoft-Windows-WebAuth/Operational" /enabled:true

REM ********* WebAuthN is enabled by default
REM *wevtutil.exe set-log "Microsoft-Windows-WebAuthN/Operational" /enabled:true
REM ********************************************************** start WEB AUTH *******************

REM ********************************************************** start TPM *******************
logman start TPMTraceAll -pf %_TPM_TRACES_TMP% -o %_LOG_DIR%\tpmtraceall.etl -ets 2> nul
REM ********************************************************** start TPM *******************

REM ********************************************************** start WAM *******************
logman start WAMTrace -pf %_WAM_TRACES_TMP% -o %_LOG_DIR%\WAMTrace.etl -ets
REM ********************************************************** start WAM *******************


REM *************************************************************************
REM *                      Starting Network Trace                           *
REM *************************************************************************
echo ********** Start network trace **********
echo ...
netsh trace start capture=yes scenario=InternetClient_dbg maxsize=2048 tracefile=%_LOG_DIR%\network_trace.etl

GOTO SIMPLE_VERSION
REM *************************************************************************
REM *                  Full version ends here                               *
REM *************************************************************************



REM *************************************************************************
REM *                  Simple version starts here                           *
REM *************************************************************************
:SIMPLE_VERSION

if "%_TRACE_VERSION%" == "" echo ********** Starting Simple version of trace ********** 

REM *************************************************************************
REM *                     Configuring event logs                            *
REM *************************************************************************
echo ********** Configuring event logs for trace ********** 
echo ...
echo ********** Configuring AAD event log **********
echo ...
wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:false /q:true
wevtutil.exe export-log "Microsoft-Windows-AAD/Analytic" %_LOG_DIR%\aad_analytic_backup.evtx /ow:true
wevtutil.exe set-log "Microsoft-Windows-AAD/Analytic" /enabled:true /rt:false /q:true
wevtutil.exe set-log "Microsoft-Windows-AAD/Operational" /enabled:true

echo ********** Configuring Biometrics event log **********
echo ...
wevtutil.exe set-log "Microsoft-Windows-Biometrics/Operational" /enabled:true

echo ********** Starting Configuring CAPI2 event log **********
echo ...
wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:true /ms:52428800

echo ********** Starting Configuring HelloForBusiness event log **********
echo ...
wevtutil.exe set-log "Microsoft-Windows-HelloForBusiness/Operational" /enabled:true

echo ********** Configuring Kerberos event log **********
echo ...
wevtutil.exe set-log "Microsoft-Windows-Kerberos/Operational" /enabled:true /rt:false /q:true

echo ********** Configuring User device event log **********
echo ...
wevtutil.exe set-log "Microsoft-Windows-User Device Registration/Debug" /enabled:true /rt:false /q:true

echo ********** Configuring Workplace Join event log **********
echo ...
wevtutil.exe set-log "Microsoft-Windows-Workplace Join/Admin" /enabled:true
REM ****************************************************************************************************************** Configure Event logs

REM ****************************************************************************************************************** dsregcmd at start
dsregcmd.exe /status > %_LOG_DIR%\dsregcmd_status_admin_start.txt
dsregcmd.exe /debug /status > %_LOG_DIR%\dsregcmd_debug_status_admin_start.txt
REM ****************************************************************************************************************** dsregcmd at start

REM *************************************************************************
REM *                         Starting PSR                                  *
REM *************************************************************************
echo ********** Starting PSR **********
echo ...
start psr.exe /start /output "%_LOG_DIR%\psr.zip" /gui 0 /sc 1 /maxsc 100 >nul

REM *************************************************************************
REM *                  Simple version ends here                             *
REM *************************************************************************

echo ***** All Tracing started *****
:cleanup
