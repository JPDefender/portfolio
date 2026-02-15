@echo off
REM ========================================================================
REM  Network Troubleshooting Script
REM  Author: softmetapod
REM
REM  Runs common network diagnostic commands and saves all output to a
REM  single troubleshooting document on the user's Desktop.
REM
REM  Usage:  Right-click -> Run as Administrator (recommended)
REM          Or run from an elevated Command Prompt:
REM              network_troubleshoot.bat
REM
REM  Output: %USERPROFILE%\Desktop\Network_Troubleshoot_Report.txt
REM ========================================================================

setlocal EnableDelayedExpansion

REM --- Configure output file ---
set "REPORT=%USERPROFILE%\Desktop\Network_Troubleshoot_Report.txt"
set "DIVIDER=======================================================================+"
set "TIMESTAMP=%DATE% %TIME%"

echo.
echo  ============================================
echo   Network Troubleshooting Script
echo   Report will be saved to:
echo   %REPORT%
echo  ============================================
echo.

REM --- Initialize report ---
(
    echo %DIVIDER%
    echo  NETWORK TROUBLESHOOTING REPORT
    echo  Computer : %COMPUTERNAME%
    echo  User     : %USERNAME%
    echo  Date/Time: %TIMESTAMP%
    echo %DIVIDER%
) > "%REPORT%"

REM =====================================================================
REM  1. IP Configuration
REM =====================================================================
echo [1/12] Gathering IP configuration...
(
    echo.
    echo %DIVIDER%
    echo  [1] IP CONFIGURATION  (ipconfig /all^)
    echo %DIVIDER%
    ipconfig /all
) >> "%REPORT%"

REM =====================================================================
REM  2. DNS Cache
REM =====================================================================
echo [2/12] Dumping DNS resolver cache...
(
    echo.
    echo %DIVIDER%
    echo  [2] DNS RESOLVER CACHE  (ipconfig /displaydns^)
    echo %DIVIDER%
    ipconfig /displaydns
) >> "%REPORT%"

REM =====================================================================
REM  3. Routing Table
REM =====================================================================
echo [3/12] Retrieving routing table...
(
    echo.
    echo %DIVIDER%
    echo  [3] ROUTING TABLE  (route print^)
    echo %DIVIDER%
    route print
) >> "%REPORT%"

REM =====================================================================
REM  4. ARP Table
REM =====================================================================
echo [4/12] Retrieving ARP table...
(
    echo.
    echo %DIVIDER%
    echo  [4] ARP TABLE  (arp -a^)
    echo %DIVIDER%
    arp -a
) >> "%REPORT%"

REM =====================================================================
REM  5. Active Connections / Listening Ports
REM =====================================================================
echo [5/12] Listing active connections and listening ports...
(
    echo.
    echo %DIVIDER%
    echo  [5] ACTIVE CONNECTIONS ^& LISTENING PORTS  (netstat -ano^)
    echo %DIVIDER%
    netstat -ano
) >> "%REPORT%"

REM =====================================================================
REM  6. Ping - Default Gateway
REM =====================================================================
echo [6/12] Pinging default gateway...
(
    echo.
    echo %DIVIDER%
    echo  [6] PING DEFAULT GATEWAY
    echo %DIVIDER%
) >> "%REPORT%"

REM Extract default gateway from ipconfig
for /f "tokens=2 delims=:" %%G in ('ipconfig ^| findstr /i "Default Gateway" ^| findstr /r "[0-9]"') do (
    set "GW=%%G"
    set "GW=!GW: =!"
    if not "!GW!"=="" (
        echo      Pinging gateway !GW! ...
        (
            echo  Gateway: !GW!
            ping -n 4 !GW!
        ) >> "%REPORT%"
    )
)

REM =====================================================================
REM  7. Ping - External (Google DNS 8.8.8.8)
REM =====================================================================
echo [7/12] Pinging external host 8.8.8.8...
(
    echo.
    echo %DIVIDER%
    echo  [7] PING EXTERNAL HOST  (8.8.8.8^)
    echo %DIVIDER%
    ping -n 4 8.8.8.8
) >> "%REPORT%"

REM =====================================================================
REM  8. Ping - DNS Resolution Test (google.com)
REM =====================================================================
echo [8/12] Pinging google.com (DNS resolution test)...
(
    echo.
    echo %DIVIDER%
    echo  [8] PING google.com  (DNS resolution test^)
    echo %DIVIDER%
    ping -n 4 google.com
) >> "%REPORT%"

REM =====================================================================
REM  9. Traceroute to 8.8.8.8
REM =====================================================================
echo [9/12] Running traceroute to 8.8.8.8 (this may take a moment)...
(
    echo.
    echo %DIVIDER%
    echo  [9] TRACEROUTE TO 8.8.8.8  (tracert^)
    echo %DIVIDER%
    tracert -d -w 1000 8.8.8.8
) >> "%REPORT%"

REM =====================================================================
REM  10. NSLookup
REM =====================================================================
echo [10/12] Running DNS lookups...
(
    echo.
    echo %DIVIDER%
    echo  [10] DNS LOOKUPS  (nslookup^)
    echo %DIVIDER%
    echo --- google.com ---
    nslookup google.com
    echo.
    echo --- microsoft.com ---
    nslookup microsoft.com
) >> "%REPORT%"

REM =====================================================================
REM  11. Windows Firewall Status
REM =====================================================================
echo [11/12] Checking Windows Firewall status...
(
    echo.
    echo %DIVIDER%
    echo  [11] WINDOWS FIREWALL STATUS  (netsh advfirewall show allprofiles^)
    echo %DIVIDER%
    netsh advfirewall show allprofiles
) >> "%REPORT%"

REM =====================================================================
REM  12. Wireless Network Info (if applicable)
REM =====================================================================
echo [12/12] Gathering wireless network info...
(
    echo.
    echo %DIVIDER%
    echo  [12] WIRELESS NETWORK INFO  (netsh wlan show interfaces^)
    echo %DIVIDER%
    netsh wlan show interfaces
    echo.
    echo  Available wireless networks:
    netsh wlan show networks mode=bssid
) >> "%REPORT%"

REM =====================================================================
REM  Wrap up
REM =====================================================================
(
    echo.
    echo %DIVIDER%
    echo  END OF REPORT - Generated %TIMESTAMP%
    echo %DIVIDER%
) >> "%REPORT%"

echo.
echo  ============================================
echo   Report saved to:
echo   %REPORT%
echo  ============================================
echo.
echo  Opening report...
start notepad "%REPORT%"

endlocal
pause
