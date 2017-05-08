#define UNICODE
#define _UNICODE

#define PSAPI_VERSION 1  // for use psapi.lib

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

#include <windows.h>
#include <wchar.h>
#include <psapi.h>

#define PROCESS_ID_BUFFER_SIZE    4096


VOID EnableDebugPrivilege();


VOID PrintProcessInfo(DWORD processId);
VOID GetUserName(HANDLE tokenHandle, LPWSTR userName, DWORD userNameLengthInChars,
        LPWSTR domainName, DWORD domainNameLengthInChars);
VOID GetSessionId(HANDLE tokenHandle, PDWORD sessionId);
VOID GetModuleName(HANDLE processHandle, LPWSTR processName, DWORD processNameLengthInChars);
VOID GetLogonId(HANDLE tokenHandle, PLUID logonId);


INT
wmain(INT argc, WCHAR *argv[])
{
    EnableDebugPrivilege();

    DWORD processIds[PROCESS_ID_BUFFER_SIZE];
    DWORD bytesReturned;
    if (!EnumProcesses(processIds, sizeof(DWORD) * PROCESS_ID_BUFFER_SIZE, &bytesReturned))
    {
        wprintf(L"FAILED: EnumProcesses: %d\n", GetLastError());
        goto Cleanup;
    }

    wprintf(L"PID       ProcessName                                       SessionID  LogonId (H L)      User\n");
    wprintf(L"--------  ------------------------------------------------  ---------  -----------------  --------\n");

    DWORD numProcess = bytesReturned / sizeof(DWORD);

    for (DWORD i = 0; i < numProcess; i++)
    {
        PrintProcessInfo(processIds[i]);
    }

Cleanup:

    return 0;
}


VOID
EnableDebugPrivilege()
{
    HANDLE tokenHandle = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES,
            &tokenHandle))
    {
        wprintf(L"FAILED: OpenProcessToken() in EnableDebugPrivilege(): %d\n", GetLastError());
        return;
    }

    LUID privilegeLuid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &privilegeLuid))
    {
        wprintf(L"FAILED: LookupPrivilegeValue() in EnableDebugPrivilege(): %d\n", GetLastError());
        goto Cleanup;
    }

    TOKEN_PRIVILEGES tokenPrivileges;
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = privilegeLuid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(tokenHandle, FALSE,
            &tokenPrivileges, sizeof(tokenPrivileges), NULL, NULL))
    {
        wprintf(L"FAILED: AdjustTokenPrivileges: %d\n", GetLastError());
        return;
    }

Cleanup:

    if (tokenHandle != NULL)
    {
        CloseHandle(tokenHandle);
    }
}


VOID
PrintProcessInfo(DWORD processId)
{
    HANDLE processHandle = NULL;
    HANDLE tokenHandle = NULL;

    WCHAR userName[MAX_PATH] = L"-";
    DWORD userNameLengthInChars = sizeof(userName) / sizeof(WCHAR);

    WCHAR domainName[MAX_PATH] = L"-";
    DWORD domainNameLengthInChars = sizeof(domainName) / sizeof(WCHAR);

    DWORD sessionId = 0;

    WCHAR processName[MAX_PATH] = L"-";
    DWORD processNameLengthInChars = sizeof(processName) / sizeof(WCHAR);

    LUID logonId;
    SecureZeroMemory(&logonId, sizeof(LUID));

    // PID
    wprintf(L"%8d  ", processId);

    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (processHandle == NULL)
    {
        wprintf(L"FAILED: OpenProcess: %d\n", GetLastError());
        goto Cleanup;
    }

    if (!OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle))
    {
        wprintf(L"FAILED: OpenProcessToken: %d\n", GetLastError());
        tokenHandle = NULL;
        goto Cleanup;
    }

    GetModuleName(processHandle, processName, processNameLengthInChars);
    GetUserName(tokenHandle, userName, userNameLengthInChars,
            domainName, domainNameLengthInChars);
    GetSessionId(tokenHandle, &sessionId);
    GetLogonId(tokenHandle, &logonId);

    wprintf(L"%-48s  %-9d  %08X %08X  %s\\%s\n", processName, sessionId, logonId.HighPart, logonId.LowPart,
            domainName, userName);


Cleanup:

    if (tokenHandle != NULL)
    {
        CloseHandle(tokenHandle);
    }

    if (processHandle != NULL)
    {
        CloseHandle(processHandle);
    }
}


VOID
GetUserName(HANDLE tokenHandle, LPWSTR userName, DWORD userNameLengthInChars,
        LPWSTR domainName, DWORD domainNameLengthInChars)
{
    PTOKEN_USER tokenUser = NULL;

    DWORD neededInBytes;
    DWORD err;
    GetTokenInformation(tokenHandle, TokenUser, tokenUser, 0, &neededInBytes);
    err = GetLastError();
    if (err != ERROR_INSUFFICIENT_BUFFER)
    {
        wprintf(L"FAILED: GetTokenInformation() in GetUserName(): 1:  %d\n", err);
        goto Cleanup;
    }

    tokenUser = (PTOKEN_USER) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, neededInBytes);
    if (tokenUser == NULL)
    {
        wprintf(L"FAILED: HeapAlloc() in GetUserName()\n");
        goto Cleanup;
    }

    if (!GetTokenInformation(tokenHandle, TokenUser, tokenUser,
            neededInBytes, &neededInBytes))
    {
        wprintf(L"FAILED: GetTokenInformation() in GetUserName(): 2: %d\n", GetLastError());
        goto Cleanup;
    }

    SID_NAME_USE sidNameUse;
    if (!LookupAccountSid(NULL, tokenUser->User.Sid, userName, &userNameLengthInChars,
            domainName, &domainNameLengthInChars, &sidNameUse))
    {
        wprintf(L"FAILED: LookupAccountSid() in GetUserName(): %d\n", GetLastError());
        goto Cleanup;
    }

Cleanup:

    if (tokenUser != NULL)
    {
        HeapFree(GetProcessHeap(), 0, tokenUser);
    }
}


VOID
GetSessionId(HANDLE tokenHandle, PDWORD sessionId)
{
    DWORD tokenSessionId;
    DWORD returnLength;

    if (!GetTokenInformation(tokenHandle, TokenSessionId, &tokenSessionId,
            sizeof(tokenSessionId), &returnLength))
    {
        wprintf(L"FAILED: GetTokenInformation() in GetSessionId(): %d\n", GetLastError());
        return;
    }

    *sessionId = tokenSessionId;
}


VOID
GetModuleName(HANDLE processHandle, LPWSTR processName, DWORD processNameLengthInChars)
{
    HMODULE moduleHandle;
    DWORD needed;

    if (EnumProcessModulesEx(processHandle, &moduleHandle, sizeof(moduleHandle), &needed, LIST_MODULES_ALL))
    {
        GetModuleBaseName(processHandle, moduleHandle, processName, processNameLengthInChars);
    }
}


VOID
GetLogonId(HANDLE tokenHandle, PLUID logonId)
{
    TOKEN_STATISTICS tokenStatistics;
    DWORD returnLength;

    if (!GetTokenInformation(tokenHandle, TokenStatistics, &tokenStatistics,
            sizeof(tokenStatistics), &returnLength))
    {
        wprintf(L"FAILED: GetTokenInformation() in GetLogonId(): %d\n", GetLastError());
        return;
    }

    logonId->HighPart = tokenStatistics.AuthenticationId.HighPart;
    logonId->LowPart = tokenStatistics.AuthenticationId.LowPart;
}
