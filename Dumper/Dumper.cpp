#define _CRT_SECURE_NO_DEPRECATE
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#include <windows.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <psapi.h>
#include <filesystem>
#include <experimental/filesystem>

#pragma comment(lib,"Wtsapi32.lib")

using namespace std;
namespace fs = std::experimental::filesystem::v1;

void ErrorExit(const char* lpszFunction)
{
    wchar_t lpMsgBuf[256];
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        lpMsgBuf,
        256, NULL);


    fwprintf(stderr,
        L"%hs failed with error %d: %s",
        lpszFunction, dw, lpMsgBuf);

    ExitProcess(dw);

}

void EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid);

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("INFO: SeDebugPrivilege Enabled\n");
    }

    CloseHandle(hToken);
}

void PrintTheRunningProcceses() {
    WTS_PROCESS_INFOA* pWPIs = NULL;
    DWORD dwProcCount = 0;
    if (WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, NULL, 1, &pWPIs, &dwProcCount))
    {
        for (DWORD i = 0; i < dwProcCount; i++)
        {
            printf("%s (PID: %d)\n", pWPIs[i].pProcessName, pWPIs[i].ProcessId, pWPIs[i].pUserSid);
        }
    }

    //Free memory
    if (pWPIs)
    {
        WTSFreeMemory(pWPIs);
        pWPIs = NULL;
    }
}

int PrintModules(DWORD processID) {
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
    typedef std::basic_string<TCHAR> tstring;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
    if (NULL == hProcess)
        return 1;

    // Get a list of all the modules in this process.

    if (K32EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.

            if (K32GetModuleFileNameExW(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {

                // Print the module name and handle value.
                std::cout << fs::path((tstring)szModName).filename();
                _tprintf(TEXT(" (0x%08X)\n"), hMods[i]);
            }
        }
    }

    // Release the handle to the process.

    CloseHandle(hProcess);

    return 0;
}

int main() {
    EnableDebugPrivilege();
    cout << "\n-----------------------\n";
    PrintTheRunningProcceses();
    int pID;
    cout << "\nEnter the procces id (PID): ";
    cin >> pID;
    if (HANDLE Process = OpenProcess(PROCESS_VM_READ, FALSE, pID)) {
        PrintModules(pID);
        printf("\n- Or you can get the address manually using VMMAP/IDA/etc..\n");
        printf("\n- (Link: https://docs.microsoft.com/en-us/sysinternals/downloads/vmmap)\n");
        char Buffer[80] = {}; // you can change that if you want to
        PVOID mID;
        cout << "\nEnter the module id (MID): ";
        cin >> mID;
        /*
        You can call ReadProcessMemory instead of Toolhelp32ReadProcessMemory
            BOOL ReadProcessMemory(
                [in]  HANDLE  hProcess,
                [in]  LPCVOID lpBaseAddress,
                [out] LPVOID  lpBuffer,
                [in]  SIZE_T  nSize,
                [out] SIZE_T  *lpNumberOfBytesRead
            );

        if (ReadProcessMemory(Process, mID, Buffer, 80, 0)) {

        }
        Just to give you more calls to use :)
        */
        if (Toolhelp32ReadProcessMemory(pID, mID, Buffer, 80, 0)) {
            printf("the PVA data space: %ls\n", Buffer);
        }
        else {
            ErrorExit("Toolhelp32ReadProcessMemory");
        }
    }
    else {
        ErrorExit("OpenProcess");
    }
    return 0;
}