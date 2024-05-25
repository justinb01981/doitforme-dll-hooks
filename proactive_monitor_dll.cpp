#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <windows.h>
#include "proactive_monitor.h"
#include "proactive_defines.h"
#include "detour_hooking.h"

#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)

#define ERRORMSG(x) cout << x << endl;
#define LOGWRITE(x) /* append_log(x) */

using namespace std;

/* TYPES */

enum
{
    HOOK_ID_GETMESSAGEW = 0,
    HOOK_ID_GETMESSAGEA,
    HOOK_ID_CREATEPROCESSW,
    HOOK_ID_CREATEPROCESSA
};

/* GLOBALS */

static bool disable_patching = false;
static char gLogPath[1024];

static LPCTSTR gCmdLine;

static void AttemptIATPatching(bool hook, char *moduleName, int depth);

char * getLogPath()
{
    /* sprintf(gLogPath, "C:\\proactive_monitor.log"); */
    sprintf(gLogPath, PROACTIVE_PIPE_NAME);
    return gLogPath;
}

/* the DLL will be loaded, but will not patch in... */
bool check_disable_patching()
{
    fstream f;
    
    f.open("C:\\proactive_monitor_disable", ios::in);
    if(f.good())
    {
        return true;
    }
    return false;
}

void debug_log_write(char *str, char *str2, char *filepath)
{
    fstream f;
    f.open(filepath, ios::out|ios::app);
    if(f.good())
    {
        f << str << " " << str2 << endl;
        f.close();
    }
}

void do_write_log(char *str, char *str2)
{
    debug_log_write(str, str2, "C:\\proactive_debug.log");
}

void do_write_log_hex(char *str, void *buf, size_t len)
{
    unsigned char *ptr = (unsigned char *) buf;
    char tmpstr[1024];
    int i = 0;

    tmpstr[0] = '\0';
    while( i < len)
    {
        sprintf(tmpstr + strlen(tmpstr), "%02x", *ptr);
        i++;
        ptr++;
    }
    do_write_log(str, tmpstr);
}

/* NOTE: this code is for the DLL that is built, and added to the registry as
 * an "AppInit" dll that is loaded into every process run by the user.
 * It patches hooks into a few key kernel32 exported functions.
 * In Windows Vista, AppInit DLL's are not loaded unless they are signed
 * (I believe by any trusted CA). Rather than pay MS $$$ to sign my DLL's
 * I would just ask the user to trust my CA. If I start making bucks on
 * this product, then maybe I can get it properly signed. Not likely. */

static int check_proactive_permission(char *str)
{
    HANDLE h;
    DWORD bytesWritten = 0;
    char response[1024];
    int verdict = VERDICT_ALLOW;

    if(/* WaitNamedPipe(getLogPath(), 100) */ 1)
    {
        h = CreateFile(getLogPath(), GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);
        if(h)
        {
            DWORD bytesWritten, mode;

            mode = PROACTIVE_PIPE_TYPE_CLIENT;
            if(SetNamedPipeHandleState(h, &mode, NULL, NULL) != 0)
            {
                if(WriteFile(h, str, strlen(str), &bytesWritten, NULL))
                {
                    if(ReadFile(h, response, sizeof(response)-1, &bytesWritten, NULL))
                    {
                        if(strcmp(response, "<response>allow</response>") == 0)
                        {
                            verdict = VERDICT_ALLOW;
                        }
                        else
                        {
                            verdict = VERDICT_DENY;
                        }
                    }
                }
            }
            CloseHandle(h);
        }
    
        if(bytesWritten != strlen(str))
        {
            /*
            cout << "proactive_monitor_dll: WriteFile failed" << endl;
            */
        }
    }
    return verdict;
}

void msg_to_str(LPMSG pMsg, char *str)
{
    sprintf(str, "<msg><hw>%lu</hw><id>%d</id><wp>%lu</wp><lp>%lu</lp><ti>%lu</ti><pt>%d/%d</pt></msg>",
            (unsigned long) pMsg->hwnd,
            pMsg->message,
            (unsigned long) pMsg->wParam,
            (unsigned long) pMsg->lParam,
            (unsigned long) pMsg->time /*timeGetTime()*/,
            pMsg->pt.x,
            pMsg->pt.y);
}

void divert_message(LPMSG pMsg)
{
    HANDLE h;
    DWORD bytesWritten = 0;
    char str[1024], response[1024];
    int verdict = VERDICT_ALLOW;

    if(/* WaitNamedPipe(getLogPath(), 100) */ 1)
    {
        h = CreateFile(AUTOMATE_MSG_PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);
        if(h)
        {
            DWORD bytesWritten, mode;

            mode = AUTOMATE_PIPE_TYPE_CLIENT;
            if(SetNamedPipeHandleState(h, &mode, NULL, NULL) != 0)
            {
                msg_to_str(pMsg, str);
                if(WriteFile(h, str, strlen(str), &bytesWritten, NULL))
                {
                    /*
                    if(ReadFile(h, response, sizeof(response)-1, &bytesWritten, NULL))
                    {
                    }
                    */
                }
            }
            CloseHandle(h);
        }
    }
}

int inject_message(LPMSG pMsg)
{
    HANDLE h;
    DWORD bytesWritten = 0;
    char response[1024];

    if(/* WaitNamedPipe(getLogPath(), 100) */ 1)
    {
        h = CreateFile(AUTOMATE_MSG_PIPE_NAME_INJECT, GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);
        if(h)
        {
            DWORD bytesWritten, mode;

            mode = AUTOMATE_PIPE_TYPE_CLIENT;
            if(SetNamedPipeHandleState(h, &mode, NULL, NULL) != 0)
            {
                if(ReadFile(h, response, sizeof(response)-1, &bytesWritten, NULL))
                {
                    if(bytesWritten > 0)
                    {
                        /* parse, build LPMSG and return.. */
                        return 1;
                    }
                }
            }
            CloseHandle(h);
        }
    }
    return 0;
}


static size_t w_strlen(LPCWSTR p)
{
    size_t len = 0;
    while(*p != 0)
    {
        len++;
        p++;
    }
    return len;
}

unsigned char *MakePtr(void *p, unsigned long offset)
{
    unsigned char *ptr = (unsigned char *) p;
    return ptr + offset;
}

size_t ConvertWStr(LPCWSTR w, char *out, size_t out_sz)
{
    size_t len = w_strlen(w), i = 0;
    while(i < len && i < out_sz-1)
    {
        out[i] = (char) w[i];
        i++;
    }
    out[i] = 0;
    return i;
}

int LogFileA(const char *str, LPCTSTR str2)
{
    char tmp[2048], pwd[1024], procname[256];

    pwd[0] = 0;
    procname[0] = 0;
    GetCurrentDirectory(sizeof(pwd)-1, pwd);
    //GetProcessName(procname, sizeof(procname));

    if(strlen(str) + strlen(str2) + strlen(procname) + strlen(pwd) < sizeof(tmp))
    {
        sprintf(tmp, "<hook><procname>%s</procname><pwd>%s</pwd><func>%s</func><path>%s</path></hook>\n", procname, pwd, str, str2);
        LOGWRITE(tmp);
        return check_proactive_permission(tmp);
    }
}

int LogFileW(const char *str, LPCWSTR str2)
{
    char tmp[1024];
    ConvertWStr(str2, tmp, sizeof(tmp));
    return LogFileA(str, tmp);
}


/* monitoring hooks */

/* CreateFileW */
typedef HANDLE (WINAPI *CreateFileWPtr)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileWPtr OriginalCreateFileW = NULL;

HANDLE WINAPI MyCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    if(lpFileName) LogFileW("CreateFileW", lpFileName);

    return (*OriginalCreateFileW)(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                  dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

/* CreateFileA */
typedef HANDLE (WINAPI *CreateFileAPtr)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileAPtr OriginalCreateFileA = NULL;

HANDLE WINAPI MyCreateFileA(
    LPCTSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
)
{
    if(lpFileName) LogFileA("CreateFileA", lpFileName);

    return (*OriginalCreateFileA)(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
                                  dwCreationDisposition,dwFlagsAndAttributes, hTemplateFile);
}

/* CreateProcessA */
typedef BOOL (WINAPI *CreateProcessAPtr)(LPCTSTR, LPTSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                  BOOL, DWORD, LPVOID, LPCTSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION);
CreateProcessAPtr OriginalCreateProcessA = NULL;

BOOL WINAPI MyCreateProcessA(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    /*
    if(lpApplicationName) LogFileA("CreateProcessA:", lpApplicationName);
    */

    /*
    char str1[64], str2[64];
    sprintf(str1, "OriginalCreateProcessA=%x", (unsigned) OriginalCreateProcessA);
    sprintf(str2, "&gHooks[0].buf=%x", (unsigned) &gHooks[HOOK_ID_CREATEPROCESSA].buf);
    do_write_log(str1, str2);
    */
    //do_write_log("CreateProcessA: ", (char *) lpApplicationName);
    //cout << (char *) lpApplicationName << endl;
    //return (*(CreateProcessAPtr) &gHooks[HOOK_ID_CREATEPROCESSA].buf)
    return HOOK_CONTINUE(CreateProcessAPtr, HOOK_ID_CREATEPROCESSA)
                        (lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                         bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                         lpStartupInfo, lpProcessInformation);
}

/* CreateProcessW */
#define CreateProcessW_proto                    \
    LPCWSTR lpApplicationName,                  \
    LPWSTR lpCommandLine,                       \
    LPSECURITY_ATTRIBUTES lpProcessAttributes,  \
    LPSECURITY_ATTRIBUTES lpThreadAttributes,   \
    BOOL bInheritHandles,                       \
    DWORD dwCreationFlags,                      \
    LPVOID lpEnvironment,                       \
    LPCWSTR lpCurrentDirectory,                 \
    LPSTARTUPINFO lpStartupInfo,                \
    LPPROCESS_INFORMATION lpProcessInformation

typedef BOOL (WINAPI *CreateProcessWPtr) (CreateProcessW_proto);
CreateProcessWPtr OriginalCreateProcessW = NULL;

BOOL WINAPI MyCreateProcessW(CreateProcessW_proto)
{
    char str[512];
    ConvertWStr(lpApplicationName, str, sizeof(str));
    do_write_log("MyCreateProcessW", str);
    /*
    if(lpApplicationName)
    {
        if(LogFileW("CreateProcessW:", lpApplicationName) == VERDICT_DENY)
        {
            return FALSE;
        }
    }
    */
    
    return HOOK_CONTINUE(CreateProcessWPtr, HOOK_ID_CREATEPROCESSW)
                        (lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                         bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                         lpStartupInfo, lpProcessInformation);
}

#if 0
/* CreateProcessInternalW */
#define CreateProcessInternalW_proto                \
    LPCWSTR lpApplicationName,                      \
    LPWSTR lpCommandLine,                           \
    LPSECURITY_ATTRIBUTES lpProcessAttributes,      \
    LPSECURITY_ATTRIBUTES lpThreadAttributes,       \
    BOOL bInheritHandles,                           \
    DWORD dwCreationFlags,                          \
    LPVOID lpEnvironment,                           \
    LPCWSTR lpCurrentDirectory,                     \
    LPSTARTUPINFO lpStartupInfo,                    \
    LPPROCESS_INFORMATION lpProcessInformation

typedef BOOL (WINAPI *CreateProcessInternalWPtr)(CreateProcessInternalW_proto);

CreateProcessInternalWPtr OriginalCreateProcessInternalW = NULL;

BOOL WINAPI MyCreateProcessInternalW (CreateProcessInternalW_proto)
{
    /*
    if(lpApplicationName)
    {
        if(LogFileW("CreateProcessInternalW:", lpApplicationName) == VERDICT_DENY)
        {
            return FALSE;
        }
    }
    */
    do_write_log_hex("MyCreateProcessInternalW called", (void*) &lpApplicationName, 40);
    return (*OriginalCreateProcessInternalW)
                        (lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                         bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                         lpStartupInfo, lpProcessInformation);
}

/* CreateProcessInternalWSecure */
typedef BOOL (WINAPI *CreateProcessInternalWSecurePtr)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                  BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFO, LPPROCESS_INFORMATION, HANDLE);
CreateProcessInternalWSecurePtr OriginalCreateProcessInternalWSecure = NULL;

BOOL WINAPI MyCreateProcessInternalWSecure(
    HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    HANDLE hNewToken
)
{
    if(lpApplicationName)
    {
        if(LogFileW("CreateProcessInternalWSecure:", lpApplicationName) == VERDICT_DENY)
        {
            return FALSE;
        }
    }
    return (*OriginalCreateProcessInternalWSecure)
                        (hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                         bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                         lpStartupInfo, lpProcessInformation, hNewToken);
}

/* CreateProcessInternalA */
typedef BOOL (WINAPI *CreateProcessInternalAPtr)(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);
CreateProcessInternalAPtr OriginalCreateProcessInternalA = NULL;

BOOL WINAPI MyCreateProcessInternalA(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    if(lpApplicationName)
    {
        if(LogFileA("CreateProcessInternalA:", lpApplicationName) == VERDICT_DENY)
        {
            return FALSE;
        }
    }
    return (*OriginalCreateProcessInternalA)
                        (lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                         bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                         lpStartupInfo, lpProcessInformation);
}
#endif

/*********************************************************************************************/
/* GetMessageW */
/* HEY! this is not a WINAPI calling style.. that fixed crashes... */
#define GetMessageW_proto                       \
    LPMSG pMsg,                                 \
    HWND hwnd,                                  \
    UINT wMsgFilterMin,                         \
    UINT wMsgFilterMax
/*
    ,BOOL *pfResult                              
*/
typedef BOOL (WINAPI *GetMessageWPtr)(GetMessageW_proto);
GetMessageWPtr OriginalGetMessageW = NULL;

BOOL WINAPI MyGetMessageW(GetMessageW_proto)
{
    HRESULT b;
 
    b = HOOK_CONTINUE(GetMessageWPtr, HOOK_ID_GETMESSAGEW)
                    (pMsg, hwnd, wMsgFilterMin, wMsgFilterMax/*, pfResult*/);
    if(pMsg)
    {
        divert_message(pMsg);
    }
    return b;
}
/*********************************************************************************************/
/* GetMessageA */
/* HEY! Pay attention to WinUser.h to see these function decls */
#define GetMessageA_proto                       \
    LPMSG pMsg,                                 \
    HWND hwnd,                                  \
    UINT wMsgFilterMin,                         \
    UINT wMsgFilterMax                         
/*
    BOOL *pfResult                              
*/
typedef BOOL (WINAPI *GetMessageAPtr)(GetMessageA_proto);
GetMessageAPtr OriginalGetMessageA = NULL;

BOOL WINAPI MyGetMessageA(GetMessageA_proto)
{
    HRESULT b;
 
    b = HOOK_CONTINUE(GetMessageAPtr, HOOK_ID_GETMESSAGEA)
                    (pMsg, hwnd, wMsgFilterMin, wMsgFilterMax /*, pfResult*/);
    if(pMsg)
    {
        divert_message(pMsg);
    }
    return b;
}
/*********************************************************************************************/
/* GetProcAddress */
/* TODO: problem here... we may intercept the request for the symbol here
 * but when the process unloads our DLL (during shutdown or otherwise) we can't
 * go back and alter the variable the address was stored in, so we can't
 * cleanly unload ourself. This crashes some applications when they quit.
 * Need to use 'detour' hooking method instead */
typedef FARPROC (WINAPI *GetProcAddressPtr)(HMODULE, LPCSTR);
GetProcAddressPtr OriginalGetProcAddress = NULL;

FARPROC WINAPI MyGetProcAddress(HMODULE hModule, LPCSTR name)
{
    DWORD proc, ordinal;
    bool is_ordinal = false;
    char tmp[64];

    ordinal = (DWORD) name;
    if(HIWORD(name) == 0) is_ordinal = true;

    OriginalGetProcAddress = GetProcAddress; /* DLL unload will invalidate OriginalGetProcAddress.. */
    proc = (DWORD) (*OriginalGetProcAddress)(hModule, name);
    if(disable_patching) return (FARPROC) proc;


    if(is_ordinal)
    {
        sprintf(tmp, "%d", LOWORD(ordinal));
        /* do_write_log("MyGetProcAddress: ", tmp); */
    }
    else
    {
        /* do_write_log("MyGetProcAddress: ", (char *) name); */
    }

    if((is_ordinal? ordinal == 103: strcmp(name, "CreateProcessW") == 0))
    {
        if(OriginalCreateProcessW == NULL)
        {
            OriginalCreateProcessW = (CreateProcessWPtr) proc;
            /*
            proc = (DWORD) MyCreateProcessW;
            */
            if(add_hook((ULONG) proc, HOOK_ID_CREATEPROCESSW, (ULONG) MyCreateProcessW))
            {
                OriginalCreateProcessW = (CreateProcessWPtr) &gHooks[HOOK_ID_CREATEPROCESSW].buf;
            }
        }
    }
    /*
    if((is_ordinal? ordinal == 102: strcmp(name, "CreateProcessInternalWSecure") == 0))
    {
        OriginalCreateProcessInternalWSecure = (CreateProcessInternalWSecurePtr) proc;
        proc = (DWORD) MyCreateProcessInternalWSecure;
    }
    */

    if(0)
    {
    }
    else if((is_ordinal? ordinal == 99: strcmp(name, "CreateProcessA") == 0))
    {
        if(OriginalCreateProcessA == NULL)
        {
            OriginalCreateProcessA = (CreateProcessAPtr) proc;
            if(add_hook((ULONG) proc, HOOK_ID_CREATEPROCESSA, (ULONG) MyCreateProcessA))
            {
                OriginalCreateProcessA = (CreateProcessAPtr) &gHooks[HOOK_ID_CREATEPROCESSA].buf;
            }
        }
    }
    /*
    else if((is_ordinal? ordinal == 83: strcmp(name, "CreateFileW") == 0))
    {
        OriginalCreateFileW = (CreateFileWPtr) proc;
        proc = (DWORD) MyCreateFileW;
    }
    else if((is_ordinal? ordinal == 80: strcmp(name, "CreateFileA") == 0))
    {
        OriginalCreateFileA = (CreateFileAPtr) proc;
        proc = (DWORD) MyCreateFileA;
    }
    */

    /* do_write_log("...returning", ""); */
    return (FARPROC) proc;
}

static void PerformPatch(PDWORD pCurImportThunk, DWORD newaddr, PDWORD oldaddr, bool reverse)
{
    MEMORY_BASIC_INFORMATION mbi;
    char tmp[64];
    DWORD oldProtect;

    /* patch already performed? */
    /*
    if(*oldaddr != NULL) return;
    */

    /*TODO: this is an RVA... handle that.. */
    if(IMAGE_SNAP_BY_ORDINAL(*pCurImportThunk))
    {
        LOGWRITE("skipping RVA");
        return;
    }

    if(VirtualQuery(pCurImportThunk, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) > 0)
    {
        if(VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect))
        {
            if(!reverse)
            {
                if(*oldaddr == NULL)
                {
                    *oldaddr = *pCurImportThunk;
                }
                *pCurImportThunk = newaddr;
            }
            else
            {
                if(*oldaddr) *pCurImportThunk = *oldaddr;
            }
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &oldProtect);
        }
    }
}

static void CheckPatch(PDWORD pCurImportThunk, DWORD newaddr, PDWORD oldaddr)
{
    if(*pCurImportThunk != newaddr)
    {
        LOGWRITE("Patch was not found");
    }
}

/* walk the import-address-table for modules names we care about,
 * and replace their addresses with our own hooks */
static void AttemptIATPatching(bool hook, char *moduleName, int depth)
{
    HMODULE hmodule;
    PIMAGE_NT_HEADERS pNtHdr;
    unsigned long importDirOffset;
    PIMAGE_IMPORT_DESCRIPTOR pFirst;
    PDWORD pCurThunk, pCurImportThunk, originalAddrDest;
    DWORD hookAddr;
    char tmp[255];

    if(depth > 7) return;

    /* TODO: replace the patched IATs if hook == false */

    hmodule = GetModuleHandle(moduleName);
    if(!hmodule)
    {
        LOGWRITE("GetModuleHandle failed");
        return;
    }

    pNtHdr = (PIMAGE_NT_HEADERS) MakePtr(hmodule, ((PIMAGE_DOS_HEADER) hmodule)->e_lfanew);
    if(!pNtHdr) return;

    importDirOffset = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if(!importDirOffset) return;

    pFirst = (PIMAGE_IMPORT_DESCRIPTOR) MakePtr(hmodule, importDirOffset);

    /* NULL element at end */
    while(pFirst && pFirst->OriginalFirstThunk)
    {
        char *ptr;
        ptr = (char *) MakePtr(hmodule, pFirst->Name);

        if(!ptr || (strcmp(ptr, "KERNEL32.dll") != 0 && strcmp(ptr, "kernel32.dll") != 0))
        {
            AttemptIATPatching(hook, ptr, depth++);  /* recurse.. */
            pFirst++;
            continue;
        }

        /* print the imported thunks.. */
        pCurThunk = (PDWORD) MakePtr(hmodule, pFirst->OriginalFirstThunk);
        pCurImportThunk = (PDWORD) MakePtr(hmodule, pFirst->FirstThunk);
        for(; *pCurThunk; pCurThunk++ && pCurImportThunk++)
        {
            PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME) MakePtr(hmodule, *pCurThunk);
            if(!pName) break;

            sprintf(tmp, "\t%s", pName->Name);

            hookAddr = NULL;

            /*
            if(strcmp((char *) pName->Name, "CreateFileA") == 0)
            {
                hookAddr = (DWORD) MyCreateFileA;
                originalAddrDest = (PDWORD) &OriginalCreateFileA;
            }

            if(strcmp((char *) pName->Name, "CreateFileW") == 0)
            {
                hookAddr = (DWORD) MyCreateFileW;
                originalAddrDest = (PDWORD) &OriginalCreateFileW;
            }
            */

#if 0
            if(strcmp((char *) pName->Name, "CreateProcessA") == 0)
            {
                /*
                hookAddr = (DWORD) MyCreateProcessA;
                originalAddrDest = (PDWORD) &OriginalCreateProcessA;
                */
                if(OriginalCreateProcessA == NULL)
                {
                    OriginalCreateProcessA = (CreateProcessAPtr) *pCurImportThunk;
                    if(add_hook((ULONG) *pCurImportThunk, HOOK_ID_CREATEPROCESSA, (ULONG) MyCreateProcessA))
                    {
                        OriginalCreateProcessA = (CreateProcessAPtr) &gHooks[HOOK_ID_CREATEPROCESSA].buf;
                    }
                }
            }

            if(strcmp((char *) pName->Name, "CreateProcessW") == 0)
            {
                /*
                hookAddr = (DWORD) MyCreateProcessW;
                originalAddrDest = (PDWORD) &OriginalCreateProcessW;
                */
                if(OriginalCreateProcessW == NULL)
                {
                    OriginalCreateProcessW = (CreateProcessWPtr) *pCurImportThunk;
                    if(add_hook((ULONG) *pCurImportThunk, HOOK_ID_CREATEPROCESSW, (ULONG) MyCreateProcessW))
                    {
                        OriginalCreateProcessW = (CreateProcessWPtr) &gHooks[HOOK_ID_CREATEPROCESSW].buf;
                    }
                }
            }
#endif

            /*
            if(strcmp((char *) pName->Name, "CreateProcessInternalW") == 0)
            {
                hookAddr = (DWORD) MyCreateProcessInternalW;
                originalAddrDest = (PDWORD) &OriginalCreateProcessInternalW;
            }
            if(strcmp((char *) pName->Name, "CreateProcessInternalA") == 0)
            {
                hookAddr = (DWORD) MyCreateProcessInternalA;
                originalAddrDest = (PDWORD) &OriginalCreateProcessInternalA;
            }
            if(strcmp((char *) pName->Name, "CreateProcessInternalWSecure") == 0)
            {
                hookAddr = (DWORD) MyCreateProcessInternalWSecure;
                originalAddrDest = (PDWORD) &OriginalCreateProcessInternalWSecure;
            }
            */

            if(strcmp((char *) pName->Name, "GetProcAddress") == 0)
            {
                hookAddr = (DWORD) MyGetProcAddress;
                originalAddrDest = (PDWORD) &OriginalGetProcAddress;
            }
            /*
            if(strcmp((char *) pName->Name, "GetMessageW") == 0
               || strcmp((char *) pName->Name, "GetMessageA") == 0
               || strcmp((char *) pName->Name, "GetMessageExW") == 0
               || strcmp((char *) pName->Name, "GetMessageExA") == 0)
            {
                if(OriginalGetMessageW == NULL)
                {
                    OriginalGetMessageW = (GetMessageWPtr) *pCurImportThunk;
                    if(add_hook((ULONG) *pCurImportThunk, HOOK_ID_GETMESSAGEW, (ULONG) MyGetMessageW))
                    {
                        OriginalGetMessageW = (GetMessageWPtr) &gHooks[HOOK_ID_GETMESSAGEW].buf;
                    }
                }
            }
            */

            if(hook && hookAddr)
            {
                if(!disable_patching)
                {
                    PerformPatch(pCurImportThunk, hookAddr, originalAddrDest, false);
                }
                else
                {
                    PerformPatch(pCurImportThunk, hookAddr, originalAddrDest, true);
                }
            }
        }
        pFirst++;
    }
}

void AttemptStaticHooking()
{
    char str[255];

    /* try and hook getmessage with a detour.. */
    if(OriginalGetMessageW == NULL)
    {
        OriginalGetMessageW = (GetMessageWPtr) GetProcAddress(LoadLibrary("user32.dll"), "GetMessageW");
        sprintf(str, "%0x", (unsigned long) OriginalGetMessageW);
        if(add_hook((ULONG) OriginalGetMessageW, HOOK_ID_GETMESSAGEW, (ULONG) MyGetMessageW))
        {
            OriginalGetMessageW = (GetMessageWPtr) &gHooks[HOOK_ID_GETMESSAGEW].buf;
        }
    }

    /* try and hook getmessage with a detour.. */
    if(OriginalGetMessageA == NULL)
    {
        OriginalGetMessageA = (GetMessageAPtr) GetProcAddress(LoadLibrary("user32.dll"), "GetMessageA");
        sprintf(str, "%0x", (unsigned long) OriginalGetMessageA);
        if(add_hook((ULONG) OriginalGetMessageA, HOOK_ID_GETMESSAGEA, (ULONG) MyGetMessageA))
        {
            OriginalGetMessageA = (GetMessageAPtr) &gHooks[HOOK_ID_GETMESSAGEW].buf;
        }
    }
}

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID reserved)
{
    if(check_disable_patching())
    {
        disable_patching = TRUE;
    }

    gCmdLine = GetCommandLine();

    if(strstr(gCmdLine, "windbg.exe")
       || strstr(gCmdLine, "drwtsn32")
       || strstr(gCmdLine, "dwwin.exe")
       || strstr(gCmdLine, "automate_tool.exe")) 
        disable_patching = TRUE;

    switch(dwReason)
    {
    case DLL_PROCESS_ATTACH:
        if(!disable_patching)
        {
            init_hooking();
            do_write_log((char*) gCmdLine, "DllMain DLL_PROCESS_ATTACH");
            //AttemptIATPatching(true, NULL, 0);
            AttemptStaticHooking();
        }
        break;

    case DLL_PROCESS_DETACH:
        do_write_log((char*) gCmdLine, "DllMain DLL_PROCESS_DETACH");
        disable_patching = true;
        int i;
        for(i = 0; i < MAX_HOOKS; i++)
        {
            reverse_hook(i);
        }
        //AttemptIATPatching(false, NULL, 0);
        break;

    case DLL_THREAD_DETACH:
    case DLL_THREAD_ATTACH:
        do_write_log("DLLMain DLL_THREAD_ATTACH", "");
        break;

    default:
        do_write_log("DLLMain UNKNOWN dwReason", "");
        break;
    }

    return TRUE;
}

