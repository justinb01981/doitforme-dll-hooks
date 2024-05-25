#include <windows.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include "proactive_monitor.h"
#include "proactive_defines.h"
#include "detour_hooking.h"
#include "sounds.h"

using namespace std;

#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)

bool always_hook = TRUE;
HHOOK mouseHook = NULL;
HHOOK keyboardHook = NULL;


void divert_message(char *str)
{
    HANDLE h;
    DWORD bytesWritten = 0;
    char response[1024];

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

extern "C" {

EXPORT LRESULT CALLBACK MyMouseProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    char str[1024];
    MSLLHOOKSTRUCT *ms = (MSLLHOOKSTRUCT*) lParam;
    fstream fstreamMouse;

    if(nCode >= 0)
    {
        fstreamMouse.open("C:\\automate_hooks_debug.txt", ios::out|ios::app);
        sprintf(str, "<msg><hw>0</hw><id>%d</id><wp>0</wp><lp>0</lp><ti>%lu</ti><pt>%d/%d</pt></msg>",
                wParam, timeGetTime(), ms->pt.x, ms->pt.y);

        if(ms->flags & LLMHF_INJECTED)
        {
        }
        else
        {
            divert_message(str);
        }
        fstreamMouse.close();
    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/* http://msdn.microsoft.com/en-us/library/ms644984%28VS.85%29.aspx */
EXPORT LRESULT CALLBACK MyKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    char str[1024];
    KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT*) lParam;

    if(nCode >= 0)
    {
        sprintf(str, "<msg><hw>0</hw><id>%d</id><wp>%d</wp><lp>0</lp><ti>%lu</ti><pt>%d/%d</pt></msg>",
                wParam, kb->vkCode, timeGetTime(), 0, 0);

        if(nCode == HC_NOREMOVE) /* was a peekmessage, ignore */
        {
        }
        else
        {
            divert_message(str);
        }
    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

}

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID reserved)
{
    fstream fstreamDLLMain;

    fstreamDLLMain.open("C:\\automate_hooks_debug.txt", ios::out|ios::app);
    fstreamDLLMain << hInstance << " " << dwReason << endl;

    switch(dwReason)
    {
    case DLL_PROCESS_ATTACH:
        if(always_hook)
        {
            mouseHook = SetWindowsHookEx(WH_MOUSE_LL, MyMouseProc, hInstance, /*GetCurrentThreadId()*/ 0);
            keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, MyKeyboardProc, hInstance, /*GetCurrentThreadId()*/ 0);
        }
        break;

    case DLL_PROCESS_DETACH:
        if(mouseHook) UnhookWindowsHookEx(mouseHook);
        if(keyboardHook) UnhookWindowsHookEx(keyboardHook);
        break;

    default:
        break;
    }
    fstreamDLLMain.close();
    return TRUE;
}
