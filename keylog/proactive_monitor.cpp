#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <windows.h>

#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)

#define ERRORMSG(x) cout << x << endl;


using namespace std;

#ifdef MAKE_DLL

/* GLOBALS */
HHOOK hHook;
EXPORT HINSTANCE gDLLHInstance;
fstream dllout;

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID reserved)
{
    gDLLHInstance = hInstance;

    dllout.open("proactive_monitor.log", ios::out);
    return 1;
}

/* this has to be loaded from a library */
EXPORT
LRESULT CALLBACK keyboardHookCallback(int nCode, WPARAM wParam, LPARAM lParam)
{
    /* stuff */
    dllout << (char) wParam;

    CallNextHookEx(hHook, nCode, wParam, lParam);
    return 0;
}

/* this has to be loaded from a library */
EXPORT
LRESULT CALLBACK hookCallback(int nCode, WPARAM wParam, LPARAM lParam)
{
    /* stuff */
    dllout << "hookCallback: nCode = " << nCode << " wParam = "
         << wParam << "(" << (char) wParam << ")" << " lParam = " << lParam << endl;
    CallNextHookEx(hHook, nCode, wParam, lParam);
    return 0;
}

#else
extern IMPORT
LRESULT CALLBACK hookCallback(int nCode, WPARAM wParam, LPARAM lParam);

extern IMPORT
LRESULT CALLBACK keyboardHookCallback(int nCode, WPARAM wParam, LPARAM lParam);

/* GLOBALS */
HHOOK hHook;
IMPORT HINSTANCE gDLLHInstance;

int WINAPI WinMain(      
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow)
{
    MSG msg;
    HINSTANCE libinstance;
    HOOKPROC hookProc;

    freopen("stdout.txt", "w", stdout);
    cout << "started..." << endl;

    /*
    libinstance = LoadLibrary((LPCTSTR)"proactive_monitor.dll");
    if(!libinstance)
    {
        ERRORMSG("LoadLibrary failed for 'proactive_monitor.dll");
        return 0;
    }
    hookProc = (HOOKPROC) GetProcAddress(libinstance, "");
    if(!hookProc)
    {
        ERRORMSG("GetProcAddress failed for 'hookCallback'");
        return 0;
    }
    */

    hookProc = keyboardHookCallback;

    hHook = SetWindowsHookEx(/*WH_CALLWNDPROC*/ WH_KEYBOARD, hookProc, gDLLHInstance, 0);
    if(!hHook)
    {
        ERRORMSG("SetWindowsHookEx failed");
        return 0;
    }

    while(GetMessage(&msg, NULL, 0, 0))
    {

        TranslateMessage(&msg);
        DispatchMessage(&msg);

        if(msg.message == WM_QUIT) break;
    }

    UnhookWindowsHookEx(hHook);

    return 0;
}

#endif /* MAKE_DLL */
