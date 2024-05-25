#include <iostream>
#include <fstream>
#include <time.h>
#include "windows.h"
#include "proactive_monitor.h"
#include "proactive_defines.h"
#include "sendevents.h"
#include "sounds.h"
#include "mutex.h"

using namespace std;

#define PIPE_INPUT_OUTPUT_BUFFER_SIZE 4096

#define CRIT_SEC_ENTER()
#define CRIT_SEC_EXIT()

#define LOCK()  wt_mutex_take(&mutex)
#define UNLOCK() wt_mutex_release(&mutex)


DWORD WINAPI EventMonitor           (LPVOID p);
void         EventMonitorCleanup    ();

/* globals */
bool gMonitorServerRunning = false;
MonitorQueryCallback gMonitorQueryCallback = NULL;
HANDLE ghMonitorPipe;
ProactivePipe *gWaitingPipe = NULL;
unsigned long runScriptStartTimeMs;
unsigned long runScriptFirstEventTimeMs;
unsigned long runScriptLastEventTimeMs;
int runScriptLastEventId;
bool recording_in_progress = false;
fstream fstreamRec;
HHOOK hookMouse = NULL;
HHOOK hookKeyboard = NULL;
MutexType mutex;
char pathPrefix[1024];
char playbackFilename[1024];

int CreatePipe(ProactivePipe *p, LPCTSTR name)
{
    memset(p, 0, sizeof(ProactivePipe));

    p->hPipe = CreateNamedPipe(name, PIPE_ACCESS_DUPLEX,
                               PROACTIVE_PIPE_TYPE,
                               PIPE_UNLIMITED_INSTANCES,
                               PIPE_INPUT_OUTPUT_BUFFER_SIZE,
                               PIPE_INPUT_OUTPUT_BUFFER_SIZE, 0, NULL);
    if(p->hPipe == NULL) return -1;
    p->inited = true;
    return 0;
}

void DestroyPipe(ProactivePipe *p)
{
    if(p->inited)
    {
        DisconnectNamedPipe(p->hPipe);
        CloseHandle(p->hPipe);
        p->hPipe = NULL;
        p->inited = false;
    }
}

int ServicePipe(ProactivePipe *p)
{
    if(!p->inited) return -1;
    if(ConnectNamedPipe(p->hPipe, NULL) != 0) return 0;
    if(GetLastError() == ERROR_PIPE_CONNECTED) return 0;
    return -1;
}

int UnServicePipe(ProactivePipe *p)
{
    if(!p->inited) return -1;
    FlushFileBuffers(p->hPipe);
    DisconnectNamedPipe(p->hPipe);
    CloseHandle(p->hPipe);
    return 0;
}

int AttachPipe(ProactivePipe *pOut, char *id)
{
    return 0;
}

int WritePipe(ProactivePipe *p, void *data, size_t len)
{
    DWORD w = len;
    if(TransactNamedPipe(p->hPipe, data, len, NULL, 0, NULL, NULL) == 0) return -1;
    return w;
}

int ReadPipe(ProactivePipe *p, void *dest, size_t len)
{
    DWORD bytesRead;

    if(TransactNamedPipe(p->hPipe, NULL, 0, dest, len, &bytesRead, NULL) == 0) return -1;
    return bytesRead;
}

int GetField(char *buf, char *bkey, char *ekey, char *dest)
{
    char *destb = dest;
    char *pbegin = strstr(buf, bkey);
    if(pbegin)
    {
        char *pend = strstr(pbegin, ekey);
        if(pend)
        {
            pbegin += strlen(bkey);
            while(pbegin < pend)
            {
                *dest = *pbegin;
                dest++;
                pbegin++;
            }
            *dest = '\0';
            return dest - destb;
        }
    }
    return -1;
}

BOOL GetSaveFilenameForRecording(char *filename)
{
    OPENFILENAME sfn;
    char initialPath[1024];
    char *filter = "*.rec\0\0";
    
    sprintf(initialPath, "%s\\recordings", pathPrefix);
    strcpy(filename, "recording.rec");

    memset(&sfn, 0, sizeof(sfn));
    sfn.lStructSize = sizeof(sfn);
    sfn.lpstrFilter = filter;
    sfn.nFilterIndex = 1;
    sfn.lpstrFile = filename;
    sfn.nMaxFile = 1024;
    sfn.lpstrInitialDir = initialPath;
    
    return GetSaveFileName(&sfn);
}

enum
{
    PARSEEVENT_ERR_FAIL = -1,
    PARSEEVENT_ERR_NONE_KEYBOARDEVENT = 0,
    PARSEEVENT_ERR_NONE_MOUSEEVENT
};



int ParseEvent(char *eventbuf, MouseEvent *me, KeyboardEvent *ke)
{
    int id;
    int ptx, pty;
    int key;
    unsigned long wparam, lparam;
    unsigned long time;
    char tmp[1024];

    id = ptx = pty = key = wparam = lparam = time = 0;

    if(GetField(eventbuf, "<id>", "</id>", tmp) > 0)
    {
        id = atoi(tmp);

        if(GetField(eventbuf, "<wp>", "</wp>", tmp) > 0) wparam = atoi(tmp);
        if(GetField(eventbuf, "<lp>", "</lp>", tmp) > 0) lparam = atoi(tmp);
        if(GetField(eventbuf, "<pt>", "</pt>", tmp) > 0)
        {
            char *ps = strchr(tmp, '/');
            if(ps)
            {
                sscanf(tmp, "%d/", &ptx);
                sscanf(ps+1, "%d", &pty);
            }
        }
        if(GetField(eventbuf, "<ti>", "</ti>", tmp) > 0) time = atoi(tmp);


        if(wparam == 255) return 0;

        if(runScriptLastEventTimeMs != 0 && time > runScriptLastEventTimeMs) Sleep(time - runScriptLastEventTimeMs);
        //else if(time < runScriptLastEventTimeMs) return 0;    /* ignore out-of-order events? */

        runScriptLastEventTimeMs = time;


        //if(id == runScriptLastEventId && id != WM_MOUSEMOVE) return 0;
        //runScriptLastEventId = id;


        switch(id)
        {
            case WM_LBUTTONDOWN:
                me->left = 1;
                me->down = 1;
                me->move = 0;
                me->x = ptx;
                me->y = pty;
                return PARSEEVENT_ERR_NONE_MOUSEEVENT;

            case WM_LBUTTONUP:
                me->left = 1;
                me->down = 0;
                me->move = 0;
                me->x = ptx;
                me->y = pty;
                return PARSEEVENT_ERR_NONE_MOUSEEVENT;

            case WM_RBUTTONDOWN:
                me->left = 0;
                me->down = 1;
                me->move = 0;
                me->x = ptx;
                me->y = pty;
                return PARSEEVENT_ERR_NONE_MOUSEEVENT;

            case WM_RBUTTONUP:
                me->left = 0;
                me->down = 0;
                me->move = 0;
                me->x = ptx;
                me->y = pty;
                return PARSEEVENT_ERR_NONE_MOUSEEVENT;

            case WM_MOUSEMOVE:
                me->left = 0;
                me->down = 0;
                me->move = 1;
                me->x = ptx;
                me->y = pty;
                return PARSEEVENT_ERR_NONE_MOUSEEVENT;  

            case WM_KEYDOWN:
                ke->down = 1;
                ke->vKey = wparam;
                return PARSEEVENT_ERR_NONE_KEYBOARDEVENT;

            case WM_KEYUP:
                ke->down = 0;
                ke->vKey = wparam;
                return PARSEEVENT_ERR_NONE_KEYBOARDEVENT;
            
            default:
                return PARSEEVENT_ERR_FAIL;
        }
    } 
}

void RunScript()
{
    char line[1024];
    char lastLine[1024];
    MouseEvent me;
    KeyboardEvent ke; 

    fstream f;

    f.open(/*"recording.log"*/playbackFilename, ios::in|ios::out);

    SendEventsInit();

    cout << "Running in 3 seconds..." << endl;
    Sleep(1000);
    AsyncPlaySound(3);
    runScriptStartTimeMs = timeGetTime();
    runScriptFirstEventTimeMs = 0;
    runScriptLastEventTimeMs = 0;
    runScriptLastEventId = 0;

    memset(lastLine, 0, sizeof(lastLine));

    while(f.is_open() && !f.eof())
    {
        if(GetAsyncKeyState(VK_ESCAPE)) break;

        f >> line;
        if(strcmp(line, lastLine) == 0 || strstr(line, "<wp>255</wp>"))
        {
            cout << "duplicate/bad event: " << lastLine << endl;
            continue;
        }
        //if(strlen(line) == 0) break;
        strcpy(lastLine, line);
        
        cout << "Processing line: " << line;
        int r = ParseEvent(line, &me, &ke);
        if(r == PARSEEVENT_ERR_NONE_MOUSEEVENT)
        {
            SendMouseEvent(&me);
        }
        else if(r == PARSEEVENT_ERR_NONE_KEYBOARDEVENT)
        {
            SendKeyboardEvent(&ke);
        }
        cout << "...done" << endl;
    }

    cout << "Playback done" << endl;

    f.close();
    AsyncPlaySound(4);
    Sleep(1000);
}

unsigned long timeLastRecEvent = 0;
char lastRecEvent[1024];
int recEventsInited = 0;

DWORD WINAPI PipeWorker(LPVOID p)
{
    DWORD bytesRead;
    int r;
    char readbuf[4096], writebuf[2048];
    ProactivePipe *pipe = (ProactivePipe *) p;

    if(!pipe) return 0;

    if(!recEventsInited)
    {
        memset(lastRecEvent, 0, sizeof(lastRecEvent));
        recEventsInited = 1;
    }

    r = 0;
    while(1)
    {
        memset(readbuf, 0, sizeof(readbuf));
        memset(writebuf, 0, sizeof(writebuf));

        if(!ReadFile(pipe->hPipe, readbuf, sizeof(readbuf)-1, &bytesRead, NULL))
        { 
            break;
        }
        
        if(bytesRead > 0)
        {
            if(recording_in_progress)
            {
                cout << readbuf << endl;
                LOCK();
                if(/*timeGetTime() == timeLastRecEvent*/ /*strcmp(readbuf, lastRecEvent) == 0*/ 0)
                {
                    cout << "duplicate event: " << readbuf << endl;
                    UNLOCK();
                    break;
                }
                timeLastRecEvent = timeGetTime();
                strcpy(lastRecEvent, readbuf);
                fstreamRec << readbuf << endl;
                fstreamRec.flush();
                UNLOCK();
            }

            /* TODO: write back a response */
            /*
            if(gMonitorQueryCallback)
            {
                gMonitorQueryCallback(readbuf, writebuf, sizeof(writebuf)-1);
            }
            else
            {
                sprintf(writebuf, "<response>allow</response>");
            }

            if(!WriteFile(pipe->hPipe, writebuf, strlen(writebuf), &bytesRead, NULL))
            {
                break;
            }
            */
        }
        else
        {
            r = GetLastError();
            break;
        }
    }

    UnServicePipe(pipe);
    
    delete pipe;

    return 0;
}

DWORD WINAPI PipeServer(LPVOID p)
{
    ProactivePipe *pipe;
    char *pipeName = AUTOMATE_MSG_PIPE_NAME;
    DWORD threadID;
    HANDLE hThread;

    while(1)
    {
        pipe = new ProactivePipe;
        if(CreatePipe(pipe, pipeName) != 0)
        {
            cout << "CreatePipe failed" << endl;
            delete pipe;
            pipe = NULL;
        }

        if(ServicePipe(pipe) != 0)
        {
            cout << "ServicePipe failed" << endl;
            continue;
        }

        hThread = CreateThread(NULL, 0, PipeWorker, (LPVOID) pipe, 0, &threadID);
        if(hThread == NULL)
        {
            cout << "thread creation failed" << endl;
            UnServicePipe(pipe);
            delete pipe;
            continue;
        }

        CloseHandle(hThread);
    }
    return 0;
}

DWORD WINAPI RecordController(LPVOID p)
{
    MSG msg;

    while(1)
    {
        if(PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        else
        {
            Sleep(1);
        }

        SHORT ctrl = GetAsyncKeyState(VK_CONTROL);
        SHORT shift = GetAsyncKeyState(VK_SHIFT);
        SHORT snapshot = GetAsyncKeyState(VK_SNAPSHOT);
        SHORT pause = GetAsyncKeyState(VK_END);
        SHORT home = GetAsyncKeyState(VK_HOME);
        if(ctrl && ctrl != 1 /*&& shift && shift != 1*/)
        {
            if(recording_in_progress)
            {
                if(pause && pause != 1)
                {
                    Sleep(1000);
                    recording_in_progress = false;
                    Sleep(1000);
                    fstreamRec.close();
                    EventMonitorCleanup();
                    AsyncPlaySound(2);
                    cout << "Recording is " << "stopped" << endl;
                }
            }
            else
            {
                if(snapshot && snapshot != 1)
                {
                    char filename[255];

                    if(GetSaveFilenameForRecording(filename))
                    {
                        Sleep(2000);
                        EventMonitor(NULL);
                        recording_in_progress = true;
                        //sprintf(filename, "recording.log");
                        fstreamRec.open(filename, ios::out|ios::in|ios::trunc);
                        AsyncPlaySound(1);
                        cout << "Recording is " << "started" << endl;
                    }
                }
                else if(home && home != 1)
                {
                    RunScript();
                }
            }
        }
    }
    return 0;
}

DWORD WINAPI EventMonitor(LPVOID p)
{
    HHOOK r;
    HOOKPROC MyMouseProc;
    HOOKPROC MyKeyboardProc;
    HMODULE hdll;

    hdll = LoadLibrary("automate_hooks.dll");
    cout << "automate_hooks.dll: " << hdll << endl;

    MyMouseProc = (HOOKPROC) GetProcAddress(hdll, "_MyMouseProc@12");
    cout << "MyMouseProc: " << MyMouseProc << endl;
    r = SetWindowsHookEx(WH_MOUSE_LL, MyMouseProc, /*hdll*/ GetModuleHandle(NULL), 0); /* hook mouse */
    cout << "SetWindowsHookEx(MyMouseProc):" << r << endl;
    hookMouse = r;
    MyKeyboardProc = (HOOKPROC) GetProcAddress(hdll, "_MyKeyboardProc@12");
    cout << "MyKeyboardProc: " << MyKeyboardProc << endl;
    r = SetWindowsHookEx(WH_KEYBOARD_LL, MyKeyboardProc, /*hdll*/ GetModuleHandle(NULL), 0); /* hook keyboard */
    cout << "SetWindowsHookEx(MyKeyboardProc):" << r << endl;
    hookKeyboard = r;
    return 0;
}

void EventMonitorCleanup()
{
    if(hookMouse) UnhookWindowsHookEx(hookMouse);
    if(hookKeyboard) UnhookWindowsHookEx(hookKeyboard);
}

enum {
    STATE_RECORD,
    STATE_PLAYBACK
};

int state = STATE_RECORD;

void parseCommandLine(LPSTR pCmdLine)
{
    char path[1024];
    char *p;

    cout << "lpCmdLine: " << pCmdLine << endl;

    memset(pathPrefix, 0, sizeof(pathPrefix));
    
#if 0
    sscanf(pCmdLine, "%s", path);
#endif
    GetModuleFileName(NULL, path, sizeof(path));
    if(strlen(path) > 0)
    {
        p = path + strlen(path);
        while(*(p-1) && *(p-1) != '/' && *(p-1) != '\\')
        {
            p--;
        }
        strncpy(pathPrefix, path, p - path);
    }

    cout << "pathPrefix: " << pathPrefix << endl;
    
    memset(playbackFilename, 0, sizeof(playbackFilename));
    if(pCmdLine[0] == '"')
        strncpy(playbackFilename, pCmdLine+1, strlen(pCmdLine)-2);
    else
        strcpy(playbackFilename, pCmdLine);

    cout << "playbackFilename: " << playbackFilename << endl;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    HANDLE hThread;
    DWORD threadID;

    freopen(state == STATE_RECORD? "stdout.log": "stdout_playback.log", "w", stdout);

    parseCommandLine(lpCmdLine);

    if(strstr(lpCmdLine, /*"play"*/ ".rec")) state = STATE_PLAYBACK;

    cout << "Monitor starting" << endl;

    srand(time(NULL));

    wt_mutex_init(&mutex);

    //pipe = NULL;

    if(state == STATE_PLAYBACK)
    {
        RunScript();
    }
    else
    {
        //EventMonitor(NULL);

        hThread = CreateThread(NULL, 0, PipeServer, (LPVOID) NULL, 0, &threadID);
        CloseHandle(hThread);


        hThread = CreateThread(NULL, 0, RecordController, (LPVOID) NULL, 0, &threadID);
        CloseHandle(hThread);

        MSG msg;
        while(GetMessage(&msg, NULL, 0, 0))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);

        }

        //EventMonitorCleanup();
    }
    cout << "Monitor shutting down" << endl;

    wt_mutex_destroy(&mutex);
}
