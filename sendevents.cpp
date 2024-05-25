#include "windows.h"
#include "sendevents.h"

struct
{
    int screen_width;
    int screen_height;
} SendEventGlobals;

void SendEventsInit()
{
    /* TO-DO: grab these programatically.. */
    SendEventGlobals.screen_width = GetSystemMetrics(SM_CXSCREEN);
    SendEventGlobals.screen_height = GetSystemMetrics(SM_CYSCREEN);
}

/* see http://msdn.microsoft.com/en-us/library/ms646310%28VS.85%29.aspx */

/* http://msdn.microsoft.com/en-us/library/ms646273%28VS.85%29.aspx */
int SendMouseEvent(MouseEvent *me)
{
    INPUT input;

    memset(&input, 0, sizeof(input));
    input.type = INPUT_MOUSE;
    unsigned long tmpx = (me->x * 65535) / SendEventGlobals.screen_width;
    unsigned long tmpy = (me->y * 65535) / SendEventGlobals.screen_height;
    input.mi.dx = tmpx;
    input.mi.dy = tmpy; 
    input.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | (me->move? MOUSEEVENTF_MOVE: (me->left? (me->down? MOUSEEVENTF_LEFTDOWN: MOUSEEVENTF_LEFTUP): ((me->down? MOUSEEVENTF_RIGHTDOWN: MOUSEEVENTF_RIGHTUP))));
    
    return SendInput(1, &input, sizeof(input));
}

int SendKeyboardEvent(KeyboardEvent *ke)
{
    INPUT input;

    memset(&input, 0, sizeof(input));
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = ke->vKey;
    input.ki.wScan = /*ke->scanCode*/ 0;
    input.ki.dwFlags = (ke->down? 0: KEYEVENTF_KEYUP) | (0 /*KEYEVENTF_SCANCODE*/);
    
    return SendInput(1, &input, sizeof(input));
}
