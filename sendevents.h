#ifndef __SENDEVENTS_H__
#define __SENDEVENTS_H__

typedef struct
{
    int left;
    int down;
    int move;
    int x;
    int y;
} MouseEvent;

typedef struct
{
    int vKey;
    int scanCode;
    int down;
} KeyboardEvent;

void SendEventsInit();
int SendMouseEvent(MouseEvent *me);
int SendKeyboardEvent(KeyboardEvent *ke);

#endif
