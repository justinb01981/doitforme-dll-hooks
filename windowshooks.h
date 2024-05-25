#ifndef __WINDOWSHOOKS_H__
#define __WINDOWSHOOKS_H__

#include <windows.h>

LRESULT CALLBACK MyMouseProc(int nCode, WPARAM wParam, LPARAM lParam);

LRESULT CALLBACK MyKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);


#endif
