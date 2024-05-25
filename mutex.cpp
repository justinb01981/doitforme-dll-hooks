#include <windows.h>
#include "mutex.h"

void wt_mutex_init(MutexType *mutex)
{
    *mutex = CreateMutex(NULL, false, NULL);
}

void wt_mutex_destroy(MutexType *mutex)
{
    CloseHandle(*mutex);
}

void wt_mutex_take(MutexType *mutex)
{
    while(true)
    {
        if(WaitForSingleObject(*mutex, INFINITE) == 0)
            break;
    }
}

void wt_mutex_release(MutexType *mutex)
{
    ReleaseMutex(*mutex);
}