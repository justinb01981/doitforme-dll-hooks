#ifndef __MUTEX_H__
#define __MUTEX_H__

typedef HANDLE MutexType;

void wt_mutex_init(MutexType *mutex);
void wt_mutex_destroy(MutexType *mutex);
void wt_mutex_take(MutexType *mutex);
void wt_mutex_release(MutexType *mutex);

#endif