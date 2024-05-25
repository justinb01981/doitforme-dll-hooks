#include "windows.h"

#define PROACTIVE_PIPE_NAME "\\\\.\\pipe\\proactive_monitor_pipe"
#define AUTOMATE_MSG_PIPE_NAME "\\\\.\\pipe\\proactive_monitor_pipe"
#define AUTOMATE_MSG_PIPE_NAME_INJECT "\\\\.\\pipe\\proactive_monitor_pipe_inject"
#define PROACTIVE_PIPE_TYPE (PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT)
#define PROACTIVE_PIPE_TYPE_CLIENT (PIPE_READMODE_MESSAGE | PIPE_WAIT)
#define AUTOMATE_PIPE_TYPE_CLIENT (PIPE_READMODE_MESSAGE | PIPE_WAIT)

typedef void (*MonitorQueryCallback) (char *query, char *response_buf,
                                      size_t response_buf_size);

typedef struct
{
    HANDLE hPipe;
    //OVERLAPPED overlapped;
    bool inited;
} ProactivePipe;

int StartMonitorServer(MonitorQueryCallback cb);

void StopMonitorServer();
