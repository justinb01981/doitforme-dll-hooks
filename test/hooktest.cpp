
#include <iostream>
#include <windows.h>

using namespace std;

void makew(unsigned char * i, unsigned short *o)
{
    while(*i != '\0')
    {
        *o = (unsigned short) *i;
        o++;
        i++;
    }
}

int main(int argc, char **argv)
{
    char *procname = "c:\\walkietalkie.exe";
    unsigned short procnamew[64];
    PROCESS_INFORMATION procinfo;
    STARTUPINFO startupinfo;

    if(LoadLibrary("proactive_monitor.dll") == NULL)
    {
        return 0;
    }

    makew((unsigned char*) procname, procnamew);
    /* call CreateProcessW for the process passed in */
    memset(&startupinfo, 0, sizeof(startupinfo));
    startupinfo.cb = sizeof(startupinfo);
    CreateProcessA(procname, NULL, NULL, NULL, true, 0x0, NULL, NULL, &startupinfo, &procinfo);

    cout << "Process created successfully" << endl;
    cout << "Process created successfully" << endl;
    return 0;
}
