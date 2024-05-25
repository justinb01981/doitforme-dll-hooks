
#include <windows.h>
#include <iostream>
#include <string.h>

using namespace std;

typedef unsigned long ULONG;

int gCount = 0;
int *gCountP;

void print_something1(char *str)
{
    cout << str << endl;
}

void __declspec(naked) my_hook(char *str)
{
    __asm
    {
        mov dword ptr [gCountP],1;
        ret;
    }
}

void __declspec(naked) trampoline()
{
    __asm
    {
        jmp my_hook;
    }
}

void add_hook(ULONG function, ULONG hook, bool reverse)
{
    char buf[10];
    MEMORY_BASIC_INFORMATION meminfo;
    DWORD oldProtect;
    int i = 0;

    cout << "attempting hook..." << endl;
    /* buf = JMP DWORD PTR %hook */
    memcpy(buf, trampoline, sizeof(buf));

    cout << "trampoline=" << cout.hex << (ULONG) trampoline << endl;

    for(i = 0; i < sizeof(buf); i++)
    {
        cout << (unsigned int) buf[i];
    }
    cout << endl;

    /* probably necessary to do VirtualProtect here... */
    if(!VirtualQuery((void*) function, &meminfo, sizeof(meminfo)))
    {
        cout << "VirtualQuery failed" << endl;
        return;
    }

    if(!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, PAGE_READWRITE, &meminfo.Protect))
    {
        cout << "VirtualProtect failed" << endl;
        return;
    }
    memcpy((void*)function, buf, sizeof(buf));

    if(!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, meminfo.Protect, &oldProtect))
    {
        return;
    }
    cout << "hooking complete" << endl;
}

int main(int argc, char **argv)
{
    gCountP = &gCount;

    add_hook((ULONG) print_something1, (ULONG) my_hook, false);
    print_something1("hope this works...");
    cout << "gCount=" << gCount;
    return 0;
}
