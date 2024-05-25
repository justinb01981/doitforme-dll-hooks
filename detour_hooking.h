#ifndef __DETOUR_HOOKING__
#define __DETOUR_HOOKING__

#define MAX_HOOKS 64
#define HOOK_CONTINUE(fptr_type, n) ((fptr_type) &gHooks[n].buf)

typedef unsigned long ULONG;
typedef unsigned short USHORT;

typedef struct
{
    unsigned char buf[64]; /* buffer to hold copy of original code's bytes we overwrote */
    ULONG jump1;       /* copied over original */
    ULONG jump2;       /* jump back to the remainder of the original code not overwritten */
    int bytes_relocated;
    unsigned char *modified_ptr;
} DHook;

extern DHook gHooks[MAX_HOOKS];
extern int gAddHookLastErr;

void init_hooking();
int add_hook(ULONG function, unsigned nHook, ULONG hook);
void reverse_hook(unsigned nHook);

void print_hex(void *p, unsigned size);


#endif
