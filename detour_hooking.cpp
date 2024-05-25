
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include "detour_hooking.h"

using namespace std;

fstream logstream;

/* globals */
DHook gHooks[MAX_HOOKS];
int gAddHookLastErr = 0;

/* this function used as a hooking template */
/* 5 bytes big */
void __declspec(naked) trampoline()
{
    __asm
    {
        /*
        call hookprintp;
        */
        jmp /* hookprintp */ gHooks[0].jump1;
    }
}


/* this function used as a hooking template */
/*
char *pTargetLanding = NULL;
*/
void __declspec(naked) trampoline_back()
{
    __asm
    {
        jmp /* pTargetLanding */ gHooks[0].jump2;
    }
}

void print_hex(void *p, unsigned size)
{
    unsigned char *ptr = (unsigned char*) p;
    while(size > 0)
    {
        logstream << hex << (unsigned int) *ptr; //printf("%02x", *ptr);
        size--;
        ptr++;
    }
    logstream << endl; //printf("\n");
}

int DetermineLanding(ULONG function, ULONG requiredSize)
{
    unsigned char *ptr;
    unsigned offset = 0;

    ptr = (unsigned char *) function;
    while(offset < /* size of code to insert ... */ requiredSize)
    {
        /* TODO: probably could make this much smarter.. */
        /* TODO: some of these are relative to the current instruction.. relocating them will crash */
        switch(*ptr)
        {
        case 0x6a:  /* push <byte> */
            offset += 2;
            break;
        case 0xc3:  /* ret */
            return -1;
            break;
        case 0x50:  /* PUSH eax */
        case 0x51:  /* PUSH ecx */
        case 0x55:  /* PUSH ebp */
        case 0x5d:  /* POP ebp */
            offset += 1;
            break;
        case 0x83:  /* sub exp, 8 */
            if(*(ptr+1) == 0xec)
            {
                offset += 3;
            }
            else
            {
                return -1;
            }
            break;
        case 0x8b:
            if(*(ptr+1) == 0xec || *(ptr+1) == 0xff)
            {
                offset += 2;
            }
            else if(*(ptr+1) == 0x45)
            {
                offset += 3;
            }
            else if(*(ptr+1) == 0x55 && *(ptr+2) == 0x10)
            {
                offset += 3;
            }
            else
            {
                return -1;
            }
            break;
        case 0xc7:  /* c745fc28c24200  mov     dword ptr [ebp-4],offset */
            if(*(ptr+1) == 0x45)
            {
                offset += 7;
            }
            else
            {
                return -1;
            }
            break;
        case 0xe8:  /* call */
            if(*(ptr+1) == 0xe5)
            {
                offset += 5;
            }
            else
            {
                return -1;
            }
            break;
        case 0xe9:  /* unconditional jump, must follow this and do patching there.. (debug?) */
            logstream << "unconditional jump found.. debug build?" << endl;
            return -2;
            break;
        /* TODO: not right... FF752c = push dword ptr [ebp+2c] */
        case 0xff:
            if(*(ptr+1) == 0x75)
            {
                offset += 3;
            }
            else if(*(ptr+1) == 0x25) /* long jump */
            {
                offset += 5;
            }   
            else
            {
                return -1;
            }
            break;
        default:
            return -1;
            break;
        }
        ptr = (unsigned char *) function + offset;
    }
    return offset;
}

void reverse_hook(unsigned nHook)
{
    MEMORY_BASIC_INFORMATION meminfo;
    DWORD oldProtect;

    if(!gHooks[nHook].modified_ptr) return;

    if(!VirtualQuery((void*) gHooks[nHook].modified_ptr, &meminfo, sizeof(meminfo)))
    {
        logstream << "VirtualQuery failed" << endl;
        return;
    }

    if(!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, PAGE_READWRITE, &meminfo.Protect))
    {
        logstream << "VirtualProtect failed" << endl;
        return;
    }

    memcpy(gHooks[nHook].modified_ptr, gHooks[nHook].buf, gHooks[nHook].bytes_relocated);
    gHooks[nHook].modified_ptr = NULL;
 
    if(!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, meminfo.Protect, &oldProtect))
    {
        return;
    }

    FlushInstructionCache(NULL, NULL, NULL);    /* not sure this is working.. */

    logstream << "\nunhooked hook " << nHook << endl;
}

int add_hook(ULONG function, unsigned nHook, ULONG hook)
{
    MEMORY_BASIC_INFORMATION meminfo;
    DWORD oldProtect;
    DWORD dwtmp;
    int i = 0;
    char *pbuffer, tmp[64];
    unsigned char ljbuf[6];
    unsigned long offset;

    gAddHookLastErr = 0;

    offset = /* (&gHooks[1].buf[0]) - (&gHooks[0].buf[0]) */ sizeof(DHook);

    if(gHooks[nHook].modified_ptr) { gAddHookLastErr = 1; return 0; }

    pbuffer = (char *) gHooks[nHook].buf;

    logstream << "attempting hook..." << endl;

    jump_table_retry:
    /* probably necessary to do VirtualProtect here... */
    if(!VirtualQuery((void*) function, &meminfo, sizeof(meminfo)))
    {
        logstream << "VirtualQuery failed" << endl;
        gAddHookLastErr = 2;
        return 0;
    }

    if(!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, PAGE_READWRITE, &meminfo.Protect))
    {
        logstream << "VirtualProtect failed" << endl;
        gAddHookLastErr = 3;
        return 0;
    }

    /* we will overrite the first 5 bytes of the TargetFunction with an unconditional long JMP (5 bytes)
     * to our trampoline, and in the trampoline we will replace those instructions we overwrote, then
     * jump back to the original function + the offset of the next instruction */
    /* http://research.microsoft.com/~galenh/Publications/HuntUsenixNt99.pdf */
    /* it's not as simple as just copying 5 bytes over, we need to copy the whole instruction
     * and it's operands... 5 bytes may fall in the middle of an instruction... */

    /* determine landing within original code */
    gHooks[nHook].bytes_relocated = DetermineLanding(function, 6);
    logstream << "landing_offset = " << gHooks[nHook].bytes_relocated << endl;
    sprintf(tmp, "pbuffer=%x, function=%x\n\tlanding offset=%d",
            (unsigned) pbuffer, (unsigned) function, gHooks[nHook].bytes_relocated);
    if(gHooks[nHook].bytes_relocated > 0)
    {
        /* copy over part of original function */
        memcpy(pbuffer, (void *) function, gHooks[nHook].bytes_relocated);
        print_hex(pbuffer, gHooks[nHook].bytes_relocated);

        /* setup trampoline->original jump */
        /*
        pTargetLanding = (char *) TargetFunction + gHooks[nHook].bytes_relocated;
        gHooks[nHook].jump2 = function + gHooks[nHook].bytes_relocated;
        memcpy(&dwtmp, (char*) (trampoline_back)+2, sizeof(dwtmp));
        memcpy(pbuffer + gHooks[nHook].bytes_relocated, trampoline_back, 6);
        memcpy(pbuffer + gHooks[nHook].bytes_relocated + 2, &dwtmp, sizeof(dwtmp));

        print_hex(pbuffer + gHooks[nHook].bytes_relocated, 6);
        */
        print_hex((void*) function, 20);

        ljbuf[0] = 0xff; ljbuf[1] = 0x25;
        gHooks[nHook].jump1 = hook;
        gHooks[nHook].jump2 = function + gHooks[nHook].bytes_relocated;
        logstream << "trampoline_back->";
        print_hex((void*) gHooks[nHook].jump2, 10);
        memcpy(&dwtmp, (char*) (trampoline_back) + 2, 4);
        dwtmp += /*sizeof(DHook)*/ offset * nHook;
        memcpy(ljbuf+2, &dwtmp, sizeof(dwtmp));
        memcpy(pbuffer + gHooks[nHook].bytes_relocated, ljbuf, sizeof(ljbuf));
    }
    else
    {
#if 0
        if(gHooks[nHook].bytes_relocated == -2)    /* long jump */
        {
            char tmp[4];
            memcpy(tmp, (void*) (function+1), sizeof(tmp));
            logstream << "jump table entry-> ";
            print_hex(tmp, sizeof(tmp));
            function += *((DWORD*) tmp);
            goto jump_table_retry;
        }
#endif
        logstream << "hooking failed, couldn't determine landing offset" << endl;
        gAddHookLastErr = 4;
        return 0;
    }

    /* overwrite original with our JMP */
    gHooks[nHook].modified_ptr = (unsigned char*) function;
    memcpy(gHooks[nHook].modified_ptr, trampoline, 6);
    memcpy(&dwtmp, (char*) trampoline + 2, sizeof(dwtmp));
    dwtmp += /* sizeof(DHook) */ offset * nHook;
    memcpy(gHooks[nHook].modified_ptr + 2, &dwtmp, sizeof(dwtmp));

    if(!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, meminfo.Protect, &oldProtect))
    {
        gAddHookLastErr = 5;
        return 0;
    }

    /* make our trampoline area executable */
    if(!VirtualQuery((void*) &gHooks, &meminfo, sizeof(gHooks)))
    {
        logstream << "VirtualQuery failed" << endl;
        gAddHookLastErr = 6;
        return 0;
    }   

    if(!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, PAGE_EXECUTE_READWRITE, &meminfo.Protect))
    {
        logstream << "VirtualProtect failed" << endl;
        gAddHookLastErr = 7;
        return 0;
    }

    FlushInstructionCache(NULL, NULL, NULL);

    return 1;
}

void init_hooking()
{
    logstream.open("C:\\proactive_debug.log", ios::out|ios::app);
    memset(&gHooks, 0, sizeof(gHooks));
}
