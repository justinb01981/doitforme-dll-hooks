// Hook_IAT.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "Hook_IAT.h"
#include <stdio.h>
#include <string.h>

bool HOOKED = false;

//just make sure our replacement function prototype matchs expected 
int _cdecl m_strcmp(const char * arg1, const char* arg2){

		char buf[200];
		sprintf(buf,"Inside hooked m_strcmp.\n\nArg1=%s\nArg2=%s", arg1, arg2);
		MessageBox(0,buf,"",0);
		
		return strcmp(arg1,arg2); //also we could fake return value if want

}


BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			
			if(!HOOKED){

				int *thunk = (int*)0x402024 ; //disasm and get address 
			    int val = *thunk;
				int fxAddress;

				HINSTANCE h=0;
				int fx=0;

				h = GetModuleHandle("msvcrt.dll");
				fx = (int)GetProcAddress( h,"strcmp");

				char buf[200];
				sprintf(buf, "Preparing to patch IAT Current Val=%x \n\tstrcmp Address=%x", *thunk, fx);
				MessageBox(0,buf,"",0);
										
				fxAddress = (int)m_strcmp ;
				*thunk = fxAddress;
				
				sprintf(buf, "IAT Patched.. old val=%x \n\t Now is=%x \n\t fxAddr=%x", val, *thunk, fxAddress);
				MessageBox(0,buf,"",0);


				HOOKED = true;
			}

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
    }
    return TRUE;
}

