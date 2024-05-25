all: automate_tool.exe
        cl.exe /w /EHsc /LD /D_CRT_SECURE_NO_DEPRECATE /DMAKE_DLL proactive_monitor_dll.cpp detour_hooking.cpp user32.lib winmm.lib /link /out:proactive_monitor.dll
        cl.exe /w /EHsc /LD /D_WIN32_WINNT=0x0500 /D_CRT_SECURE_NO_DEPRECATE /DMAKE_DLL windowshooks.cpp detour_hooking.cpp user32.lib winmm.lib /link /out:automate_hooks.dll


automate_tool.exe: proactive_monitor.cpp
	cl.exe /w /EHsc /DEBUG:FULL /D_WIN32_WINNT=0x0500 /D_CRT_SECURE_NO_DEPRECATE /DPIPE_TEST=1 proactive_monitor.cpp sendevents.cpp sounds.cpp mutex.cpp comdlg32.lib user32.lib winmm.lib /link /out:automate_tool.exe

clean:
	del proactive_monitor.dll automate_hooks.dll automate_tool.exe

