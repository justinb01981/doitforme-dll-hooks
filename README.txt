I'm interested in hooking OpenFile() calls in every process. Maybe other calls to, like CreateProcess().
It would be nice to reverse-engineer a good anti-virus program to see what they call to get their hooks
in... I would not be surprised if MS was giving them an undocumented API to use. Maybe not though.
There is a registry key you can set that will get a DLL loaded automatically into *every* process
that gets run in user space. That means the DLLMain function gets called whenever a process starts.
In DLLMain you can patch up the addresses used for OpenFile (or other API's...) to get a hook callback
called (which will then call the original address). Just an idea.