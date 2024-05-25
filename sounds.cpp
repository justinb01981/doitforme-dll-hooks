#include <stdio.h>
#include <windows.h>

extern char pathPrefix[];

void AsyncPlaySound(int id)
{
    char filename[1024];

    sprintf(filename, "%s\\sounds\\%d.wav", pathPrefix, id);
    PlaySound(filename, NULL, SND_ASYNC | SND_FILENAME);
}
