#include <stdio.h>
#include <string.h>
#include <conio.h>

//obviously this code has other problems but we 
//just needed a quick example to to make a quick 
//point for the IAT hooking article 

void main(void){

	char *pass = "blah";
	char buf[30];

	printf("Password:");
	gets(buf);

	if( strcmp(pass,buf) ==0 )	printf("ya good");
	 else printf("nay bad");
	

}

