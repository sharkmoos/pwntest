#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main()
{
	char data_buf[100];
	puts("Enter 100 bytes of data!");

	gets(data_buf);
	
	int string_len = strlen(data_buf);

	if ( string_len != 100 )
	{
		if ( string_len > 100 )
			puts("Too long!");
		else
			puts("Too short!");
	}
	else
	{
		puts("Well done!");
	}

	return 1;
}
