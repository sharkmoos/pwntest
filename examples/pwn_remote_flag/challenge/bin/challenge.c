#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>

int main()
{
    // this can often be useful for remote challenges
    // unless you want to manually flush buffers
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    char user_buf[200];

    puts("Send me 150 characters to get a free flag!");

    fgets(user_buf, sizeof(user_buf), stdin);

    if ( strlen(user_buf) != 150 )
    {
        puts("You didn't send me 150 characters!");
        return 1;
    }
    else
    {
        puts("Here's your flag!");
        FILE* fp = fopen("flag", "r");
        sendfile(1, fileno(fp), NULL, 0x100);
        return 0;
    }

}
