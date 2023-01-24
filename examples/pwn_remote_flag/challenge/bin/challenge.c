#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <stdlib.h>

void print_flag()
{
    FILE* fp = fopen("/flag", "r");
    char flag[100];
    fgets(flag, sizeof(flag), fp);
    puts(flag);
    exit(0);
}

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
        print_flag();
    }

}
