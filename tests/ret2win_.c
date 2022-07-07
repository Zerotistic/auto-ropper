#include <stdio.h>

void print_flag()
{
	system("cat flag.txt");
}


int pwn_me()
{
	char my_buf[20] = {'\x00'};
	gets(my_buf);
	return 0;
}

void main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
	puts("pwn_me");
	pwn_me();
}