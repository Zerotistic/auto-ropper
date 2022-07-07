#include <stdio.h>

int main(){
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);
	char buffer[32];
	puts("simple rop.\n");
	gets(buffer);
	return 0;
}
