#include <stdio.h>

/**
 * It prints out "simple rop." and then gets a buffer from the user.
 * 
 * @return The address of the buffer.
 */
int main(){
	setbuf(stdout, NULL);
	char buffer[32];
	puts("simple rop.\n");
	gets(buffer);
	return 0;
}
