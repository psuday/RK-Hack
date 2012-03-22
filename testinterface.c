#include <stdio.h>

// I wanted to check out some basic C stuff. This is what happens when
// we operate in JIT mode.
// Essentially we cant cast a char * pointer to a struct pointer. 
// uday1 below is a kind of pointer which can be used for accessing the
// array members. But we cant use the increment operator on it. so
// we need to assign it to the appropriate variable such as uday2
// before we do any incrementing shenanigans.
// This was needed to check out the parameter passing stuff in the
// sc_example.c function.
int main(int argc, char ** argv) {

	struct gogash {
		char * str;
	};

	char * uday = "golly baba";

	char * uday1[] = { "gollay bab", "house", "peck"};
	char ** uday2  = uday1;

	

	struct gogash * up = (struct gogash *)++uday2;

	printf("%s\n", up->str);
}
