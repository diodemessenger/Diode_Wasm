#include <stdio.h>

void DEBUG_print(unsigned char *A, unsigned long long L)
{
	unsigned long long i;
	for ( i=0; i<L; i++ ) fprintf(stdout, "%02X", A[i]);
	if ( L == 0 ) fprintf(stdout, "00");
}
