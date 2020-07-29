#include <stdio.h>
#include <stdlib.h>


unsigned int ror(int param_1,int shift)

{
  return param_1 >> (8 - shift & 0x1f) | param_1 << (shift & 0x1f);
}

void main() {

	for( int hash = 0; hash < 1024; hash++){
	  long lVar1;
  	  srandom(hash & 0x3ff);
	  int j = 0;
	  while (j < 0x60) {
	    int lVar1 = rand();
	    char c = (char)(lVar1 & 0xFF);
	    printf("%02X", (unsigned int)(lVar1 & 0xFF));
	    j += 1;
	  }
	  printf("\n");
	}
}
