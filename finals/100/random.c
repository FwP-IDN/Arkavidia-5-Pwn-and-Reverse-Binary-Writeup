#include <stdio.h>
#include <stdlib.h>

int main() {
	srand(1337);
	for(int i = 0; i < 252; i++) {
		printf("%d ", rand() % 100);
	}
}
