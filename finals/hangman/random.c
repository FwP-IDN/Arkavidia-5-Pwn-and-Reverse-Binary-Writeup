#include<stdio.h>
#include<time.h>
#include<stdlib.h>

char buf[100];

int main() {
	for(int i = 0; i < 4; i++) {
		malloc(0x100);
	}
	srand(time(0));
	setvbuf(stdout, NULL, _IONBF, 0);
	while(1) {
		if(!gets(buf)) {
			return;
		}
		printf("%d\n", rand());
	}
}