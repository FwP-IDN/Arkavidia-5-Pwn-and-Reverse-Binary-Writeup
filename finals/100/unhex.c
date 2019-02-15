#include <stdio.h>
#include <string.h>

char unhex(char *a1)
{
  char v1; // dl
  char *result; // rax
  unsigned long long v3; // [rsp+18h] [rbp-18h]
  size_t i; // [rsp+20h] [rbp-10h]
  size_t v5; // [rsp+28h] [rbp-8h]

  v5 = strlen(a1);
  v3 = 0LL;
  for ( i = 0LL; i < v5 >> 1; ++i )
  {
    v1 = (unsigned char)(a1[v3 + 1] >> 7) >> 3;
    a1[v3 >> 1] = 16 * ((a1[v3] % 32 + 9) % 25) + ((char)(((v1 + a1[v3 + 1]) & 0x1F) - v1) + 9) % 25;
    v3 += 2LL;
  }
  result = (char *)&a1[v5 >> 1];
  *result = 0;
  return result;
}



int main() {
  char buffer[20];
  fgets(buffer, 20, stdin);
  unhex(buffer);
  printf("%hhx%hhx\n", buffer[0], buffer[1]);
}