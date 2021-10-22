#define NO_CALC_DETECT
#define USE_TI92PLUS

#include <stdio.h>
#include <stdlib.h>
#include "lib/time.c"
#include <vat.h>

#include "lib/sha1.c"
#include "lib/hmac.c"

#define HeapDeref _rom_call(void*,(HANDLE),96)

const char NO_SECRETS [] = "No secrets.";

static char *convert_to_sym_str (char *buf, char *src) {
        char *dst = buf;
        *dst = '\0';
        dst += 1;
        while (*src != '\0') {
                        *dst = *src;
                        dst += 1;
                        src += 1;
        }
        *dst = '\0';
        return dst;
}

int main (int argc, char *argv[]) {
  printf("TOTP-Pedrom 0.0.2 - 2021-10-23\n");

  if(argc < 7) {
    printf("use: totp key tz dur yr mon day hr min sec\n");
    return(1);
  }

  char * endPtr;
  int tz=atoi(argv[2]);
  unsigned short dur=strtoul(argv[3], &endPtr, 10);
  unsigned short year=strtoul(argv[4], &endPtr, 10);
  unsigned short month=strtoul(argv[5], &endPtr, 10);
  unsigned short day=strtoul(argv[6], &endPtr, 10);
  unsigned short hour=strtoul(argv[7], &endPtr, 10);
  unsigned short minute=strtoul(argv[8], &endPtr, 10);
  unsigned short second=strtoul(argv[9], &endPtr, 10);
  printf("Date: %02d/%02d/%d %02d:%02d:%02d UTC%+d\n", day, month, year, hour, minute, second, tz);

  char * secret=malloc(256);
  FILE *KeyFN = fopen (argv[1], "r");
  if(KeyFN == NULL) {
    printf("- Error opening key file, exitting now.\n");
    return(1);
  }
  fgets(secret, 255, KeyFN);
  fclose(KeyFN);
  if(!strncmp(secret, NULL, 255)) {
    printf("- Error reading key\n");
    return(1);
  }
  printf("- Key %s opened, read and is non-NULL\n", KeyFN);
  printf("- Code validity: %ds\n", dur);

  char * code;
  int64_t timestamp=get_timestamp (0, tz, year, month, day, hour, minute, second);
  unsigned int code_len=6;

  int64_t counter=(int64_t)timestamp/dur;

  /* Do Hmac with specified hash function */
  unsigned char hmac_output [20];
  hmac (hmac_output, secret, strlen(secret), (unsigned char *) &counter, 8);
  /* do truncation to single integer */
  unsigned int offset = hmac_output [19] & 0xf;
  uint32_t code_numeric = ((uint32_t) hmac_output [offset] & 0x7f) << 24
    | ((uint32_t) hmac_output [offset + 1]) << 16
    | ((uint32_t) hmac_output [offset + 2]) << 8
    | ((uint32_t) hmac_output [offset + 3]);

  /* shorten to code length, convert to ascii decimal */
  uint32_t mod = 1;
  unsigned int i = 0;
  for (i = 0; i < code_len; i++)
    mod *= 10;
  code_numeric %= mod;

  switch (code_len) {
    case 6:
      printf("Code: %06lu\n", code_numeric);
      break;
    case 7:
      printf("Code: %07lu\n", code_numeric);
      break;
    case 8:
      printf("Code: %08lu\n", code_numeric);
      break;
    case 9:
      printf("Code: %09lu\n", code_numeric);
      break;
    case 10:
      printf("Code: %010lu\n", code_numeric);
    break;
  }

  free(secret);
}
