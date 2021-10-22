CC = tigcc
CFLAGS = -Iinc/pedrom -v

all: bin/totp.9xz

bin/totp.9xz: totp.c
	$(CC) $(CFLAGS) totp.c -o bin/totp.9xz

clean:
	rm -f bin/totp.9xz
