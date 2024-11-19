CC ?= $(CROSS_COMPILE)gcc
CFLAGS += -Wall -Wextra -g

all: aesdsocket

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket

.PHONY: clean
clean:
	rm -f aesdsocket
