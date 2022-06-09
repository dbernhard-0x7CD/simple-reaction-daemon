CC = gcc
CFLAGS = -O3 -Wall -Wextra -pthread -lrt -lsystemd -lconfig -lm


all: srd

% : %.c
	$(CC) $< $(CFLAGS) -o $@

clean:
	rm -f srd

.PHONY: all
.PHONY: clean
