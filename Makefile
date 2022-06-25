CC = gcc
CFLAGS = -O3 -Wall -Wextra -pthread -lrt -lsystemd -lconfig -lm


all: srd

srd: util.o srd.o Makefile
	$(CC) $(CFLAGS) util.o srd.o -o srd

%.o : %.c Makefile
		$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f *.o srd

.PHONY: all
.PHONY: clean
