makefile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
proj_dir := $(dir $(makefile_path))

CC = gcc
CFLAGS = -O3 -Wall -Wextra -pthread -lrt \
		-lsystemd \
		-lconfig \
		-lm \
		-D_GNU_SOURCE \
		# -DDEBUG \

all: srd

srd: util.o srd.o actions.o printing.o Makefile
	$(CC) $(CFLAGS) -o srd util.o srd.o actions.o printing.o

%.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@
	

clean:
	rm -f *.o srd


.PHONY: all
.PHONY: clean
.PHONY: srd
