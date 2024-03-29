CC = gcc
CFLAGS = -O3 --std=c17 -Wall -Wextra -pthread -lrt \
		-lsystemd \
		-lconfig \
		-lm \
		-lanl \
		-D_GNU_SOURCE \
		# -DDEBUG \
		# -fsanitize=address

all: srd

srd: util.o srd.o actions.o printing.o Makefile
	$(CC) $(CFLAGS) -o srd util.o srd.o actions.o printing.o

%.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

valgrind: srd
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --show-reachable=yes --num-callers=50 --trace-children=yes ./srd

# This needs to have include-what-you-use installed
check_includes: util.c
	include-what-you-use -D_GNU_SOURCE util.c
	include-what-you-use -D_GNU_SOURCE srd.c
	include-what-you-use -D_GNU_SOURCE actions.c
	include-what-you-use -D_GNU_SOURCE printing.c
	include-what-you-use -D_GNU_SOURCE perf_metric.h

clean:
	rm -f *.o srd


.PHONY: all
.PHONY: clean
.PHONY: srd
