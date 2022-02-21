C = gcc
CFLAGS = -O3 -Wall -Wextra -pthread -lrt -lsystemd -lconfig -lm


all: srd

% : %.c
	$(C) $< $(CFLAGS) -o $@

clean:
	rm -f *.o *~ $(targets)

.PHONY: all
.PHONY: clean
