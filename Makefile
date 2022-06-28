makefile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
proj_dir := $(dir $(makefile_path))

CC = gcc
CFLAGS = -g3 -Wall -Wextra -pthread -lrt \
		-lsystemd -lconfig -lm -I$(proj_dir)/liboping/src/
OPING_LIB = $(proj_dir)/liboping/build/opt/oping/lib/

all: srd

srd: util.o srd.o $(OPING_LIB)/liboping.a Makefile
	$(CC) $(CFLAGS) -o srd util.o srd.o $(OPING_LIB)/liboping.a

%.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

$(OPING_LIB)/liboping.a:
	cd liboping && ./autogen.sh
	cd liboping && ./configure --without-perl-bindings --without-ncurses
	sed '/-Wall -Werror/d' -i liboping/src/Makefile.*
	cd liboping && make DESTDIR=$(proj_dir)/liboping/build install
	

clean:
	rm -f *.o srd

.PHONY: all
.PHONY: clean
