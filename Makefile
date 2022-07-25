makefile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
proj_dir := $(dir $(makefile_path))
oping_lib = $(proj_dir)/liboping/build/opt/oping/lib/

CC = gcc
CFLAGS = -O3 -Wall -Wextra -pthread -lrt \
		-lsystemd -lconfig -lm -I$(proj_dir)/liboping/src/

all: srd

srd: util.o srd.o actions.o printing.o $(oping_lib)/liboping.a Makefile
	$(CC) $(CFLAGS) -o srd util.o srd.o actions.o printing.o $(oping_lib)/liboping.a

%.o : %.c Makefile
	$(CC) -c $(CFLAGS) $< -o $@

$(oping_lib)/liboping.a:
	cd liboping && ./autogen.sh
	cd liboping && ./configure --without-perl-bindings --without-ncurses
	sed '/-Wall -Werror/d' -i liboping/src/Makefile.*
	cd liboping && make DESTDIR=$(proj_dir)/liboping/build install
	

clean:
	rm -f *.o srd

completeclean: clean
	rm -rf liboping && git submodule update


.PHONY: all
.PHONY: clean
