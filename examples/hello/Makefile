#
# Copyright (c) 2013 No Face Press, LLC
# License http://opensource.org/licenses/mit-license.php MIT License
#

#This makefile is used to test the other Makefiles


PROG = hello
SRC = hello.c

TOP = ../..
HTTP_LIB = libhttp.a

CFLAGS = -I$(TOP)/include $(COPT)
LIBS = -lpthread

include $(TOP)/resources/Makefile.in-os

ifeq ($(TARGET_OS),LINUX)
	LIBS += -ldl
endif

all: $(PROG)

$(PROG): $(HTTP_LIB) $(SRC)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $(SRC) $(HTTP_LIB) $(LIBS)

$(HTTP_LIB):
	$(MAKE) -C $(TOP)
	cp $(TOP)/lib/$(HTTP_LIB) .

clean:
	rm -f $(HTTP_LIB) $(PROG)

.PHONY: all clean
