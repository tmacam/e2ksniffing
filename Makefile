all:main

LIBS = -lnids

main: main.c e2k_defs.h
	$(CC) -ggdb $(LIBS) main.c -o main
