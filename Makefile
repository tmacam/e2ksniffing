all:main

LIBS = -lnids

main: main.c
	$(CC) -ggdb $(LIBS) main.c -o main
