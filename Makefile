all:main

LIBS = -lnids -lpcap
CC=gcc -O3 -march=athlon -Winline 
#CC=gcc -ggdb

main: main.c e2k_defs.h main.h
	$(CC) $(LIBS) main.c -o main

teste: teste.c e2k_defs.h main.h
	$(CC) -ggdb $(LIBS) teste.c -o teste
