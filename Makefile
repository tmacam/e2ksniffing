all:main

LIBS = -lnids
#CC=gcc 
#-O3 -march=athlon -Winline

main: main.c e2k_defs.h main.h
	$(CC) -ggdb $(LIBS) main.c -o main

teste: teste.c e2k_defs.h main.h
	$(CC) -ggdb $(LIBS) teste.c -o teste
