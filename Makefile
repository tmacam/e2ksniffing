all:main

LIBS = -lnids

main: main.c e2k_defs.h main.h
	$(CC) -ggdb $(LIBS) main.c -o main

teste: teste.c e2k_defs.h main.h
	$(CC) -ggdb $(LIBS) teste.c -o teste
