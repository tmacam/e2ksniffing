all:main

LIBS = -lnids -lpcap
#CC=gcc -O3 -march=athlon -Winline 
CC=gcc -ggdb

OBJS=main.o e2k_utils.o  e2k_proto.o e2k_state_machine.o

main: $(OBJS)
	$(CC) $(LIBS) $(OBJS) -o main
	
main.o: main.c main.h e2k_utils.h e2k_state_machine.h

e2k_utils.o: e2k_utils.c e2k_utils.h e2k_defs.h

e2k_proto.o: e2k_proto.c e2k_proto.h e2k_defs.h e2k_utils.h

e2k_state_machine.o: e2k_state_machine.c main.h e2k_defs.h e2k_proto.h

teste: teste.c e2k_defs.h main.h
	$(CC) -ggdb $(LIBS) teste.c -o teste

udp_main : udp_main.c e2k_defs.h main.h e2k_utils.o
	$(CC) $(LIBS) e2k_utils.o e2k_proto.o udp_main.c -o udp_main 
