
FRAGMENTED_WRITER_DIR = ./FragmentSaver/

LIBS = -lnids -lpcap -lstdc++
INCLUDE_DIR = -IFragmentSaver/
CFLAGS= -ggdb $(INCLUDE_DIR)
#CC=gcc -O3 -march=athlon -Winline 
CC=gcc $(CFLAGS)


all:main

OBJS=main.o e2k_utils.o  e2k_proto.o e2k_state_machine.o writers_pool_bundle.o

main: $(OBJS)
	$(CC) $(LIBS) $(OBJS) -o main
	
main.o: main.c main.h e2k_utils.h e2k_state_machine.h

e2k_utils.o: e2k_utils.c e2k_utils.h e2k_defs.h

e2k_proto.o: e2k_proto.c e2k_proto.h e2k_defs.h e2k_utils.h

e2k_state_machine.o: e2k_state_machine.c main.h e2k_defs.h e2k_proto.h

writers_pool_bundle.o:
	(cd $(FRAGMENTED_WRITER_DIR) && make writers_pool_bundle.o) && cp -fv $(FRAGMENTED_WRITER_DIR)/writers_pool_bundle.o .

teste: teste.c e2k_defs.h main.h
	$(CC) -ggdb $(LIBS) teste.c -o teste

udp_main : udp_main.c e2k_defs.h main.h e2k_utils.o
	$(CC) $(LIBS) e2k_utils.o e2k_proto.o udp_main.c -o udp_main 

.PHONY: clean

clean:
	-rm -rf *.o main udp_main
