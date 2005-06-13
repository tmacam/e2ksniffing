#
# Author: Tiago Alves Macambira
# Version: $Id: Makefile,v 1.14 2005-06-13 20:52:37 tmacam Exp $
#
# See COPYING for license details


FRAGMENTED_WRITER_DIR = ./FragmentSaver/

# E2KSNIFFER_JUST_LOG e P4P_SIGNATURE_SHORT_CIRCUIT
#SNIFF_LEVEL= -DP4P_SIGNATURE_SHORT_CIRCUIT=8388608l
#SNIFF_LEVEL= -DE2KSNIFFER_JUST_LOG
SNIFF_LEVEL=
export SNIFF_LEVEL

#OPTIMIZE= -ggdb -g3 -D_GLIBCXX_CONCEPT_CHECKS
#OPTIMIZE= -O3 -march=pentium4 -Winline
#OPTIMIZE= -O3 -march=athlon -Winline 
OPTIMIZE=  -O3
export OPTIMIZE

LIBS = -lnids -lstdc++ -lz
INCLUDE_DIR = -IFragmentSaver/
CFLAGS= $(INCLUDE_DIR) $(OPTIMIZE) $(SNIFF_LEVEL)
#CFLAGS= -ggdb $(INCLUDE_DIR) -DP4P_SIGNATURE_SHORT_CIRCUIT=8388608l
#CFLAGS= -O3 -march=pentium4 -Winline $(INCLUDE_DIR) -DE2KSNIFFER_JUST_LOG
#CFLAGS= -ggdb $(INCLUDE_DIR) -DE2KSNIFFER_JUST_LOG
#CC=gcc -O3 -march=athlon -Winline 
CC=gcc $(CFLAGS)


all:main

OBJS=main.o e2k_utils.o  e2k_proto.o e2k_state_machine.o writers_pool_bundle.o e2k_zip.o

main: $(OBJS)
	$(CC) $(LIBS) $(OBJS) -o main
	
main.o: main.c main.h e2k_utils.h e2k_state_machine.h

e2k_utils.o: e2k_utils.c e2k_utils.h e2k_defs.h

e2k_proto.o: e2k_proto.c e2k_proto.h e2k_defs.h e2k_utils.h

e2k_state_machine.o: e2k_state_machine.c main.h e2k_defs.h e2k_proto.h

writers_pool_bundle.o:
	(cd $(FRAGMENTED_WRITER_DIR) && $(MAKE) writers_pool_bundle.o) && cp -fv $(FRAGMENTED_WRITER_DIR)/writers_pool_bundle.o .

teste: teste.c e2k_defs.h main.h
	$(CC) -ggdb $(LIBS) teste.c -o teste

udp_main : udp_main.c e2k_defs.h main.h e2k_utils.o
	$(CC) $(LIBS) e2k_utils.o e2k_proto.o udp_main.c -o udp_main 

udp_kad_main: udp_kad_main.c e2k_defs.h main.h e2k_utils.o 
	$(CC) $(LIBS) e2k_utils.o udp_kad_main.c -o udp_kad_main 
	
.PHONY: clean

clean:
	-rm -rf *.o main udp_main
	cd $(FRAGMENTED_WRITER_DIR) && $(MAKE) clean
	
