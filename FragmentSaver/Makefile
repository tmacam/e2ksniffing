CPPFLAGS = -Wall -ggdb -g3 -I../e2ksniffing_v1 
all: IntervalMap c_tests


IntervalMap : IntervalMap.o main.o FragmentedFileWriter.o WritersPool.o
	g++ IntervalMap.o main.o FragmentedFileWriter.o WritersPool.o -o IntervalMap 

writers_pool_bundle = writers_pool.o IntervalMap.o FragmentedFileWriter.o WritersPool.o
#	g++  writers_pool.o IntervalMap.o FragmentedFileWriter.o WritersPool.o ../e2ksniffing_v1/e2k_utils.o -o writers_pool_bundle.o 

#	g++ $(CPPFLAGS) -c -o writers_pool.o writers_pool.cpp IntervalMap.o FragmentedFileWriter.o WritersPool.o 
#	see http://electron.phys.dal.ca/GCC-HOWTO-6.html

c_tests: c_tests.o $(writers_pool_bundle) 
	gcc -lstdc++ c_tests.o $(writers_pool_bundle) -o c_tests 

.PHONY: clean

clean:
	-rm -f *.o IntervalMap c_tests
