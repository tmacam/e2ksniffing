all: max_offsets byte_hit_rate

LogParser.o: LogParser.cpp LogParser.h
	g++ -ggdb -c LogParser.cpp -o LogParser.o

ByteHitParser.o: LogParser.h ByteHitParser.cpp ByteHitParser.h
	g++ -ggdb -c ByteHitParser.cpp -o ByteHitParser.o

MaxOffsetParser.o: LogParser.h MaxOffsetParser.cpp MaxOffsetParser.h
max_offsets.o: MaxOffsetParser.h max_offsets.cpp

byte_hit_rate.o: ByteHitParser.h byte_hit_rate.cpp
	g++ -ggdb -c byte_hit_rate.cpp -o byte_hit_rate.o

max_offsets: LogParser.o MaxOffsetParser.o max_offsets.o
	g++ -ggdb LogParser.o MaxOffsetParser.o max_offsets.o -o max_offsets

byte_hit_rate: LogParser.o ByteHitParser.o byte_hit_rate.o
	g++ -ggdb LogParser.o ByteHitParser.o byte_hit_rate.o -o byte_hit_rate

.PHONY: clean

clean:
	-rm -fv *.o max_offsets byte_hit_rate
