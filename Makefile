CC=g++ -I . -Wall -Wextra -std=c++11

all: filesys.x

filesys.x: main.cpp filesys.o
	$(CC) -o filesys.x main.cpp filesys.o

filesys.o : filesys.h filesys.cpp
	$(CC) -o filesys.o -c filesys.cpp	
