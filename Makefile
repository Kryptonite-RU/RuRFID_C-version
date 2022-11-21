# Это комментарий, который говорит, что переменная CC указывает компилятор, используемый для сборки
CC=gcc
#Это еще один комментарий. Он поясняет, что в переменной CFLAGS лежат флаги, которые передаются компилятору
CFLAGS=-c -Wall

all: rfid

rfid: rfid.o magma.o interacting.o Kuznyechik.o
	$(CC) $^ -o rfid

rfid.o: rfid.c
	$(CC) $(CFLAGS) $^

magma.o: magma.c
	$(CC) $(CFLAGS) $^

interacting.o: interacting.c
	$(CC) $(CFLAGS) $^

Kuznyechik.o: Kuznyechik.c
	$(CC) $(CFLAGS) $^


clean:
	rm -rf *.o rfid