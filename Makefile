src = $(wildcard *.c)
targets = $(patsubst %.c,%,$(src))

CC = gcc
CFLAGS = -Wall -g -lpthread -fno-stack-protector -O0

all:$(targets)

$(targets):%:%.c
	$(CC) $< -o $@ $(CFLAGS)
.PHONY:clear all
clean:
	rm -rf $(targets)
