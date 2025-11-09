CC=gcc
CFLAGS=-Wall -g
LIBS=-lssl -lcrypto

all: server client rclient

up:
	@docker compose up -d
.PHONY: up

shell:
	@docker compose exec local bash
.PHONY: shell

# Runs inside dev container
ecdh:
	gcc ecdh.c ecdh

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(LIBS)

client: client.c
	$(CC) $(CFLAGS) -o client client.c $(LIBS)

rclient: rclient.c
	$(CC) $(CFLAGS) -o rclient rclient.c $(LIBS)

clean:
	rm -f server client rclient *.o
