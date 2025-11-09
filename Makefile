CC=gcc
CFLAGS=-Wall -g
LIBS=-lsodium

# Normally runs inside dev container
ecdh:
	$(CC) $(CFLAGS) ecdh.c -o ecdh $(LIBS)

up:
	@docker compose up -d
.PHONY: up

down:
	@docker compose stop
.PHONY: down

shell:
	@docker compose exec local bash
.PHONY: shell

clean:
	rm -f *.o output 
