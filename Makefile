CC=gcc
CFLAGS=-Wall -g
LIBS=-lsodium

up:
	@docker compose up -d
.PHONY: up

down:
	@docker compose stop
.PHONY: down

shell:
	@docker compose exec local bash
.PHONY: shell

# Runs inside dev container
ecdh:
	$(CC) $(CFLAGS) ecdh.c -o ecdh $(LIBS)

clean:
	rm -f *.o output 
