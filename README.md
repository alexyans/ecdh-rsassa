# Elliptic Curve Diffie-Hellman key exchange tool

## Installation

```
$ apt update && apt install gcc libtool libsodium-dev
```

## Usage
```
$ make && ./ecdh -h
```

## Development
I work on a Mac. For portability, a dockerized Ubuntu development environment is provided.
```
$ make up
$ make shell
# the shell opens in /, remember to cd to /app. The worspace directory is mounted as a volume
# to synchronize the files back to the host 
```
