#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>

const char* TOOL_NAME = "ecdh";

void usage() {
    printf ("\
Usage: %s [OPTION]\n\
", TOOL_NAME);
    
    fputs ("\
Perform an Elliptic-Curve Diffie-Hellman key exchange.\n\
\n\
  -o                       path to output file\n\
  -a                       alice's private key\n\
  -b                       bob's private key\n\
  -c                       context string for key derivation\n\
  -h                       show this help message\n\
", stdout);

    return;
}
 
int main(int argc, char *argv[])
{
    if (sodium_init() == -1)
    {
	fputs("Error: Failed to initalize sodium.\n", stderr);
        exit(1);
    }

    if (argc < 3)
    {
        usage();
        exit(0);
    }

    int opt;
    char *output_path; // TODO: set default
    uint32_t alice_pk_int, bob_pk_int; // TODO: set defaults
    unsigned char alice_pk_bytes[crypto_scalarmult_BYTES], bob_pk_bytes[crypto_scalarmult_BYTES];
    char *context; // TODO: set defaults
    while ((opt = getopt (argc, argv, "ho:a:b:c:")) != -1)
    {
      switch (opt)
        {
	case 'o':
	  output_path = optarg;
	  break;

	case 'a':
	  sscanf(optarg, "%u", &alice_pk_int);
          memcpy(alice_pk_bytes, &alice_pk_int, 4);
	  break;

	case 'b':
	  sscanf(optarg, "%u", &bob_pk_int);
          memcpy(bob_pk_bytes, &bob_pk_int, 4);
	  break;

	case 'c':
	  context = optarg;
	  break;

	case 'h':
        default:
          usage ();
        }
    }

    unsigned char alice_pub[crypto_scalarmult_BYTES];
    unsigned char bob_pub[crypto_scalarmult_BYTES];
    char alice_pub_hex[crypto_scalarmult_BYTES*64];
    char bob_pub_hex[crypto_scalarmult_BYTES*64];
    // scalar * base point on Curve25519 = point on Curve25519
    if (crypto_scalarmult_base(alice_pub, alice_pk_bytes) != 0) {
	fputs("Error: Failed to generate Alice's public key.\n", stderr);
        exit(1);
    }
    if (crypto_scalarmult_base(bob_pub, bob_pk_bytes) != 0) {
	fputs("Error: Failed to generate Bob's public key.\n", stderr);
        exit(1);
    }

    // convert to hex
    char *res = sodium_bin2hex(alice_pub_hex, crypto_scalarmult_BYTES*64, alice_pub, crypto_scalarmult_BYTES);
    if (res == NULL) {
	fputs("Error: Failed to convert Alice's public key from binary to hex.\n", stderr);
        exit(1);
    }
    res = NULL;
    res = sodium_bin2hex(bob_pub_hex, crypto_scalarmult_BYTES*64, bob_pub, crypto_scalarmult_BYTES);
    if (res == NULL) {
	fputs("Error: Failed to convert Bob's public key from binary to hex.\n", stderr);
        exit(1);
    }

  /*
    printf("Bob pk: %s\n", bob_pk_bytes);
    printf("Bob pub: %s\n", bob_pub);
    printf("alice pub hex addr: %p\n", alice_pub_hex);
    printf("alice pub hex length: %lu\n", sizeof(alice_pub_hex));
    printf("alice pub hex end addr: %p\n", alice_pub_hex+sizeof(alice_pub_hex));
    printf("bob pub hex addr: %p\n", bob_pub_hex);
    printf("bob pub hex length: %lu\n", sizeof(bob_pub_hex));
    printf("bob pub hex end addr: %p\n", bob_pub_hex+sizeof(bob_pub_hex));
    printf("Bob pub: %s\n", bob_pub);

    printf("Alice priv: %s\n", alice_pub);
    printf("Alice pub: %s\n", alice_pub_hex);
    printf("Bob priv: %s\n", bob_pub);
    printf("Bob pub: %s\n", bob_pub_hex);
  */ 

    // compute shared keys
    unsigned char alice_shared_secret[crypto_scalarmult_BYTES], bob_shared_secret[crypto_scalarmult_BYTES];
    char alice_shared_secret_hex[crypto_scalarmult_BYTES*64], bob_shared_secret_hex[crypto_scalarmult_BYTES*64];

    // scalar * point on Curve25519 = point on Curve25519
    if (crypto_scalarmult(alice_shared_secret, alice_pk_bytes, bob_pub) != 0) {
	fputs("Error: Failed to generate Alice's shared secret.\n", stderr);
        exit(1);
    }
    if (crypto_scalarmult(bob_shared_secret, bob_pk_bytes, alice_pub) != 0) {
	fputs("Error: Failed to generate Bob's shared secret.\n", stderr);
        exit(1);
    }

    // convert to hex
    res = NULL;
    res = sodium_bin2hex(alice_shared_secret_hex, crypto_scalarmult_BYTES*64, alice_shared_secret, crypto_scalarmult_BYTES);
    if (res == NULL) {
	fputs("Error: Failed to convert Alice's shared secret from binary to hex.\n", stderr);
        exit(1);
    }

    res = NULL;
    res = sodium_bin2hex(bob_shared_secret_hex, crypto_scalarmult_BYTES*64, bob_shared_secret, crypto_scalarmult_BYTES);
//return 0;
    if (res == NULL) {
	fputs("Error: Failed to convert Bob's shared secret from binary to hex.\n", stderr);
        exit(1);
    }

  /*
    printf("Alice shared secret: %s\n", alice_shared_secret);
    printf("Alice shared secret: %s\n", alice_shared_secret_hex);
    printf("Bob shared secret: %s\n", bob_shared_secret);
    printf("Bob shared secret: %s\n", bob_shared_secret_hex);
    printf("Are they equal? %b\n", memcmp(alice_shared_secret, bob_shared_secret, sizeof(alice_shared_secret)) == 0);
  */

    // compute symmetric key
    unsigned char alice_enc_key[crypto_scalarmult_BYTES], bob_enc_key[crypto_scalarmult_BYTES];
    char alice_enc_key_hex[crypto_scalarmult_BYTES*64], bob_enc_key_hex[crypto_scalarmult_BYTES*64];
    const int SIZE_ENCRYPTION_KEY = 32,
	  SIZE_MAC_KEY = 32;

    if (crypto_kdf_derive_from_key(alice_enc_key, SIZE_ENCRYPTION_KEY, 0, "ECDH_KDF", alice_shared_secret) != 0) {
	fputs("Error: Failed to generate Alice's encryption key.\n", stderr);
        exit(1);
    }
    if (crypto_kdf_derive_from_key(bob_enc_key, SIZE_ENCRYPTION_KEY, 0, "ECDH_KDF", bob_shared_secret) != 0) {
	fputs("Error: Failed to generate Bob's encryption key.\n", stderr);
        exit(1);
    }

    // convert to hex
    res = NULL;
    res = sodium_bin2hex(alice_enc_key_hex, SIZE_ENCRYPTION_KEY*2+1, alice_enc_key, crypto_scalarmult_BYTES);
    if (res == NULL) {
	fputs("Error: Failed to convert Alice's shared encryption key from binary to hex.\n", stderr);
        exit(1);
    }

    res = NULL;
    res = sodium_bin2hex(bob_enc_key_hex, SIZE_ENCRYPTION_KEY*2+1, bob_enc_key, crypto_scalarmult_BYTES);
    if (res == NULL) {
	fputs("Error: Failed to convert Bob's shared encryption key from binary to hex.\n", stderr);
        exit(1);
    }
/*
    printf("Alice encryption key: %s\n", alice_enc_key);
    printf("Alice encryption key: %s\n", alice_enc_key_hex);
    printf("Bob encryption key: %s\n", bob_enc_key);
    printf("Bob encryption key: %s\n", bob_enc_key_hex);
    printf("Are they equal? %b\n", memcmp(alice_enc_key, bob_enc_key, SIZE_ENCRYPTION_KEY) == 0);
*/

    return 0;
}
