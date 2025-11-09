#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>

const char* TOOL_NAME = "ecdh";

void usage() {
    printf ("\
Usage: %s [OPTION]...\n\
", TOOL_NAME);
    
    fputs ("\
Perform an Elliptic-Curve Diffie-Hellman key exchange.\n\
\n\
  -o [filename]            path to output file (default: prints to stdout)\n\
  -a [integer]             alice's private key\n\
  -b [integer]             bob's private key\n\
  -c [string]              context string for key derivation\n\
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
    char *buf;
    char *path;
    FILE *fd = stdout;
    uint32_t alice_pk_int, bob_pk_int; // TODO: set defaults
    unsigned char alice_pk_bytes[crypto_scalarmult_BYTES], bob_pk_bytes[crypto_scalarmult_BYTES];
    char *context = "ECDH_KDF";
    while ((opt = getopt (argc, argv, "ho:a:b:c:")) != -1)
    {
      switch (opt)
        {
	case 'o':
	  path = optarg;
	  break;

	case 'a':
	  buf = optarg;
	  // keys are nonnegative decimal integers
	  sscanf(buf, "%u", &alice_pk_int);
	  // unless 0x prefixed
	  if (buf[0]=='0' && buf[1]=='x') {
	      sscanf(buf, "%x", &alice_pk_int);
	  }
          memcpy(alice_pk_bytes, &alice_pk_int, 4);
	  break;

	case 'b':
	  buf = optarg;
	  // keys are nonnegative decimal integers
	  sscanf(buf, "%u", &bob_pk_int);
	  // unless 0x prefixed
	  if (buf[0]=='0' && buf[1]=='x') {
	      sscanf(buf, "%x", &bob_pk_int);
	  }
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

    if (path != NULL) {
    	FILE *fd_try = fopen(path, "w");
	if (fd_try != NULL) {
	    fd = fd_try;
	}

	if (fd != fd_try) {
	    fputs("Warning: Failed to process path specified by -o. Continuing with stdout...", stderr);
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

    fprintf(fd, "Alice's Public Key:\n\n%s\n\n", alice_pub_hex);
    fprintf(fd, "Bob's Public Key:\n\n%s\n\n", bob_pub_hex);

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
    if (res == NULL) {
	fputs("Error: Failed to convert Bob's shared secret from binary to hex.\n", stderr);
        exit(1);
    }

    fprintf(fd, "Shared Secret (Alice):\n\n%s\n\n", alice_shared_secret_hex);
    fprintf(fd, "Shared Secret (Bob):\n\n%s\n\n", bob_shared_secret_hex);

    bool is_match = memcmp(alice_shared_secret, bob_shared_secret, sizeof(alice_shared_secret)) == 0;
    fprintf(fd, "Shared secrets %smatch!\n\n", is_match? "": "do not ");

    // compute symmetric key
    const int SIZE_ENCRYPTION_KEY = 32,
	  SIZE_MAC_KEY = 32;
    unsigned char alice_enc_key[SIZE_ENCRYPTION_KEY], bob_enc_key[SIZE_ENCRYPTION_KEY];
    char alice_enc_key_hex[SIZE_ENCRYPTION_KEY*2+1], bob_enc_key_hex[SIZE_ENCRYPTION_KEY*2+1];

    if (crypto_kdf_derive_from_key(alice_enc_key, SIZE_ENCRYPTION_KEY, 0, context, alice_shared_secret) != 0) {
	fputs("Error: Failed to generate Alice's encryption key.\n", stderr);
        exit(1);
    }
    if (crypto_kdf_derive_from_key(bob_enc_key, SIZE_ENCRYPTION_KEY, 0, context, bob_shared_secret) != 0) {
	fputs("Error: Failed to generate Bob's encryption key.\n", stderr);
        exit(1);
    }

    // convert to hex
    res = NULL;
    res = sodium_bin2hex(alice_enc_key_hex, SIZE_ENCRYPTION_KEY*2+1, alice_enc_key, SIZE_ENCRYPTION_KEY);
    if (res == NULL) {
	fputs("Error: Failed to convert Alice's shared encryption key from binary to hex.\n", stderr);
        exit(1);
    }

    res = NULL;
    res = sodium_bin2hex(bob_enc_key_hex, SIZE_ENCRYPTION_KEY*2+1, bob_enc_key, SIZE_ENCRYPTION_KEY);
    if (res == NULL) {
	fputs("Error: Failed to convert Bob's shared encryption key from binary to hex.\n", stderr);
        exit(1);
    }

    fprintf(fd, "Derived Encryption Key (Alice):\n\n%s\n\n", alice_enc_key_hex);
    fprintf(fd, "Derived Encryption Key (Bob):\n\n%s\n\n", bob_enc_key_hex);

    is_match = memcmp(alice_enc_key, bob_enc_key, sizeof(SIZE_ENCRYPTION_KEY)) == 0;
    fprintf(fd, "Encryption keys %smatch!\n\n", is_match? "": "do not ");

    // compute mac key
    unsigned char alice_mac_key[SIZE_ENCRYPTION_KEY], bob_mac_key[SIZE_ENCRYPTION_KEY];
    char alice_mac_key_hex[SIZE_ENCRYPTION_KEY*2+1], bob_mac_key_hex[SIZE_ENCRYPTION_KEY*2+1];

    if (crypto_kdf_derive_from_key(alice_mac_key, SIZE_ENCRYPTION_KEY, 1, context, alice_shared_secret) != 0) {
	fputs("Error: Failed to generate Alice's MAC key.\n", stderr);
        exit(1);
    }
    if (crypto_kdf_derive_from_key(bob_mac_key, SIZE_ENCRYPTION_KEY, 1, context, bob_shared_secret) != 0) {
	fputs("Error: Failed to generate Bob's MAC key.\n", stderr);
        exit(1);
    }

    // convert to hex
    res = NULL;
    res = sodium_bin2hex(alice_mac_key_hex, SIZE_MAC_KEY*2+1, alice_mac_key, SIZE_MAC_KEY);
    if (res == NULL) {
	fputs("Error: Failed to convert Alice's shared MAC key from binary to hex.\n", stderr);
        exit(1);
    }

    res = NULL;
    res = sodium_bin2hex(bob_mac_key_hex, SIZE_MAC_KEY*2+1, bob_mac_key, SIZE_MAC_KEY);
    if (res == NULL) {
	fputs("Error: Failed to convert Bob's shared MAC key from binary to hex.\n", stderr);
        exit(1);
    }

    fprintf(fd, "Derived MAC Key (Alice)::\n\n%s\n\n", alice_mac_key_hex);
    fprintf(fd, "Derived MAC Key (Bob):\n\n%s\n\n", bob_mac_key_hex);

    is_match = memcmp(alice_mac_key, bob_mac_key, sizeof(SIZE_MAC_KEY)) == 0;
    fprintf(fd, "MAC keys %smatch!\n\n", is_match? "": "do not ");

    return 0;
}
