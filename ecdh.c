#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    if (argc < 3)
    {
        usage();
        exit(0);
    }

    int opt;
    char *output_path; // TODO: set default
    int alice_pk, bob_pk; // TODO: set defaults
    char *context; // TODO: set defaults
    while ((opt = getopt (argc, argv, "ho:a:b:c:")) != -1)
    {
      switch (opt)
        {
	case 'o':
	  output_path = optarg;
	  break;

	case 'a':
	  sscanf(optarg, "%u", &alice_pk);
	  break;

	case 'b':
	  sscanf(optarg, "%u", &bob_pk);
	  break;

	case 'c':
	  context = optarg;
	  break;

	case 'h':
        default:
          usage ();
        }
    }

    return 0;
}
