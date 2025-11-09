#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
		    
		   //  #include <unistd.h>
const char* TOOL_NAME = "ecdh";

void usage() {
    printf ("\
Usage: %s [OPTION]\n\
", TOOL_NAME);
    
    fputs ("\
Perform an Elliptic-Curve Diffie-Hellman key exchange.\n\
\n\
  -h                       show this help message\n\
", stdout);
    
    return;
}
 
  /*-A, --show-all           equivalent to -vET\n\
  -b, --number-nonblank    number nonempty output lines, overrides -n\n\
  -e                       equivalent to -vE\n\
  -E, --show-ends          display $ at end of each line\n\
  -n, --number             number all output lines\n\
  -s, --squeeze-blank      suppress repeated empty output lines\n\
  */

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        usage();
        exit(0);
    }

    int opt;
    while ((opt = getopt (argc, argv, "h")) != -1)
    {
      switch (opt)
        {
        /*case 'b':
          number = true;
          number_nonblank = true;
          break;

        case 'e':
          show_ends = true;
          show_nonprinting = true;
          break;

        case 'n':
          number = true;
          break;

        case 's':
          squeeze_blank = true;
          break;

        case 't':
          show_tabs = true;
          show_nonprinting = true;
          break;

        case 'u':
          * We provide the -u feature unconditionally.  *
          break;

        case 'v':
          show_nonprinting = true;
          break;

        case 'A':
          show_nonprinting = true;
          show_ends = true;
          show_tabs = true;
          break;

        case 'E':
          show_ends = true;
          break;

        case 'T':
          show_tabs = true;
          break;
*/
        //case_GETOPT_HELP_CHAR;

        //case_GETOPT_VERSION_CHAR (PROGRAM_NAME, AUTHORS);

	case 'h':
        default:
          usage ();
        }
    }
    return 0;
}
