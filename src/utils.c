/* Miscellaneous utilities:
	smalloc()
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "defs.h"

#include <strings.h> 
#include <stdlib.h>


#include "arpsend.h"
#include "utils.h"



/* smalloc()  --  safe malloc()
 Always returns a valid pointer (if it returns at all).  The allocated
 memory is initialized to all zeros if 'init' is non-zero.  
 If malloc() returns an error, a
 message is printed and the program aborts with a status of 1.
 */

void *
smalloc(size_t size, int init)
{

	void *rc;

	rc = malloc(size);
	if (!rc) {
		fprintf(stderr, "malloc() failed -- exiting\n");
		cleanup();
		exit(1);
	}

	if (init)
		bzero((char *) rc, size);

	return rc;
}

