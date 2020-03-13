#include "config.h"
#include "test_driver.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char **argv)
{
    srand(time(NULL));

	int c;
	opterr = 0;

    // init_config();

	while((c = getopt(argc, argv, "c:s:d:")) != -1) {
		switch(c) {
            case 'c':
                test_client(atoi(optarg));
                break;
            case 's':
                test_sp(atoi(optarg));
                break;
            case 'd':
                test_cloud(atoi(optarg));
                break;
			default:
				printf("Incorrect arguments!\n");
		}
    }
}