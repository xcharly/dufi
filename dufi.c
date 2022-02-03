/* MIT License
*
* Copyright (c) 2020 xcharly.github.com
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include <getopt.h>

#include <errno.h>

#include "mad_ioctl.h"


/* Global variables */
static uint32_t page_size; /* Page size */

/* Functions prototypes */
void help();
int dump_memory(uint64_t dump_start_addr, uint32_t dump_size, char * filename);
int fill_memory(uint64_t start_addr, uint32_t size, uint32_t pattern);

void help()
{
	printf("Usage: dufi [64-bit start_address] [32-bit size] [-f 32-bit pattern] [-d file.bin]\n");
	printf("\tstart-address and size in hexadecimal\n");
	printf("\t-f fills [size] bytes of memory from [start_address] using [pattern]\n");
	printf("\t-d dumps [size] bytes of memory from [start_address] and write it to a file\n");
}

int dump_memory(uint64_t dump_start_addr, uint32_t dump_size, char * filename)
{

    int mem_fd = 0;
    uint32_t *ptr = NULL;
    uint32_t page_num = 0;
    FILE *fout = NULL;
    int i = 0;
    uint32_t buffer = 0;

	mem_fd = open("/dev/mem", O_RDWR|O_SYNC);

	if ( mem_fd < 0 )
	{
		printf("Error opening /dev/mem\n");
		return 0;
	}

	page_num = (uint32_t)( (size_t)(dump_size)/page_size ) + 1 ;


	ptr = (uint32_t *)mmap(NULL,  page_num*page_size, PROT_READ|PROT_WRITE, MAP_SHARED, mem_fd, dump_start_addr);

	if ( ptr == MAP_FAILED )
	{
		printf("Could not map the memory\n");
		return 0;
	}

	fout = fopen(filename, "wb+");
	if ( fout == NULL )
	{
		printf("Cannot write file\n ");
		return 0;
	}



	for (i = 0; i < (page_num*page_size)/sizeof(uint32_t); i++)
	{
		buffer = *(ptr + i);
		fwrite(&buffer, sizeof(uint32_t), 1, fout);

	}



	fclose(fout);

	munmap(ptr, page_size);

	return 1;
}

int fill_memory(uint64_t start_addr, uint32_t size, uint32_t pattern)
{

    int mem_fd = 0;
    uint32_t *ptr = NULL;
    int page_num = 0;
    int i = 0;

	mem_fd = open("/dev/mem", O_RDWR|O_SYNC);

	if ( mem_fd < 0 )
	{
		printf("Error opening /dev/mem\n");
		return 0;
	}

	page_num = (size_t)(size)/page_size + 1;


	ptr = (uint32_t *)mmap(NULL,  page_num*page_size, PROT_READ|PROT_WRITE, MAP_SHARED, mem_fd, start_addr);

	if ( ptr == MAP_FAILED )
	{
		printf("Could not map the memory\n");
		return 0;
	}

	for (i = 0; i < (page_num*page_size)/sizeof(uint32_t); i++)
	{
		*(ptr + i) = pattern;
	}

	munmap(ptr, page_size);

	return 1;
}

int drv_mem_alloc(long int block_size)
{
	/* Memory won't be unmapped */

	void * p_virtadd = 0;
	int ret = 0;
    int fd = 0;

	struct mad_mo mo;

	fd = open("/dev/"MAD_DEV_FILENAME, O_RDWR | O_SYNC, 0);
	printf("%d\n", fd);


    if ( fd < 0 )
    {
        printf("Cannot open device file: %s\n", MAD_DEV_FILENAME);
        return -1;
    }

    /* Test ioctl */
    mo.size = block_size;
    /* Align for page size */
    if ( mo.size % page_size )
    {
        mo.size = (mo.size/page_size) * page_size + page_size;
    }


    ret = ioctl(fd, MAD_IOCTL_MALLOC, (struct mad_mo *) &mo);

    if ( ret < 0 )
    {
        printf("ioctl MAD_IOCTL_MALLOC failed: %d\n", ret);
        return -1;
    }

    //p_virtadd = (uint64_t)mo.virtaddr;

    //printf("KERNEL MODE: Reserved at phyaddr 0x%lx, virtadd 0x%lx, size 0x%lx\n", mo.phyaddr, p_virtadd, mo.size);

    /* At this point, we have reserved physical memory accessible by the virtual memory
       pointer p_virtadd but only in kernel mode.
       Memory remapping is required to have this memory accesible in user land.
    */
    //p_virtadd[0] = 0xcafebabe; /* Guaranteed segfault */

    p_virtadd = mmap(NULL, mo.size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, mo.phyaddr);

    if ( MAP_FAILED == p_virtadd ) 
    {
		printf("mmap failed errno: %d %s\n", errno, strerror(errno));
        ioctl(fd, MAD_IOCTL_FREE, &mo);
        close(fd);
        return -1;        
    }
    printf("USER LAND: Reserved at phyaddr 0x%lx, virtadd 0x%lx, size 0x%lx\n", mo.phyaddr, (uint32_t *)p_virtadd, mo.size);

	return 1;
}


int main(int argc, char** argv){
	int opt = 0;

	 page_size = sysconf(_SC_PAGESIZE);

	/* Options definition */
	const char    * short_opt = "hd:f:m:"; //: to specify a flag that requires an argument
	struct option   long_opt[] =
	{
	  {"help",          no_argument, NULL, 'h'},
	  {"dump",          required_argument, NULL, 'd'},
	  {"fill",          required_argument, NULL, 'f'},
	  {"dma",          required_argument, NULL, 'm'},
	  {NULL,            0,           NULL, 0  }
	};

    uint64_t start_addr = 0; /* Start address */
    uint32_t size = 0; /* Size */
	uint32_t pattern = 0; /* Filling pattern */
    char filename[25];


    /* Check arguments */
	if ( argc < 2 )
	{
		help();
		return 0;
	}

	while((opt = getopt_long(argc, argv, short_opt, long_opt, NULL)) != -1)
	{
	  switch(opt)
	  {
		 case -1:       /* no more arguments */
		 case 0:        /* long options toggles */
			break;

		 case 'd': /* Dump memory */
			strncpy(filename, optarg, strlen(optarg) + 1); /* Filename */
			start_addr = strtoull(argv[1], NULL, 16);
		 	size = strtoull(argv[2], NULL, 16);
			printf("Dumping memory from 0x%llx with size 0x%llx\n", start_addr, size);
			return dump_memory(start_addr, size, filename);
			break;

		 case 'f': /* Fill memory */
			start_addr = strtoull(argv[1], NULL, 16);
		 	size = strtoull(argv[2], NULL, 16);
			pattern = strtoul(optarg, NULL, 16);
			printf("Filling memory from 0x%llx with size 0x%llx writing 0x%lx\n", start_addr, size, pattern);
			return fill_memory(start_addr, size, pattern);
		 	break;

		 case 'm': /* DMA allocation */
		 	size = strtoull(argv[2], NULL, 16);
			printf("MAD Driver allocating size 0x%x\n", size);
			return drv_mem_alloc(size);
		 	break;

		 case 'h':
			help();
			return(0);

		 case ':':
		 case '?':
			printf("Try `%s --help' for more information.\n", argv[0]);
			return(-2);

		 default:
			printf("%s: invalid option -- %c\n", argv[0], opt);
			printf("Try `%s --help' for more information.\n", argv[0]);
			return(-2);
	  };
	};


	/* Arguments not parsed by getops */
    /*for(; optind < argc; optind++){
		 start_addr = strtoull(argv[1], NULL, 16);
		 size = strtoull(argv[2], NULL, 16);
    }*/

	return 1;
}
