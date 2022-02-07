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
static int mad_fd; /* MAD driver fd */

/* Functions prototypes */
void help();
int dump_memory(uint64_t dump_start_addr, uint32_t dump_size, char * filename);
int fill_memory(uint64_t start_addr, uint32_t size, uint32_t pattern);

void help()
{
	printf("Usage: dufi [options]\n");
	printf("options:\n");
	printf("\tNOTE: start-address and size in hexadecimal\n");

	printf("\t%-15s %-50s %-30s\n", "Options", "Arguments", "Description");
	printf("\t%-15s %-50s %-30s\n", "-f, --fill", "64-bit-start_address 32-bit-size 32-bit-pattern", "Fills size bytes of memory from start_address with pattern");
	printf("\t%-15s %-50s %-30s\n", "-d, --dump", "64-bit-start_address 32-bit-size filename", "Dumps size bytes of memory from start_address and writes it in filename");
	printf("\t%-15s %-50s %-30s\n", "-m, --dma", "32-bit-size", "Allocates size bytes of physical coherent memory (MAD driver required)");
	printf("\t%-15s %-50s %-30s\n", "-t, --memtest", "32-bit-size iterations", "Allocates size bytes of physical coherent memory and runs iterations of a memory test (MAD driver required)");
	printf("\t%-15s %-50s %-30s\n", "-h, --help", "", "Print this menu");
}

/* Dump memory to a file */
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

/* Fill memory with a pattern */
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

/* Free coherent physical memory
	MAD driver is required  */
void mad_mem_free(struct mad_mo * mo)
{
    ioctl(mad_fd, MAD_IOCTL_FREE, mo);
    close(mad_fd);
}

/* Allocate coherent physical memory
	MAD driver is required */	
int mad_mem_alloc(uint32_t block_size, struct mad_mo * mo)
{
	/* Memory won't be unmapped */

	void * p_virtadd = 0;
	int ret = 0;
    

	//struct mad_mo mo;

	mad_fd = open("/dev/"MAD_DEV_FILENAME, O_RDWR | O_SYNC, 0);

    if ( mad_fd < 0 )
    {
        printf("Cannot open device file: %s\n", MAD_DEV_FILENAME);
        return -1;
    }

    /* Test ioctl */
    mo->size = block_size;
    /* Align for page size */
    if ( mo->size % page_size )
    {
        mo->size = (mo->size/page_size) * page_size + page_size;
    }


    ret = ioctl(mad_fd, MAD_IOCTL_MALLOC, (struct mad_mo *) mo); //(struct mad_mo *) &mo

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

    mo->virtaddr = mmap(NULL, mo->size, PROT_READ|PROT_WRITE, MAP_SHARED, mad_fd, mo->phyaddr);

    if ( MAP_FAILED == mo->virtaddr ) 
    {
		printf("mmap failed errno: %d %s\n", errno, strerror(errno));
        ioctl(mad_fd, MAD_IOCTL_FREE, mo);
        close(mad_fd);
        return -1;        
    }

    //printf("USER LAND: Reserved at phyaddr 0x%lx, virtadd 0x%lx, size 0x%lx\n", mo->phyaddr, (uint32_t *)(mo->virtadd), mo->size);
	return 1;
}

/* Memory write test */
int mem_test(struct mad_mo * mo, uint32_t size)
{
	uint32_t offset = 0;
	uint32_t word = 0;
	uint32_t nwords = size/sizeof(word);

	/* Fill memory */
	for ( offset = 0; offset < nwords; offset++ )
	{
		*( (uint32_t *)mo->virtaddr + offset ) = word;
		word++;
	}

	word = 0;

	/* Check each position */
	for ( offset = 0; offset < nwords; offset++ )
	{
		if ( *( (uint32_t *)mo->virtaddr + offset ) != word )
		{
			return -1; /* Memory check error */
		}
		word++;
	}

	return 1;
}

/* Memory stress test */
int mem_stress_test(uint32_t size, uint32_t iter)
{
	struct mad_mo mo;
	int ret = 0;
	int i = 0;

	/* Allocate physical coherent memory */
	ret = mad_mem_alloc(size, &mo);
	if ( 1 == ret )
	{
		printf("Reserved at phyaddr 0x%x, virtadd 0x%x, size 0x%x\n", mo.phyaddr, (uint32_t *)(mo.virtaddr), mo.size);
	}
	else
	{
		return -2;
	}

	/* Do mem test */
	for ( i; i < iter; i++ )
	{
		ret = mem_test(&mo, size);
		fprintf(stderr, "."); /* Print immediatly */
		if ( ret < 0 )
		{
			mad_mem_free(&mo);
			return -1;
		}
	}
	
	/* Relase memory */
	mad_mem_free(&mo);
	return 1;
}

int main(int argc, char** argv){
	int opt = 0;
	int ret = 0;

	page_size = sysconf(_SC_PAGESIZE);

	/* Options definition */
	const char    * short_opt = "hd:f:m:s:"; //: to specify a flag that requires an argument
	struct option   long_opt[] =
	{
	  {"help",          no_argument, NULL, 'h'},
	  {"dump",          required_argument, NULL, 'd'},
	  {"fill",          required_argument, NULL, 'f'},
	  {"dma",          required_argument, NULL, 'm'},
	  {"memtest",    required_argument, NULL, 't'},
	  {NULL,            0,           NULL, 0  }
	};

    uint64_t start_addr = 0; /* Start address */
    uint32_t size = 0; /* Size */
	uint32_t pattern = 0; /* Filling pattern */
	uint32_t iter = 0; /* Iterations */
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
			struct mad_mo mo;
			return mad_mem_alloc(size, &mo);
			break;

		case 's': /* Memory stress test */
			size = strtoull(argv[2], NULL, 16);
			iter = strtoull(argv[3], NULL, 10);
			printf("Starting memtest for %d iterations on size 0x%x\n", iter, size);
			ret = mem_stress_test(size, iter);
			if ( ret < 0 )
			{
				printf("Memory test ended with errors.\n");
			}
			else
			{
				printf("Memory test OK\n");
			}
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

	return 1;
}
