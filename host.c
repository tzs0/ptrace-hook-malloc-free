#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <regex.h>
#include <setjmp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <elf.h>
#include <sys/mman.h>
#include <link.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "hook.h"


#define my_printf(fmt, ...) 		printf("[%s %d] "fmt, __func__, __LINE__, ##__VA_ARGS__)

const char* libc_path = "/lib/i386-linux-gnu/libc-2.23.so";
const char* linker_path = "/lib/i386-linux-gnu/libdl-2.23.so";
const char* libc_name = "libc-2.23.so";
const char* libdl_name = "libdl-2.23.so";

//const char *libc_path = "/usr/libx32/libc.so.6";
//const char *linker_path = "/usr/libx32/ld-linux-x32.so.2";
//const char *libc_name = "libc.so.6";


int main(int argc, char * * argv)
{
	my_printf("\nhost pid:%d\n", getpid());

	my_printf("\nhost mmap(plt):%p\n", mmap);
	void* ret_addr = hk_show_sym_info(-1, "mmap", libc_name);
	my_printf("host mmap real addr from libc:%p\n", ret_addr);

	my_printf("host dlopen(plt):%p\n", dlopen);
	ret_addr = hk_show_sym_info(-1, "dlopen", libdl_name);
	my_printf("host dlopen real addr from libdl:%p\n", ret_addr);

	my_printf("host dlsym(plt):%p\n", dlsym);
	ret_addr = hk_show_sym_info(-1, "dlsym", libdl_name);
	my_printf("host dlsym real addr from libdl:%p\n", ret_addr);

	my_printf("host dlclose(plt):%p\n", dlclose);
	ret_addr = hk_show_sym_info(-1, "dlclose", libdl_name);
	my_printf("host dlclose real addr from libdl:%p\n", ret_addr);

	my_printf("host dlerror(plt):%p\n", dlerror);
	ret_addr = hk_show_sym_info(-1, "dlerror", libdl_name);
	my_printf("host dlerror real addr from libdl:%p\n", ret_addr);

	while(1) {
		sleep(3);
        my_printf("i am host, i will malloc 1024\n");
		void* p = malloc(1024);
		sleep(1);
		if(p) {
            my_printf("i am host, i will free %p\n", p);
			free(p);
		}
	}
	my_printf("exit\n");

	return 0;
}

