#ifndef __HOOK_H__
#define __HOOK_H__

typedef void* (*FUNC_PROXY)(void*);

void* hk_show_sym_info(int pid, const char* sym_name, const char* so_name);
void* hk_get_elfinfo(const char* elf_name);
int hk_hook(void* elf, const char* sym, FUNC_PROXY proxy);


#endif