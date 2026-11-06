/* Minimal stand-in for the PikeOS SDK vm.h, with the SDK's signatures. It lets
 * the transport build and run on a host; it is not used on a PikeOS target. */
#ifndef PIKEOS_STUB_VM_H
#define PIKEOS_STUB_VM_H
#include <p4.h>
typedef struct { unsigned int gdh; } vm_file_desc_t;
#define VM_O_RD_WR 3
P4_e_t vm_open(const char *name, unsigned int oflags, vm_file_desc_t *fd);
P4_e_t vm_read(vm_file_desc_t *fd, void *buff, P4_size_t buff_size,
    P4_size_t *read_size);
P4_e_t vm_write(vm_file_desc_t *fd, const void *buff, P4_size_t buff_size,
    P4_size_t *written_size);
P4_e_t vm_close(vm_file_desc_t *fd);
#endif
