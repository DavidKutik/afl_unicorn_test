import argparse
import os
import signal
import struct


from unicornafl import *
from unicornafl.x86_const import *

import unicorn_loader

CONTEXT_DIR = "/home/dv/master/unicorn_test/UnicornContext_20200818_182345/"
unicorn_heap = None


# Start and end of emulation
START_ADDR    = 0x555555555519
END_ADDR      = 0x55555555551e

# Function hooks
MALLOC_HOOK   = 0x5555555550c0
MEMCPY_HOOK   = 0x5555555550b0
STRCPY_HOOK   = 0x555555555040
    
def unicorn_hook_instr(uc, address, size, user_data):
    if MALLOC_HOOK == address:
        size = uc.reg_read(UC_X86_REG_RDI)
        ret_val = unicorn_heap.malloc(size)
        uc.reg_write(UC_X86_REG_RAX, ret_val)

        # skip malloc, since it was handled above
        rsp      = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]

        uc.reg_write(UC_X86_REG_RIP, ret_addr)
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)

    elif MEMCPY_HOOK == address:
        
        # void *memcpy(void *dest, const void *src, size_t n);
        # get args
        dest = uc.reg_read(UC_X86_REG_RDI)
        src = uc.reg_read(UC_X86_REG_RSI)
        n = uc.reg_read(UC_X86_REG_RDX)
        print("[HOOK]  memcpy(dest={:016x}, src={:016x}, n={});".format(dest, src, n))

        # copy
        src_content = bytes(uc.mem_read(src, n))
        uc.mem_write(dest, src_content)

        # ret_val = dest
        uc.reg_write(UC_X86_REG_RAX, dest)

        # skip memcpy, since it was handled above
        rsp      = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]

        uc.reg_write(UC_X86_REG_RIP, ret_addr)
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)

    elif STRCPY_HOOK == address:
        # void *memcpy(void *dest, const void *src, size_t n);
        # get args
        dest = uc.reg_read(UC_X86_REG_RDI)
        src = uc.reg_read(UC_X86_REG_RSI)
        print("[HOOK]  strpy(dest=0x{:016x}, src=0x{:016x});".format(dest, src))
        
        # copy until 0
        i = 0
        while True:
            c = bytes(uc.mem_read(src + i, 1))

            uc.mem_write(dest + i, c)
            i += 1
            if c == b'\x00':
                break

        # ret_val = dest
        uc.reg_write(UC_X86_REG_RAX, dest)

        # skip strcpy, since it was handled above
        rsp      = uc.reg_read(UC_X86_REG_RSP)
        ret_addr = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]

        uc.reg_write(UC_X86_REG_RIP, ret_addr)
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', type=str, help="Filepath to mutated corpus files")
    args = parser.parse_args()

    print("Loading Context")
    uc = unicorn_loader.AflUnicornEngine(CONTEXT_DIR, enable_trace=False, debug_print=False)

    
    global unicorn_heap
    unicorn_heap = unicorn_loader.UnicornSimpleHeap(uc, debug_print=False)
    uc.hook_add(UC_HOOK_CODE, unicorn_hook_instr)

    print("Starting the forkserver by executing 1 instruction")
    try:
        uc.emu_start(START_ADDR, 0, 0, count=1)
    except UcError as e:
        print("ERROR: Failed to execute a single instruction (error: {}!".format(e))
        return

    print("Loading input_file into heap")
    if args.input_file:
        f = open(args.input_file, 'rb')
        content = f.read()
        f.close()

        file_content_addr = unicorn_heap.malloc(len(content))
        uc.mem_write(file_content_addr, content)
        uc.reg_write(UC_X86_REG_RDI, file_content_addr)

    # Go
    print("Executing from 0x{0:016x} to 0x{1:016x}".format(START_ADDR, END_ADDR))
    try:
        result = uc.emu_start(START_ADDR, END_ADDR, timeout=0, count=0)
    except UcError as e:
        print("Execution failed with error: {}".format(e))
        uc.dump_regs()
        uc.force_crash(e)

    print("Done")

if __name__ == "__main__":
    main()
