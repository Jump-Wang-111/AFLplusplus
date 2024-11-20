import rstr
import ctypes
import mmap
import os
import sys
from ctypes import *
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED

class RegexEnv(ctypes.Structure):
    _fields_ = [
        ("all_regex_map", c_uint8 * (1 << 12)),
        ("all_regex_val", (c_char * (1 << 8)) * (1 << 12)),
        ("env_name", c_char * 128),
        ("path_info_map", c_uint8 * (1 << 12)),
        ("num_of_regex", c_int),
        ("path_info_str", (c_char * (1 << 8)) * (1 << 12)),
        ("path_info_r", (c_char * (1 << 8)) * (1 << 12)),
    ]


libc = ctypes.CDLL("libc.so.6")

shmat = libc.shmat
shmat.argtypes = [c_int, POINTER(c_void_p), c_int]
shmat.restype = c_void_p

shmdt = libc.shmdt
shmdt.argtypes = [POINTER(c_void_p)]
shmdt.restype = c_int


def get_shared_memory(shm_id):
    shm_addr = shmat(shm_id, None, 0)
    if shm_addr == -1:
        errno = ctypes.get_errno()
        raise OSError(f"shmat failed with shm_id: {shm_id}, errorno: {errno}")
    
    return shm_addr


def detach_shared_memory(shm_addr):
    shm_addr = ctypes.cast(shm_addr, ctypes.POINTER(c_void_p))
    if libc.shmdt(shm_addr) == -1:
        raise OSError("shmdt failed.")


def copy_str(dest, src):
    for i, b in enumerate(src.encode()):
        dest[i] = b
    dest[len(src)] = 0


def gen_regex(str:str):
    s = str.replace('[[:alnum:]]', '[0-9A-Za-z]') \
                    .replace('[[:alpha:]]', '[A-Za-z]') \
                    .replace('[[:ascii:]]', '[\x00-\x7F]') \
                    .replace('[[:blank:]]', '[\t ]') \
                    .replace('[[:cntrl:]]', '[\x00-\x1F\x7F]') \
                    .replace('[[:digit:]]', '[0-9]') \
                    .replace('[[:lower:]]', '[a-z]') \
                    .replace('[[:upper:]]', '[A-Z]') \
                    .replace('[[:space:]]', '[\t\n\v\f\r ]') \
                    .replace('[[:xdigit:]]', '[0-9A-Fa-f]')
    return rstr.xeger(s)


def task_gen(old_array):
    new_str = gen_regex(old_array.value.decode())
    copy_str(old_array, new_str)


def muti_gen_regex(regex_env):
    tasks = []
    pool = ThreadPoolExecutor(max_workers=16)
    try:
        for i in range(regex_env.num_of_regex):
            tasks.append(pool.submit(task_gen, regex_env.path_info_r[i]))
    except Exception as e:
        print(e)
    return tasks

def main():

    shared_id = int(os.getenv("__AFL_SHM_CGI_RE_ID"))
    shm_addr = get_shared_memory(shared_id)

    try:
        regex_env = ctypes.cast(shm_addr, ctypes.POINTER(RegexEnv)).contents
        print(f"Shared memory address: {shm_addr:#x}")

        tasks = muti_gen_regex(regex_env)
        wait(tasks, return_when=ALL_COMPLETED)

    except Exception as e:
        print(e)

    finally:
        detach_shared_memory(shm_addr)


main()

