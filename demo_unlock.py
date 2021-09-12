#!/usr/bin/env python3
# !!!! Attention !!!!
# This file is an automatically generated demo file!
# This is only useful for demonstrating my script with the included `blob` file
# It serves no other purpose.
# See README.md for more information
import os
import getpass
import subprocess
import sys
from hashlib import sha3_512
class PartitionDetails:
    def __init__(self, block: int, key: bytes):
        self.block = block
        self.key = key
def get_partition_details(
        password: str, salt: bytes, num_iterations: int, keysize_bytes: int, max_blocks: int, hashfunc
) -> PartitionDetails:
    passsalt = password.encode() + salt
    h = hashfunc(passsalt)
    for _ in range(num_iterations):
        h = hashfunc(h.digest() + passsalt)
    block = int.from_bytes(h.digest(), 'big') % max_blocks
    h = hashfunc(h.digest() + bytes([block % 256]) + passsalt)
    key = b''
    while len(key) < keysize_bytes:
        key += h.digest()
        h = hashfunc(h.digest() + passsalt)
    return PartitionDetails(block, key[:keysize_bytes])
def block_to_byte(block: int, block_size: int) -> str:
    block *= block_size
    unit = 0
    units = 'BKMGTP'
    while block > 1024:
        block /= 1024
        unit += 1
    return format(block, '.03f').rstrip('0').rstrip('.') + units[unit]
def get_file_size_bytes(filename: str) -> int:
    fd = os.open(filename, os.O_RDONLY)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)
def unlock(salt, num_iterations, block_size, hashfunc):
    # Gets the block device and mapped name from stdin
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <block_device> <mapped_name>')
        sys.exit(1)
    block_device = sys.argv[1]
    map_name = sys.argv[2]
    num_blocks = get_file_size_bytes(block_device) // block_size
    disk_blocks_per_logical_block = block_size // 512
    password = getpass.getpass(f'Password for {block_device} [{map_name}]: ')
    part_details = get_partition_details(password, salt, num_iterations, 512, num_blocks, hashfunc)
    print(f'Unlocking {block_device} [{map_name}]...')
    print(f'Partition starts at block {part_details.block} ({block_to_byte(part_details.block, block_size)})')
    command = [
        'cryptsetup', '--cipher=aes-xts-plain64', f'--offset={part_details.block * disk_blocks_per_logical_block}',
        '--key-file=-', '--key-size=512', 'open', '--type=plain', block_device, map_name
    ]
    process = subprocess.Popen(command, stdin=subprocess.PIPE)
    process.communicate(part_details.key)
    process.wait()
    print(f'Done unlocking {block_device} [{map_name}]')
unlock(b'\x1b1\x87\x0f\xd5-}X\xcd\xe4\x95-L\x98\x0f\xd6\xaf\xdc\xca\x01\xdd\xbf\xbe\x82\x94/\x971\xd5\xee\x8fj\x1d\xc0\xf7\x92^{\xb4,\xd6\x9cd\xad\xc7\xb8!]f]#\xa8\x91\xb3b\x04y\xe7\xe3\x0b\xe5#\x80>', 10000, 4096, sha3_512)
