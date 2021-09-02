import getpass
import os
import secrets
import subprocess
import sys
from hashlib import sha3_512
from typing import Dict, Tuple, Type, List


def prepare_interactive(block_device: str, unlocker_filename: str):
    keysize_bytes = 512 // 8
    num_iterations = 10_000  # TODO: Figure this out dynamically
    block_size = 4096  # TODO: Make this configurable
    max_blocks = get_file_size_bytes(block_device) // block_size
    hashfunc = sha3_512  # TODO: Make this configurable

    print(f'Device is {max_blocks} blocks ({block_to_byte(max_blocks, block_size)})')

    def read_bool(prompt: str, default: bool) -> bool:
        responses = {
            '': default,
            'y': True,
            'n': False
        }
        while True:
            if default:
                prompt += ' (Y/n) '
            else:
                prompt += ' (y/N) '
            response = input(prompt).strip().lower()
            if response in responses:
                return responses[response]
            else:
                print('Enter "Y" or "N"...')

    def read_pass(prompt: str) -> str:
        while True:
            check_pass = getpass.getpass(prompt)
            if getpass.getpass('Re-enter: ') == check_pass:
                return check_pass
            else:
                print('Passwords didn\'t match!')

    def read_block(prompt: str) -> int:
        postfixes = {'k': 2 ** 10, 'm': 2 ** 20, 'g': 2 ** 30, 't': 2 ** 40, 'p': 2 ** 50}
        while True:
            try:
                block = input(prompt).strip().lower()
                if block[-1] in postfixes:
                    block = round((float(block[:-1]) * postfixes[block[-1]]) / block_size)
                else:
                    block = int(block)
                return block
            except ValueError:
                pass

    ordered_partitions: List[str] = []
    target_partitions: Dict[str, int] = {}

    reading_passwords = True

    while reading_passwords:
        part = len(target_partitions) + 1
        print(f'Getting details for partition {part}...')

        password = read_pass(f'Password for partition {part}: ')

        target = read_block(f'Starting location for partition {part}: ')
        while target >= max_blocks:
            print('Target offset is past the end of the device!')
            target = read_block(f'Starting location for partition {part}: ')

        target_partitions[password] = target
        ordered_partitions.append(password)

        print(f'Target offset for partition {part}: {target} ({block_to_byte(target, block_size)})')
        reading_passwords = read_bool('Add more partitions?', True)

        print()

    print('Targeting the following partitions...')
    for i, password in enumerate(ordered_partitions):
        target_block = target_partitions[password]
        print(f'    Partition {i + 1}: Block {target_block} ({block_to_byte(target_block, block_size)})')

    print()

    print('It is hard to target offsets exactly, so an acceptable deviation can be set.')
    print('This tool searches for offsets such that the total cumulative deviations')
    print('are less than n blocks.')
    max_cum_offset_deviation = read_block('Maximum cumulative offset deviation: ')
    print(
        f'Using maximum cumulative deviation {max_cum_offset_deviation} ({block_to_byte(max_cum_offset_deviation, block_size)})')

    found_salt = False
    salt = b''

    while not found_salt:
        salt, deviation, discovered_parts = find_salt(
            target_partitions, max_blocks, max_cum_offset_deviation, keysize_bytes, num_iterations, hashfunc
        )

        print(f'Found a salt with cumulative deviation {deviation} ({block_to_byte(deviation, block_size)}).')
        print(f'The salt has the following partitions...')

        for i, password in enumerate(ordered_partitions):
            discovered_block = discovered_parts[password]
            print(f'    Partition {i + 1}: Block {discovered_block} ({block_to_byte(discovered_block, block_size)})')

        found_salt = read_bool(f'Accept this partition layout and generate an unlocker?', True)

    with open(unlocker_filename, 'w') as out:
        out.write(generate_unlocker(salt, num_iterations, block_size, hashfunc))

    print(f'Saved unlocker script to {unlocker_filename}')


def get_file_size_bytes(filename: str) -> int:
    fd = os.open(filename, os.O_RDONLY)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)


def block_to_byte(block: int, block_size: int) -> str:
    block *= block_size

    unit = 0
    units = 'BKMGTP'

    while block > 1024:
        block /= 1024
        unit += 1

    return format(block, '.03f').rstrip('0').rstrip('.') + units[unit]


def find_salt(
        partitions: Dict[str, int], max_blocks: int, max_cum_offset_deviation: int, keysize_bytes: int,
        num_iterations: int, hashfunc
) -> Tuple[bytes, int, Dict[str, int]]:
    digest_size_bytes = hashfunc().digest_size

    salt = b''
    deviation = float('inf')
    best_deviation = float('inf')
    discovered_partitions: Dict[str, int] = {}

    while deviation > max_cum_offset_deviation:
        salt = secrets.randbits(digest_size_bytes * 8).to_bytes(digest_size_bytes, 'big')

        deviation, discovered_partitions = grade_salt(
            salt, partitions, max_blocks, num_iterations, keysize_bytes, best_deviation, hashfunc
        )

        if deviation < best_deviation:
            print(f'Found a deviation of {deviation}...')
            best_deviation = deviation

    return salt, deviation, discovered_partitions


def grade_salt(
        salt: bytes, partitions: Dict[str, int], max_blocks: int, num_iterations: int, keysize_bytes: int,
        max_deviation: int, hashfunc: Type
) -> Tuple[int, Dict[str, int]]:
    deviation = 0
    discovered_partitions: Dict[str, int] = {}

    for password, target_offset in partitions.items():
        details = get_partition_details(password, salt, num_iterations, keysize_bytes, max_blocks, hashfunc)
        discovered_partitions[password] = details.block
        deviation += abs(target_offset - details.block)

        if deviation > max_deviation:
            return deviation, {}

    return deviation, discovered_partitions


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


# TODO: Generate num_iterations dynamically instead of using a fixed value
# TODO: Generate cryptsetup options dynamically
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


def generate_unlocker(salt: bytes, num_iterations: int, block_size: int, hashfunc: Type) -> str:
    import inspect
    import re

    unlocker = ''

    unlocker += '#!/usr/bin/env python3\n'
    unlocker += 'import getpass\n'
    unlocker += 'import os\n'
    unlocker += 'import subprocess\n'
    unlocker += 'import sys\n'
    unlocker += f'from {hashfunc.__module__} import {hashfunc.__name__}\n'
    unlocker += inspect.getsource(PartitionDetails) + '\n'
    unlocker += inspect.getsource(get_partition_details) + '\n'
    unlocker += inspect.getsource(block_to_byte) + '\n'
    unlocker += inspect.getsource(get_file_size_bytes) + '\n'
    unlocker += inspect.getsource(unlock) + '\n'
    unlocker += f'unlock({repr(salt)}, {num_iterations}, {block_size}, {hashfunc.__name__})\n'

    unlocker = re.sub(r'\n(\s*\n)+', '\n', unlocker)

    return unlocker


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <block_device> <unlocker_filename.py>')
        sys.exit(1)

    prepare_interactive(sys.argv[1], sys.argv[2])
