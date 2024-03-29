import struct
from typing import List, Union, Dict
from functools import reduce, partial
import tables as tables


class Serpent:
    key_storage: Dict[Union[str, bytes], List[int]] = {}

    @staticmethod
    def batch_size():
        return 16

    @staticmethod
    def gen_key(key: Union[str, bytes]) -> List[int]:
        if isinstance(key, str):
            key = bytes(key, 'utf8')
        space = 0
        if len(key) > 32:
            loop = len(key) // 32 + 1
            key = b'\x00' * (32 - len(key) % 32) + key
            t_key = [key[32 * i:32 * (i + 1)] for i in range(loop)]
            key = reduce(lambda x, y: b''.join([int(i ^ j)
                                               .to_bytes(1, 'big', signed=False) for i, j in zip(x, y)]), t_key)
        elif len(key) != 32:
            space = 8 * (32 - len(key)) - 1
        key = int.from_bytes(key, 'big', signed=False)
        if space:
            key = (key << 1) | 1
            key <<= space

        key = struct.unpack('I' * 8, key.to_bytes(32, 'big', signed=False))
        w = {}
        for i in range(-8, 0):
            w[i] = key[8 + i]

        for i in range(132):
            w[i] = l_move32(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ 0x9e3779b9 ^ i, 11)

        k = []
        s_counter = 3
        for i in range(132):
            if s_counter < 0:
                s_counter = 7
            k.append(Serpent.s_box(s_counter, w[i], 32))
            s_counter -= 1

        sliced = []
        for i in range(132 // 4):
            sliced.append(k[4 * i:4 * (i + 1)])
        arr = []
        for k1, k2, k3, k4 in sliced:
            arr.append((k1 << 3 * 32) | (k2 << 2 * 32) | (k3 << 32) | k4)
        for i in range(33):
            arr[i] = permutation(arr[i], tables.IP)
        return arr

    @staticmethod
    def get_keys(key: Union[str, bytes]) -> List[int]:
        if key not in Serpent.key_storage:
            Serpent.key_storage[key] = Serpent.gen_key(key)
        return Serpent.key_storage[key]

    @staticmethod
    def s_box(box: int, num: int, size: int, inverse: bool = False) -> int:
        res = 0
        for i in range(size // 4):
            r = num & 0b1111
            num >>= 4
            res = (res << 4) | (tables.S_i_inv[box][r] if inverse else tables.S_i[box][r])
        return res

    @staticmethod
    def encrypt(block: bytes, key: Union[str, bytes]) -> bytes:
        block = block.zfill(16)

        if len(block) != 16:
            raise LenError(16, len(block))

        keys = Serpent.get_keys(key)

        b = int.from_bytes(block, 'big', signed=False)

        for i in range(31):
            b = Serpent.s_box(i % 8, b ^ keys[i], 128)
            b = Serpent.linear_transform_bitwise(b)
        b = Serpent.s_box(7, b ^ keys[31], 128) ^ keys[32]

        return b.to_bytes(16, 'big', signed=False)

    @staticmethod
    def decrypt(block: bytes, key: Union[str, bytes]) -> str:
        if len(block) != 16:
            raise LenError(16, len(block))

        keys = Serpent.get_keys(key)

        b = int.from_bytes(block, 'big', signed=False)

        b = Serpent.s_box(7, b ^ keys[32], 128, inverse=True) ^ keys[31]
        for i in range(30, -1, -1):
            b = Serpent.inverse_linear_transform_bitwise(b)
            b = Serpent.s_box(i % 8, b, 128, inverse=True) ^ keys[i]

        decrypted_str = b.to_bytes(16, 'big', signed=False).decode('utf8')
        return decrypted_str

    @staticmethod
    def linear_transform_bitwise(b: int) -> int:
        x0, x1, x2, x3 = (b >> 3 * 32) & 0xffffffff, \
                         (b >> 2 * 32) & 0xffffffff, \
                         (b >> 32) & 0xffffffff, \
                         b & 0xffffffff
        x0 = l_move32(x0, 13)
        x2 = l_move32(x2, 3)
        x1 = x1 ^ x0 ^ x2
        x3 ^= x2 ^ ((x0 << 3) & 0xffffffff)
        x1 = l_move32(x1, 1)
        x3 = l_move32(x3, 7)
        x0 ^= x1 ^ x3
        x2 ^= x3 ^ ((x1 << 7) & 0xffffffff)
        x0 = l_move32(x0, 5)
        x2 = l_move32(x2, 22)
        b = x0 << 3 * 32 | x1 << 2 * 32 | x2 << 32 | x3
        return b

    @staticmethod
    def inverse_linear_transform_bitwise(b: int) -> int:
        x0, x1, x2, x3 = (b >> 3 * 32) & 0xffffffff, \
                         (b >> 2 * 32) & 0xffffffff, \
                         (b >> 32) & 0xffffffff, \
                         b & 0xffffffff
        x2 = r_move32(x2, 22)
        x0 = r_move32(x0, 5)
        x2 ^= x3 ^ ((x1 << 7) & 0xffffffff)
        x0 ^= x1 ^ x3
        x1 = r_move32(x1, 1)
        x3 = r_move32(x3, 7) ^ x2 ^ ((x0 << 3) & 0xffffffff)
        x1 ^= x0 ^ x2
        x2 = r_move32(x2, 3)
        x0 = r_move32(x0, 13)
        b = x0 << 3 * 32 | x1 << 2 * 32 | x2 << 32 | x3
        return b

    @staticmethod
    def linear_transform_table(b: int, table: List[List[int]]) -> int:
        """Doesn't work"""
        res = 0
        for bits_num in table[::-1]:
            bit = 0
            for num in bits_num:
                bit ^= (b >> num) & 1
            res <<= 1
            res |= bit
        return res


class LenError(Exception):
    def __init__(self, expected_len: int, real_len: int):
        super(LenError, self).__init__()
        self._exp_len = expected_len
        self._r_len = real_len

    def __str__(self):
        return f'Expected len of block {self._exp_len} got instead {self._r_len}'


def rounded_bit_move_left(n: int, step: int, size: int) -> int:
    n <<= step
    if n.bit_length() <= size:
        return n
    tail = n >> size
    n |= tail
    n &= (1 << size) - 1
    return n


def rounded_bit_move_right(n: int, step: int, size: int) -> int:
    begin = n & ((1 << step) - 1)
    n >>= step
    n |= begin << (size - step)
    return n


l_move32 = partial(rounded_bit_move_left, size=32)
r_move32 = partial(rounded_bit_move_right, size=32)


def permutation(num: int, perm: Union[List]) -> int:
    result = 0
    for k in perm:
        result <<= 1
        result |= (num >> k) & 1
    return result


if __name__ == '__main__':
    # Serpent usage example
    s_key = "key"
    cipher = Serpent()
    message = "message007"
    message = f"{len(message)}:{message}"
    print("Message:", message)
    encrypted = cipher.encrypt(bytes(message.encode('utf8')), s_key)
    print("Encryption:", encrypted.decode('utf8', errors='replace'))
    decrypted = cipher.decrypt(encrypted, s_key)
    print("Decryption:", decrypted)
    print("")
