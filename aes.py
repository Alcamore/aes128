#!/usr/bin/env python3
# Substitution box for the sub_bytes routine for encryption
_sub_box = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],
]

# Substitution box for the inv_sub_bytes routine for decryption
_inv_sub_box = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d],
]

def cipher(plaintext, key):
    a = AES()

    state = plaintext[:]
    key_schedule = a.key_expansion(key)

    a.add_round_key(state, key_schedule[:a.block_size])

    for round in range(a.num_rounds):
        state = a.sub_bytes(state)
        state = a.shift_rows(state)
        state = a.mix_columns(state)
        key_start = round * a.block_size
        key_end = (round+ 1 ) * a.block_size - 1
        a.add_round_key(state, key_schedule[key_start:key_end])

    state = a.sub_bytes(state)
    state = a.shift_rows(state)
    key_start = a.num_rounds * a.block_size
    key_end = (a.num_rounds + 1) * a.block_size - 1
    a.add_round_key(state, key_schedule[key_start:key_end])

    return state

def decipher(ciphertext, key):
    a = AES()

    state = ciphertext[:]
    key_schedule = a.key_expansion(key)

    key_start = a.num_rounds * a.block_size
    key_end = (a.num_rounds + 1) * a.block_size - 1
    a.add_round_key(state, key_schedule[key_start:key_end])

    for round in range(a.num_rounds-1, 1, -1):
        state = a.inv_shift_rows(state)
        state = a.inv_sub_bytes(state)
        key_start = round * a.block_size
        key_end = (round + 1) * a.block_size - 1
        a.add_round_key(state, key_schedule[key_start:key_end])
        state = a.inv_mix_columns(state)

    state = a.inv_shift_rows(state)
    state = a.inv_sub_bytes(state)
    key_start = a.num_rounds * a.block_size
    key_end = (a.num_rounds + 1) * a.block_size - 1
    a.add_round_key(state, key_schedule[key_start:key_end])

    return state

class AES:

    def __init__(self):
        self.key_length = 4 # key length in words
        self.block_size = 4 # block size in words
        self.num_rounds = 10 # number of rounds to perform

        # populate round constant list with powers of 2 in GF(8)
        self.round_constant = [0x1]
        for i in range(14):
            self.round_constant.append(self.xmult(self.round_constant[i], 2))

    def sub_bytes(self, state):
        '''Performs the byte substitution operation.
        '''
        new_state = bytearray(state)

        for index, byte in enumerate(state):
            # separate hex xy into x and y
            x = byte // 0x10
            y = byte % 0x10

            # perform substitution
            new_state[index] = _sub_box[x][y]

        return bytes(new_state)

    def inv_sub_bytes(self, state):
        '''Performs the inverse of the byte substitution operation.
        '''
        new_state = bytearray(state)

        for index, byte in enumerate(state):
            # separate hex xy into x and y
            x = byte // 0x10
            y = byte % 0x10

            # perform substitution
            new_state[index] = _inv_sub_box[x][y]

        return new_state

    def shift_rows(self, state: bytes):
        '''Performs the inverse of the shift rows operation.
        '''
        # Convert state to a matrix
        matrix = self.make_matrix(state)

        # Shift rows 1 2 and 3 back by 1, 2, and 3 respectively
        for index, row in enumerate(matrix):
            matrix[index] = self.rotate(row, index)

        # Convert result back to an array
        return bytes(self.inv_make_matrix(matrix))

    def inv_shift_rows(self, state):
        '''Performs the inverse of the shift rows operation.
        '''
        # Convert state to a matrix
        matrix = self.make_matrix(state)

        # Shift each row by their row number respectively
        for index, row in enumerate(matrix):
            matrix[index] = self.rotate(row, index, reverse=True)

        # Convert result back to an array
        return bytes(self.inv_make_matrix(matrix))

    def mix_columns(self, state):
        '''Performs the mix columns operation.
        '''
        # Make a list of all the columns in the state
        cols = self.make_column(bytearray(state))

        xmult = self.xmult
        # Perform multiplication
        for col in cols:
            tmp = col[:]
            col[0] = xmult(2, tmp[0]) ^ xmult(3, tmp[1]) ^ xmult(1, tmp[2]) ^ xmult(1, tmp[3])
            col[1] = xmult(1, tmp[0]) ^ xmult(2, tmp[1]) ^ xmult(3, tmp[2]) ^ xmult(1, tmp[3])
            col[2] = xmult(1, tmp[0]) ^ xmult(1, tmp[1]) ^ xmult(2, tmp[2]) ^ xmult(3, tmp[3])
            col[3] = xmult(3, tmp[0]) ^ xmult(1, tmp[1]) ^ xmult(1, tmp[2]) ^ xmult(2, tmp[3])

        # Re-combine list
        return self.inv_make_column(cols)

    def inv_mix_columns(self, state):
        '''Performs the inverse mix columns operation.
        '''
        # Make a list of all the columns in the state
        cols = self.make_column(bytearray(state))

        xmult = self.xmult
        # Perform multiplication
        for col in cols:
            tmp = col[:]
            col[0] = xmult(0x0e, tmp[0]) ^ xmult(0x0b, tmp[1]) ^ xmult(0x0d, tmp[2]) ^ xmult(0x09, tmp[3])
            col[1] = xmult(0x09, tmp[0]) ^ xmult(0x0e, tmp[1]) ^ xmult(0x0b, tmp[2]) ^ xmult(0x0d, tmp[3])
            col[2] = xmult(0x0d, tmp[0]) ^ xmult(0x09, tmp[1]) ^ xmult(0x0e, tmp[2]) ^ xmult(0x0b, tmp[3])
            col[3] = xmult(0x0b, tmp[0]) ^ xmult(0x0d, tmp[1]) ^ xmult(0x09, tmp[2]) ^ xmult(0x0e, tmp[3])

        # Re-combine columns`
        return self.inv_make_column(cols)

    def add_round_key(self, state, key_schedule):
        '''XORs the state with the next round key.
        '''
        # Make a list of all the columns in the state
        cols = self.make_column(state)

        # Make a matching list from the key schedule segment
        keys = self.make_column(key_schedule)

        for index, (col, key) in enumerate(zip(cols, keys)):
            cols[index] = [c^k for c,k in zip(col, key)]

        return self.inv_make_column(cols)

    def key_expansion(self, key):
        '''Expands the key into a key schedule.
        '''
        schedule_size = self.block_size * (self.num_rounds + 1)
        key_sch = bytearray(schedule_size)
        temp = bytearray(4)

        for i in range(0, self.key_length, 4):
            key_sch[i:i+4] = key[4*i:4*i+4]

        for i in range(self.key_length, self.block_size * self.num_rounds, 4):
            temp = key_sch[i-1:i+3]
            if (i % self.key_length == 0):
                temp = self.constant_word_xor(self.sub_bytes(self.rotate(temp)), self.round_constant[i//self.key_length])
            key_sch[i:i+4] = self.word_xor(key_sch[i-4:i], temp)

        return bytes(key_sch)


    def make_matrix(self, state):
        '''Converts the state from an array form to a matrix form.
        '''
        mtx = [
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0]
        ]

        for index, byte in enumerate(state):
            row = index % 4
            col = index // 4
            mtx[row][col] = byte

        return mtx

    def inv_make_matrix(self, mtx):
        '''Converts the state from a matrix form to a bytestring form.
        '''
        state = bytearray(16)

        for index in range(len(state)):
            row = index % 4
            col = index // 4
            state[index] = mtx[row][col]
        return bytes(state)

    def make_column(self, state):
        '''Extracts the columns of the state into a list.
        '''
        return [
            state[:4],
            state[4:8],
            state[8:12],
            state[12:]
        ]

    def inv_make_column(self, cols):
        '''Converts a column version of the state into a list.
        '''
        return cols[0] + cols[1] + cols[2] + cols[3]

    def xmult(self, a, b):
        '''Performs a finite-field multiplication in GF(2^8).

        Based on the Russian Peasant Multiplication Algorithm
        found at https://en.wikipedia.org/wiki/Finite_field_arithmetic
        '''
        if a > 255 or b > 255 or a < 0 or b < 0:
            raise ValueError(f'{a=} and {b=} must be between 0 and 255')

        product = 0
        polynomial = 0b1_0001_1011 # x^8 + x^4 + x^3 + x + 1

        while a and b:
            if b & 1 != 0:
                product ^= a
            if a & 128:
                a = (a << 1) ^ polynomial
            else:
                a *= 2
            b //= 2

        return product

    def rotate(self, iterable, amount=1, reverse=False):
        '''Rotates an iterable by a certain amount.

        Rotates left by default
        '''
        if reverse:
            amount *= -1
        return iterable[amount:] + iterable[:amount]

    def constant_word_xor(self, word, constant):
        ''' XORs a word with some constant
        '''
        return [x^constant for x in word]

    def word_xor(self, word, other):
        ''' XORs a word with another word
        '''
        return [x^y for x, y in zip(word, other)]


if __name__ == '__main__':
    choice = input("Type 'c' for cipher or 'd' for decipher: ")
    text = input("Type text in hex: ")
    key = input("Type key in hex: ")

    if choice == 'c':
        print(cipher(text, key).hex())
    if choice == 'd':
        print(decipher(text, key).hex())
