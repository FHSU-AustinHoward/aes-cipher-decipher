# aes_cipher.py
#
# Simulates AES-128 encryption and decryption
#
# Author: Austin Howard
# Date: April 27, 2025

### LOOKUP TABLES FOR AES OPERATIONS ###

# Forward S-box
s_box = [
    # 0     1      2      3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# Inverse S-Box
inv_s_box = [0] * 256
for i, val in enumerate(s_box):
    inv_s_box[val] = i

# Round constants for key expansion
r_con = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00],
]

### CLASS IMPLEMENTATION ###
class AESCipher:
    def __init__(self, key):
        # Initialize AES to have 128-bit key
        assert len(key) == 16
        self.key = key
        self.round_keys = self.key_expansion()

    def sub_bytes(self, state):
        return [s_box[b] for b in state]

    def inv_sub_bytes(self, state):
        return [inv_s_box[b] for b in state]

    def shift_rows(self, state):
        # Convert to 4x4 matrix, shift each row, flatten back results
        matrix = [state[i::4] for i in range(4)]
        for i in range(4):
            matrix[i] = matrix[i][i:] + matrix[i][:i]
        return [matrix[i][j] for j in range(4) for i in range(4)]

    def inv_shift_rows(self, state):
        # Reverse the shifted rows
        matrix = [state[i::4] for i in range(4)]
        for i in range(4):
            matrix[i] = matrix[i][-i:] + matrix[i][:-i]
        return [matrix[i][j] for j in range(4) for i in range(4)]

    def gmul(self, a, b):
        # Multiply two bytes using Galois Field multiplication (2^8)
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            carry = a & 0x80
            a = (a << 1) & 0xFF
            if carry:
                a ^= 0x1b
            b >>= 1
        return p

    def mix_columns(self, state):
        # Use column mixing on 4-byte columns
        result = []
        for col in range(4):
            i = col * 4
            a = state[i:i+4]
            r0 = self.gmul(a[0], 2) ^ self.gmul(a[1], 3) ^ a[2] ^ a[3]
            r1 = a[0] ^ self.gmul(a[1], 2) ^ self.gmul(a[2], 3) ^ a[3]
            r2 = a[0] ^ a[1] ^ self.gmul(a[2], 2) ^ self.gmul(a[3], 3)
            r3 = self.gmul(a[0], 3) ^ a[1] ^ a[2] ^ self.gmul(a[3], 2)
            result += [r0, r1, r2, r3]
        return result

    def inv_mix_columns(self, state):
        # Reverse the MixColumns function
        result = []
        for col in range(4):
            i = col * 4
            a = state[i:i+4]
            r0 = self.gmul(a[0], 0x0e) ^ self.gmul(a[1], 0x0b) ^ self.gmul(a[2], 0x0d) ^ self.gmul(a[3], 0x09)
            r1 = self.gmul(a[0], 0x09) ^ self.gmul(a[1], 0x0e) ^ self.gmul(a[2], 0x0b) ^ self.gmul(a[3], 0x0d)
            r2 = self.gmul(a[0], 0x0d) ^ self.gmul(a[1], 0x09) ^ self.gmul(a[2], 0x0e) ^ self.gmul(a[3], 0x0b)
            r3 = self.gmul(a[0], 0x0b) ^ self.gmul(a[1], 0x0d) ^ self.gmul(a[2], 0x09) ^ self.gmul(a[3], 0x0e)
            result += [r0, r1, r2, r3]
        return result

    # Round Key and Key Expansion Utilities
    def add_round_key(self, state, round_key):
        return [b ^ k for b, k in zip(state, round_key)]

    def rot_word(self, word):
        return word[1:] + word[:1]

    def sub_word(self, word):
        return [s_box[b] for b in word]

    def xor_words(self, a, b):
        return [i ^ j for i, j in zip(a, b)]

    # AES-128 Expansion
    def key_expansion(self):
        # Generate 11 round keys for AES-128
        w = [self.key[i:i+4] for i in range(0, 16, 4)]
        for i in range(4, 44):
            temp = w[i - 1].copy()
            if i % 4 == 0:
                temp = self.xor_words(self.sub_word(self.rot_word(temp)), r_con[i // 4 - 1])
            w.append(self.xor_words(w[i - 4], temp))
        return [sum(w[4*i:4*i+4], []) for i in range(11)]

    # Encrypt a single 16-byte block
    def encrypt_block(self, plaintext):
        assert len(plaintext) == 16
        state = self.add_round_key(plaintext, self.round_keys[0])
        for round_num in range(1, 10):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.round_keys[round_num])

        # Final Round does not mix the columns
        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.round_keys[10])
        return state

    # Decrypt a single 16-byte block
    def decrypt_block(self, ciphertext):
        assert len(ciphertext) == 16
        state = self.add_round_key(ciphertext, self.round_keys[10])
        for round_num in range(9, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, self.round_keys[round_num])
            state = self.inv_mix_columns(state)

        # Final inverse round
        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, self.round_keys[0])
        return state
