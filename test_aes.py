#!/usr/bin/env python3
import unittest
import aes

class TestAES(unittest.TestCase):
    def setUp(self):
        self.plaintext = bytes.fromhex('00112233445566778899aabbccddeeff')
        self.key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        self.ciphertext = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')

        self.plaintext2 = bytes.fromhex('54776f204f6e65204e696e652054776f')
        self.key2 = bytes.fromhex('5468617473206d79204b756e67204675')
        self.ciphertext2 = bytes.fromhex('29c3505f571420f6402299b31a02d73a')

        self.aes = aes.AES()

    def testCipher(self):
        ciphertext = aes.cipher(self.plaintext, self.key)
        ciphertext2 = aes.cipher(self.plaintext2, self.key2)
        self.assertEqual(ciphertext, self.ciphertext)
        self.assertEqual(ciphertext2, self.ciphertext2)

    def testDecipher(self):
        plaintext = aes.decipher(bytes.fromhex(''), self.key)
        plaintext2 = aes.decipher(bytes.fromhex(''), self.key2)
        self.assertEqual(plaintext, self.plaintext)
        self.assertEqual(plaintext2, self.plaintext2)

    def testSubBytes(self):
        state = self.aes.sub_bytes(bytes.fromhex('00102030405060708090a0b0c0d0e0f0'))
        state2 = self.aes.sub_bytes(bytes.fromhex('001f0e543c4e08596e221b0b4774311a'))

        self.assertEqual(state.hex(), '63cab7040953d051cd60e0e7ba70e18c')
        self.assertEqual(state2.hex(), '63c0ab20eb2f30cb9f93af2ba092c7a2')

    def testShiftRows(self):
        state = self.aes.shift_rows(bytes.fromhex('63cab7040953d051cd60e0e7ba70e18c'))
        self.assertEqual(state.hex(), '6353e08c0960e104cd70b751bacad0e7')

    def testMixColumns(self):
        state = self.aes.mix_columns(bytes.fromhex('6353e08c0960e104cd70b751bacad0e7'))
        self.assertEqual(state.hex(), '5f72641557f5bc92f7be3b291db9f91a')

    def testInvSubBytes(self):
        state = self.aes.inv_sub_bytes(bytes.fromhex('63cab7040953d051cd60e0e7ba70e18c'))
        self.assertEqual(state.hex(), '00102030405060708090a0b0c0d0e0f0')

    def testInvShiftRows(self):
        state = self.aes.inv_shift_rows(bytes.fromhex('6353e08c0960e104cd70b751bacad0e7'))
        self.assertEqual(state.hex(), '63cab7040953d051cd60e0e7ba70e18c')

    def testInvMixColumns(self):
        state = self.aes.inv_mix_columns(bytes.fromhex('5f72641557f5bc92f7be3b291db9f91a'))
        self.assertEqual(state.hex(), '6353e08c0960e104cd70b751bacad0e7')

    def testKeyExpansion(self):
        #key_schedule = self.aes.key_expansion(self.key)
        key_schedule2 = self.aes.key_expansion(self.key2)

        self.assertEqual(key_schedule2[:16].hex(), '5468617473206d79204b756e67204675')
        self.assertEqual(key_schedule2[16:32].hex(), 'e232fcf191129188b159e4e6d679a293')
        self.assertEqual(key_schedule2[32:48].hex(), '56082007c71ab18f76435569a03af7fa')
        self.assertEqual(key_schedule2[48:64].hex(), 'd2600de7157abc686339e901c3031efb')

    def testAddRoundKey(self):
        state = bytes.fromhex('54776F204F6E65204E696E652054776F')
        round_key = bytes.fromhex('5468617473206D79204B756E67204675')

        result = self.aes.add_round_key(state, round_key)

        self.assertEqual(bytes(result).hex(), '001f0e543c4e08596e221b0b4774311a')

class TestAESUtilities(unittest.TestCase):
    def setUp(self):
        self.aes = aes.AES()

    def testMakeMatrix(self):
        input = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        matrix = self.aes.make_matrix(input)
        self.assertEqual(matrix, [
            [0, 4, 8, 12],
            [1, 5, 9, 13],
            [2, 6, 10, 14],
            [3, 7, 11, 15]
        ])

    def testInvMakeMatrix(self):
        input = [
            [0, 4, 8, 12],
            [1, 5, 9, 13],
            [2, 6, 10, 14],
            [3, 7, 11, 15]
        ]
        result = self.aes.inv_make_matrix(input)
        expected = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        self.assertEqual(result.hex(), expected.hex())

    def testMakeColumn(self):
        input = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        cols = self.aes.make_column(input)

        self.assertEqual(cols, [
            [0, 1, 2, 3],
            [4, 5, 6, 7],
            [8, 9, 10, 11],
            [12, 13, 14, 15]
        ])

    def testInvMakeColumn(self):
        input = [
            [0, 1, 2, 3],
            [4, 5, 6, 7],
            [8, 9, 10, 11],
            [12, 13, 14, 15]
        ]
        result = self.aes.inv_make_column(input)
        expected = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]

        self.assertEqual(result, expected)

    def testRotate(self):
        input = [0, 1, 2, 3]

        rotate_left = self.aes.rotate(input)
        rotate_right = self.aes.rotate(input, reverse=True)
        rotate_three_left = self.aes.rotate(input, 3)
        rotate_three_right = self.aes.rotate(input, 3, reverse=True)

        self.assertEqual(rotate_left, [1, 2, 3, 0])
        self.assertEqual(rotate_right, [3, 0, 1, 2])
        self.assertEqual(rotate_three_left, [3, 0, 1, 2])
        self.assertEqual(rotate_three_right, [1, 2, 3, 0])

    def testConstantWordXOR(self):
        input = [1, 2, 3, 4]
        constant = 42

        result = self.aes.constant_word_xor(input, constant)

        self.assertEqual(result, [43, 40, 41, 46])

    def testWordXOR(self):
        input = [1, 2, 3, 4]
        other = [9, 8, 7, 6]

        result = self.aes.word_xor(input, other)

        self.assertEqual(result, [8, 10, 4, 2])

    def testXMult(self):
        self.assertEqual(self.aes.xmult(80, 74), 209)

        with self.assertRaises(ValueError):
            self.aes.xmult(-1, 0)
        with self.assertRaises(ValueError):
            self.aes.xmult(256, 0)

if __name__ == '__main__':
    unittest.main()
