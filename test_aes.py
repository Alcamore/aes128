#!/usr/bin/env python3
import unittest
import aes

class TestAES(unittest.TestCase):
    def setUp(self):
        plaintext = bytes.fromhex('00112233445566778899aabbccddeeff')
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

    def testSubBytes(self):
        state = aes.sub_bytes(bytes.fromhex('00102030405060708090a0b0c0d0e0f0'))
        self.assertEqual(state, bytes.fromhex('63cab7040953d051cd60e0e7ba70e18c'))

    def testShiftRows(self):
        state = aes.shift_rows(bytes.fromhex('63cab7040953d051cd60e0e7ba70e18c'))
        self.assertEqual(state, bytes.fromhex('6353e08c0960e104cd70b751bacad0e7'))

    def testMixColumns(self):
        state = aes.mix_columns(bytes.fromhex('6353e08c0960e104cd70b751bacad0e7'))
        self.assertEqual(state, bytes.fromhex('5f72641557f5bc92f7be3b291db9f91a'))

    def testInvSubBytes(self):
        state = aes.inv_sub_bytes(bytes.fromhex('63cab7040953d051cd60e0e7ba70e18c'))
        self.assertEqual(state, bytes.fromhex('00102030405060708090a0b0c0d0e0f0'))

    def testInvShiftRows(self):
        state = aes.inv_shift_rows(bytes.fromhex('6353e08c0960e104cd70b751bacad0e7'))
        self.assertEqual(state, bytes.fromhex('63cab7040953d051cd60e0e7ba70e18c'))

    def testInvMixColumns(self):
        state = aes.inv_mix_columns(bytes.fromhex('5f72641557f5bc92f7be3b291db9f91a'))
        self.assertEqual(state, bytes.fromhex('6353e08c0960e104cd70b751bacad0e7'))

if __name__ == '__main__':
    unittest.main()
