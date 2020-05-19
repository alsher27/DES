using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DES
{
    public class Encryptor
    {
        const int ROUND_COUNT = 16;
        private byte[] key;
        private List<BitArray> roundKeys = new List<BitArray>();
        private BitArray roundKey;
        private BitArray permutedKey;

        public byte[] Encrypt(byte[] input, byte[] key)
        {
            this.key = key;

            var output = new byte[input.Length];
            List<BitArray> blocks = this.DivideToBlocks(input);
            for (int i = 0; i < blocks.Count; i++)
            {
                var encryptedBlock = this.EncryptBlock(blocks[i]);
                encryptedBlock.CopyTo(output, i * 8);
            }
            return output;
        }
        public byte[] Decrypt(byte[] input, byte[] key)
        {
            this.key = key;

            var output = new byte[input.Length];
            List<BitArray> blocks = this.DivideToBlocks(input);
            for (int i = 0; i < blocks.Count; i++)
            {
                var encryptedBlock = this.DecryptBlock(blocks[i]);
                encryptedBlock.CopyTo(output, i * 8);
            }
            return output;
        }

        private BitArray EncryptBlock(BitArray block)
        {
            block = this.InitialPermutation(block);
            this.GenerateKeysEncrypt();

            var L = new BitArray(32);
            var R = new BitArray(32);

            for (int i = 0; i < 32; i++)
            {
                L[i] = block[i];
                R[i] = block[32 + i];
            }

            for (int i = 0; i < ROUND_COUNT; i++)
            {
                this.roundKey = this.roundKeys[i];
                (L, R) = this.EncryptionRound(L, R);
            }
            for (int i = 0; i < 32; i++)
            {
                block[i] = L[i];
                block[i + 32] = R[i];
            }

            block = this.FinalPermutation(block);
            return block;
        }

        private void GenerateKeysEncrypt()
        {
            var keyArray = this.ExpandKey();
            this.permutedKey = this.KeyPermutation(keyArray);
            for (int i = 0; i < 16; i++)
            {
                this.roundKeys.Add(this.GenerateNextKeyEncrypt(i));
            }
        }

        private BitArray DecryptBlock(BitArray block)
        {
            block = this.InitialPermutation(block);

            this.GenerateKeysDecrypt();

            // First time break to parts
            var L = new BitArray(32);
            var R = new BitArray(32);
            for (int i = 0; i < 32; i++)
            {
                L[i] = block[i];
                R[i] = block[32 + i];
            }

            for (int i = 0; i < ROUND_COUNT; i++)
            {
                this.roundKey = this.roundKeys[ROUND_COUNT - 1 - i];
                (L, R) = this.DecryptionRound(L, R);
            }
            for (int i = 0; i < 32; i++)
            {
                block[i] = L[i];
                block[i + 32] = R[i];
            }

            block = this.FinalPermutation(block);
            return block;
        }

        private void GenerateKeysDecrypt()
        {
            var keyArray = this.ExpandKey();
            this.permutedKey = this.KeyPermutation(keyArray);
            for (int i = 0; i < 16; i++)
            {
                this.roundKeys.Add(this.GenerateNextKeyDecrypt(i));
            }
        }

        private BitArray GenerateNextKeyEncrypt(int roundNumber)
        {
            var C = new BitArray(28);
            var D = new BitArray(28);
            for (int i = 0; i < C.Length; i++)
            {
                C[i] = this.permutedKey[i];
                D[i] = this.permutedKey[i + 28];
            }

            for(int i = 0; i <= roundNumber; i++)
            {
                C = this.CircularLeftShift(C, Tables.ShiftCounts[i]);
                D = this.CircularLeftShift(D, Tables.ShiftCounts[i]);
            }

            var concatted = new BitArray(56);
            for (int i = 0; i < C.Length; i++)
            {
                concatted[i] = C[i];
                concatted[i + 28] = D[i];
            }

            var key = new BitArray(48);
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = concatted[Tables.KeyPermutation2[i] - 1];
            }

            return key;
        } 
        private BitArray GenerateNextKeyDecrypt(int roundNumber)
        {
            var C = new BitArray(28);
            var D = new BitArray(28);
            for (int i = 0; i < C.Length; i++)
            {
                C[i] = this.permutedKey[i];
                D[i] = this.permutedKey[i + 28];
            }

            for(int i = 0; i <= roundNumber; i++)
            {
                C = this.CircularRightShift(C, Tables.ShiftCounts[i]);
                D = this.CircularRightShift (D, Tables.ShiftCounts[i]);
            }

            var concatted = new BitArray(56);
            for (int i = 0; i < C.Length; i++)
            {
                concatted[i] = C[i];
                concatted[i + 28] = D[i];
            }

            var key = new BitArray(48);
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = concatted[Tables.KeyPermutation2[i] - 1];
            }

            return key;
        }
  

        private BitArray KeyPermutation(BitArray previousKey)
        {
            BitArray output = (BitArray)previousKey.Clone();

            for (int i = 0; i < Tables.KeyPermutation1.Length; i++)
            {
                output[i] = previousKey[Tables.KeyPermutation1[i] - 1];
            }

            return output;
        }

        private BitArray CircularLeftShift(BitArray input, int count)
        {
            IEnumerable<bool> enumerable = input.Cast<bool>();
            int realCount = count % input.Length;
            return new BitArray(enumerable.Skip(realCount).Concat(enumerable.Take(realCount)).ToArray());
        }

        private BitArray CircularRightShift(BitArray input, int count)
        {
            IEnumerable<bool> enumerable = input.Cast<bool>();
            int realCount = count % input.Length;

            return new BitArray(enumerable.Take(count - realCount).Concat(enumerable.TakeLast(realCount)).ToArray());
        }

        private BitArray ExpandKey()
        {
            var keyArray = new BitArray(this.key);
            var output = new BitArray(64);
            for (int i = 0; i < 7; i++)
            {
                var countOfOnes = 0;
                for (int k = 0; k < 7; k++)
                {
                    var bit = keyArray[i * 8 + k];
                    output[i * 8 + k] = bit;
                    if (bit == true) countOfOnes++;
                }
                output[i * 8 + 7] = countOfOnes % 2 == 0 ? true : false;
            }
            return output;
        }

        private List<BitArray> DivideToBlocks(byte[] input)
        {
            var list = new List<BitArray>();
            for (int i = 0; i < input.Length / 8; i++)
            {
                list.Add(new BitArray(input.Skip(i * 8).Take(8).ToArray()));
            }
            return list;
        }

        private BitArray InitialPermutation(BitArray input)
        {
            var output = new BitArray(input.Length);
            for (int i = 0; i < input.Length; i++)
            {
                output[i] = input[Tables.InitialPermutation[i] - 1];
            }
            return output;
        }
        private (BitArray left, BitArray right) EncryptionRound(BitArray left, BitArray right)
        {
            return (right, left.Xor(this.Feistel(right, this.roundKey)));
        }

        private (BitArray, BitArray) DecryptionRound(BitArray left, BitArray right)
        {
            return (right.Xor(this.Feistel(left, this.roundKey)), left);
        }

        private BitArray Feistel(BitArray input, BitArray key)
        {
            var expanded = new BitArray(Tables.Expansion.Length);
            for (int i = 0; i < Tables.Expansion.Length; i++)
            {
                expanded[i] = input[Tables.Expansion[i] - 1];
            }

            expanded = expanded.Xor(key);

            var output = new BitArray(32);
            for (int i = 0; i < 8; i++)
            {
                var block = new BitArray(6);
                for (int j = 0; j < 6; j++)
                {
                    block[j] = expanded[i * 6 + j];
                }

                block = this.S_Permutation(block, i);
                for (int j = 0; j < 4; j++)
                {
                    output[i * 4 + j] = block[j];
                }
            }

            output = this.P_Permutation(output);
            return output;
        }

        private BitArray P_Permutation(BitArray input)
        {
            var output = new BitArray(input.Length);
            for (int i = 0; i < 32; i++)
            {
                output[i] = input[Tables.P[i] - 1];
            }
            return output;
        }

        private BitArray S_Permutation(BitArray block, int i)
        {
            var table = Tables.S[i];
            var row = this.GetIntFromBitArray(new BitArray(new bool[] { block[0], block[5] }));
            var column = this.GetIntFromBitArray(new BitArray(new bool[] { block[1], block[2], block[3], block[4] }));
            var binary = Convert.ToString(table[row, column], 2).PadLeft(4, '0');
            return new BitArray(binary.ToCharArray().Select(c => int.Parse(c.ToString()) == 1 ? true : false).ToArray());
        }
        private BitArray FinalPermutation(BitArray input)
        {
            var output = new BitArray(input.Length);
            for (int i = 0; i < input.Length; i++)
            {
                output[i] = input[Tables.FinalPermutation[i] - 1];
            }
            return output;
        }

        private int GetIntFromBitArray(BitArray bitArray)
        {
            if (bitArray.Length > 32)
                throw new ArgumentException("Argument length shall be at most 32 bits.");

            int[] array = new int[1];
            bitArray.CopyTo(array, 0);
            return array[0];
        }
    }
}
