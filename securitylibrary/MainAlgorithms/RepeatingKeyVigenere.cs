using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string keyWord = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            char[] alphabets = alphabet.ToCharArray();
            string s1 = cipherText.ToLower();
            string s2 = plainText.ToLower();
            int keyIndex;

            for (int i = 0; i < s1.Length; i++)
            {
                keyIndex = (((s1[i] - s2[i]) + 26)) % 26;
                keyWord += alphabets[keyIndex];
            }

            int state = 0;
            int x = 1;
            int j = 1;
            bool flag = true;

            while (true)
            {
                if (keyWord[j] == keyWord[x] && state != 0)
                {
                    j++;
                    x++;

                    if (j >= state) break;
                }
                else if (keyWord[0] == keyWord[x])
                {
                    state = x;
                    x++;
                }
                else
                {
                    state = 0;
                    j = 1;
                    x++;
                }
            }

            string result = "";

            for (int h = 0; h < state; h++)
            {
                result += keyWord[h];
            }

            return result;
        }


        public string Decrypt(string cipherText, string key)
        {
            int count = 0;
            string decrypted = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            char[] alphabets = alphabet.ToCharArray();
            string s1 = cipherText.ToLower();
            int oldIndex;

            // Ensure the key is of the same length as the cipher text
            while (s1.Length != key.Length)
            {
                key = key + key[count];
                count++;
            }

            // Perform decryption
            for (int i = 0; i < s1.Length; i++)
            {
                // Calculate the new index for decryption
                oldIndex = (((s1[i] - 'a') - (key[i] - 'a') + 26)) % 26;
                decrypted += alphabets[oldIndex];
            }

            return decrypted;
        }

        public string Encrypt(string plainText, string key)
        {
            int count = 0;
            string encrypted = "";
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            char[] alphabets = alphabet.ToCharArray();
            int newIndex;

            // Ensure the key is of the same length as the plain text
            while (plainText.Length != key.Length)
            {
                key = key + key[count];
                count++;
            }

            // Perform encryption
            for (int i = 0; i < plainText.Length; i++)
            {
                // Calculate the new index for encryption
                newIndex = ((plainText[i] - 'a') + (key[i] - 'a')) % 26;
                encrypted += alphabets[newIndex];
            }

            return encrypted;
        }

    }
}