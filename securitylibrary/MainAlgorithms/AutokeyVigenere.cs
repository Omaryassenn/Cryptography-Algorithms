using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string KeyWord = "";
            string alphbet = "abcdefghijklmnopqrstuvwxyz";
            char[] alphbets = alphbet.ToCharArray();
            string s1 = cipherText.ToLower();
            string s2 = plainText.ToLower();
            int KeyIndex;

            // Calculate the key by taking the difference between corresponding characters
            // of the cipher text and plain text, and then mapping the indices to the alphabet
            for (int i = 0; i < s1.Length; i++)
            {
                KeyIndex = (((s1[i] - s2[i]) + 26)) % 26;
                KeyWord += alphbets[KeyIndex];
            }

            Console.WriteLine(KeyWord);

            int state = 0;
            int x = 1;
            int j = 1;
            bool flag = true;

            // Determine the length of the repeating key by comparing characters of the plain text
            // with the generated key and finding the pattern
            while (true)
            {
                if (plainText[j] == KeyWord[x] && state != 0)
                {
                    j++;
                    x++;
                    if (j >= state) break;
                }
                else if (plainText[0] == KeyWord[x])
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

            string res = "";
            for (int h = 0; h < state; h++)
            {
                res += KeyWord[h];
            }
            Console.WriteLine(res);
            return res;
        }

        public string Decrypt(string cipherText, string key)
        {
            int count = 0;
            string Decrypted = "";
            string alphbet = "abcdefghijklmnopqrstuvwxyz";
            char[] alphbets = alphbet.ToCharArray();
            string s1 = cipherText.ToLower();
            string s2 = key.ToLower();
            int oldIndex;
            string d = "";
            int j = 0;

            // Repeat the key until its length matches the cipher text length
            while (s1.Length > s2.Length)
            {
                for (; j < s2.Length; j++)
                {
                    oldIndex = (((s1[j] - 'a') - (s2[j] - 'a') + 26)) % 26;
                    Decrypted += alphbets[oldIndex];
                }

                while (count < Decrypted.Length && count < s1.Length)
                {
                    s2 = s2 + Decrypted[count];
                    count++;
                }
            }

            // Perform the decryption by calculating the index of the original letter
            // using the difference between the cipher text and key characters, and then
            // mapping the indices to the alphabet
            for (int i = 0; i < s1.Length; i++)
            {
                oldIndex = (((s1[i] - 'a') - (s2[i] - 'a') + 26)) % 26;
                d += alphbets[oldIndex];
            }
            return d;
        }

        public string Encrypt(string plainText, string key)
        {
            int count = 0;
            string encrypted = "";
            string alphbet = "abcdefghijklmnopqrstuvwxyz";
            char[] alphbets = alphbet.ToCharArray();
            int newIndex;

            // Repeat the key until its length matches the plain text length
            while (plainText.Length != key.Length)
            {
                key = key + plainText[count];
                count++;
            }

            // Perform the encryption by calculating
            for (int i = 0; i < plainText.Length; i++)
            {
                newIndex = ((plainText[i] - 'a') + (key[i] - 'a')) % 26;
                encrypted += alphbets[newIndex];
            }
            return encrypted;
        }
    }
}