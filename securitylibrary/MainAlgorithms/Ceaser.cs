using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string alphbet = "abcdefghijklmnopqrstuvwxyz";
            char[] alphbets = alphbet.ToCharArray();
            plainText.ToLower();
            plainText.ToCharArray();
            int newIndex;
            string encrypted = "";

            // Perform the encryption by shifting each character in the plain text
            // by the specified key value and mapping the indices to the alphabet
            for (int i = 0; i < plainText.Length; i++)
            {
                newIndex = (plainText[i] - 'a' + key) % 26;
                encrypted += alphbets[newIndex];
            }

            return encrypted;
        }

        public string Decrypt(string cipherText, int key)
        {
            string alphbet = "abcdefghijklmnopqrstuvwxyz";
            char[] alphbets = alphbet.ToCharArray();
            string lower = cipherText.ToLower();
            lower.ToCharArray();
            List<char> Decrypted = new List<char>();
            int Y;

            // Perform the decryption by shifting each character in the cipher text
            // back by the specified key value and mapping the indices to the alphabet
            for (int j = 0; j < lower.Length; j++)
            {
                Y = ((lower[j] - 'a') + (26 - key)) % 26;
                Decrypted.Add(alphbets[Y]);
            }

            string ret = "";
            for (int i = 0; i < Decrypted.Count; i++)
            {
                ret += Decrypted[i];
            }

            return ret;
        }

        public int Analyse(string plainText, string cipherText)
        {
            string s1 = cipherText.ToLower();
            string s2 = plainText.ToLower();
            s1.ToCharArray();
            s2.ToCharArray();
            int K;

            // Calculate the key value by finding the difference between the first characters
            // of the cipher text and plain text, taking into account the circular nature of the alphabet
            if (s1[0] > s2[0])
            {
                K = s1[0] - s2[0];
            }
            else if (s1[0] < s2[0])
            {
                K = (s1[0] - s2[0]) + 26;
            }
            else
            {
                K = 0;
            }

            return K;
        }

    }
}