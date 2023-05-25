using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            Dictionary<char, char> Key = new Dictionary<char, char>();
            string alphbet = "abcdefghijklmnopqrstuvwxyz";
            List<char> alphbets = new List<char>();
            string s2 = cipherText.ToLower();

            // Create a list of alphabets
            for (int i = 0; i < alphbet.Length; i++)
            {
                alphbets.Add(alphbet[i]);
            }

            // Initialize the Key dictionary with default values
            for (int i = 0; i < alphbet.Length; i++)
            {
                Key.Add(alphbets[i], '0');
            }

            // Analyze the plainText and cipherText to find the key mapping
            for (int i = 0; i < plainText.Length; i++)
            {
                Key[plainText[i]] = s2[i];
                alphbets.Remove(s2[i]);
            }

            // Fill in the remaining key mapping
            int j = 0;
            while (true)
            {
                if (Key[alphbet[j]] == '0')
                {
                    Key[alphbet[j]] = alphbets[0];
                    alphbets.RemoveAt(0);
                }
                j++;
                if (j >= alphbet.Length)
                {
                    break;
                }
            }

            // Generate the resulting key string
            string result = "";
            for (int i = 0; i < alphbet.Length; i++)
            {
                result += Key[alphbet[i]];
            }

            return result.ToLower();
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string alphabet2 = alphabet.ToUpper();
            char[] keyArr = key.ToCharArray();
            char[] alpha = alphabet2.ToCharArray();
            char[] cipherLetters = cipherText.ToLower().ToCharArray();
            StringBuilder plainText = new StringBuilder();

            int j = 0;
            while (j < cipherLetters.Length)
            {
                if (char.IsLetter(cipherText[j])) // Check if the character is a letter
                {
                    int idx = Array.IndexOf(keyArr, cipherLetters[j]);
                    plainText.Append(alpha[idx]);
                }
                j++;
            }

            string result = plainText.ToString().ToUpper();
            return result;
        }

        public string Encrypt(string plainText, string key)
        {
            StringBuilder cipherText = new StringBuilder();
            string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string alphabet2 = alphabet.ToLower();
            char[] keyArr = key.ToCharArray();
            char[] alpha = alphabet2.ToCharArray();
            char[] plainLetters = plainText.ToLower().ToCharArray();
            int size = plainLetters.Length;

            int j = 0;
            while (j < size)
            {
                if (char.IsLetter(plainText[j])) // Check if the character is a letter
                {
                    int idx = Array.IndexOf(alpha, plainLetters[j]);
                    cipherText.Append(keyArr[idx]);
                }
                j++;
            }

            string result = cipherText.ToString().ToUpper();
            return result;
        }






        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string frequent = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            Dictionary<char, char> key = new Dictionary<char, char>();
            cipher = cipher.ToLower();

            Dictionary<char, int> freqChars = new Dictionary<char, int>();

            // Count the frequency of characters in the cipher text
            for (int i = 0; i < cipher.Length; i++)
            {
                if (freqChars.ContainsKey(cipher[i]))
                {
                    freqChars[cipher[i]]++;
                }
                else
                {
                    freqChars.Add(cipher[i], 1);
                }
            }

            // Sort the characters by their frequency in descending order
            freqChars = freqChars.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value);
            List<char> orderedChars = freqChars.Keys.ToList();

            // Create a mapping between the most frequent characters in the cipher and the frequent characters in the English language
            for (int i = 0; i < orderedChars.Count; i++)
            {
                key.Add(orderedChars[i], frequent[i]);
            }

            // Decrypt the cipher text using the character mapping
            string decryptedText = "";
            for (int i = 0; i < cipher.Length; i++)
            {
                decryptedText += key[cipher[i]];
            }

            return decryptedText;
        }

    }
}