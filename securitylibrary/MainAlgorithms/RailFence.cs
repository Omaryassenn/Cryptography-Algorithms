using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int k = 0;
            int plainLength = plainText.Length; // Length of the plaintext
            string res;

            for (int i = 2; i < plainLength; i++) // Loop through possible key lengths
            {
                res = Encrypt(plainText, i).ToUpper();

                if (res == cipherText)
                {
                    k = i;
                    break;
                }
            }

            return k;
        }


        public string Decrypt(string cipherText, int key)
        {
            int num = 0;
            List<List<int>> my_list = new List<List<int>>();
            for (int i = 0; i < key; i++)
            {
                my_list.Add(new List<int>()); // Add a line in the list
            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                if (num == key) // Check if num = key, start from the first line again
                    num = 0;

                my_list[num].Add(i); // Add to the list
                num++;
            }

            int count = 0;
            char[] Buffer = new char[cipherText.Length]; // Array of characters
            for (int i = 0; i < key; i++) // Loop through the lists
            {
                for (int j = 0; j < my_list[i].Count; j++) // Loop through the list of integers
                {
                    Buffer[my_list[i][j]] = cipherText[count];
                    count++;
                }
            }

            return new string(Buffer);
        }

        public string Encrypt(string plainText, int key)
        {
            int num = 0;
            List<string> my_list = new List<string>();
            for (int i = 0; i < key; i++)
            {
                my_list.Add(""); // Add a line in the list
            }

            foreach (char c in plainText)
            {
                if (num == key) // Check if num = key, start from the first line again
                    num = 0;

                my_list[num] += c;
                num++;
            }

            string res = ""; // Result string to store the total
            foreach (string s in my_list)
            {
                res += s;
            }

            return res;
        }

    }
}
