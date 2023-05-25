using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            string block, plaintText = "";
            // List<string> list = new List<string>();
            // int x = 0, y = 1;
            key = key.ToLower();
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            alphabet.ToCharArray();
            key.ToCharArray();
            int key_len = key.Length;
            List<char> CT = new List<char>();
            cipherText = cipherText.ToLower();
            int cipherTextLength = cipherText.Length / 2;
            CT.AddRange(cipherText);
            int state_key = 0;
            int state_alphbet = 0;
            HashSet<char> added = new HashSet<char>();
            char[,] arr = new char[5, 5];
            // Constructing the 5x5 matrix key square
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    bool flag = true;
                    if (state_key < key_len)
                    {
                        while (flag)
                        {
                            if (!added.Contains(key[state_key]))
                            {
                                arr[i, j] = key[state_key];
                                added.Add(key[state_key]);
                                flag = false;
                            }
                            state_key++;
                            if (state_key == key_len)
                            {
                                break;
                            }
                        }
                    }

                    if (flag)
                    {
                        while (flag)
                        {
                            if (!added.Contains(alphabet[state_alphbet]))
                            {
                                arr[i, j] = alphabet[state_alphbet];
                                added.Add(alphabet[state_alphbet]);
                                flag = false;
                            }
                            state_alphbet++;
                            if (state_alphbet == alphabet.Length)
                            {
                                break;

                            }
                        }

                    }

                }
            }
            // Pre-processing the cipher text
            for (int i = 0; i < CT.Count; i++)
            {
                if (CT[i].Equals('j'))
                {
                    CT[i] = 'i';
                }
                if (CT[i].Equals(' '))
                {
                    CT.RemoveAt(i);
                }
            }
            // Decrypting the cipher text
            for (int i = 0; i < cipherTextLength; i++)
            {
                block = cipherText.Substring(cipherText.Length - 2);
                int first_i = 0, first_j = 0, second_i = 0, second_j = 0;
                // Finding the indices of the characters in the block

                for (int r = 0; r < 5; r++)
                {
                    for (int c = 0; c < 5; c++)
                    {
                        if (arr[r, c] == block[0])
                        {
                            first_i = r;
                            first_j = c;
                        }
                        else if (arr[r, c] == block[1])
                        {
                            second_i = r;
                            second_j = c;
                        }
                    }
                }
                // Applying the Playfair decryption rules
                if (first_j == second_j)
                {
                    //Insert(int startIndex, string value)
                    char first_i_j = arr[(first_i + 4) % 5, first_j];
                    char second_i_j = arr[(second_i + 4) % 5, second_j];
                    plaintText = plaintText.Insert(0, first_i_j.ToString());
                    plaintText = plaintText.Insert(1, second_i_j.ToString());
                }
                else if (first_i == second_i)
                {
                    char first_i_j = arr[first_i, (first_j + 4) % 5];
                    char second_i_j = arr[second_i, (second_j + 4) % 5];
                    plaintText = plaintText.Insert(0, first_i_j.ToString());
                    plaintText = plaintText.Insert(1, second_i_j.ToString());
                }
                else
                {
                    char first_i_j = arr[first_i, second_j];
                    char second_i_j = arr[second_i, first_j];
                    plaintText = plaintText.Insert(0, first_i_j.ToString());
                    plaintText = plaintText.Insert(1, second_i_j.ToString());
                }
                cipherText = cipherText.Remove(cipherText.Length - 2);
            }
            for (int i = 1; i < plaintText.Length - 1; i += 2)
            {
                //check if the x is not a real char in the text 
                if (plaintText[i] == 'x' && plaintText[i + 1] == plaintText[i - 1])
                {
                    plaintText = plaintText.Remove(i, 1);
                    //placing -anything- dot instead of the deleted char to not change the length of the string so the loop could continue without throws an exception
                    plaintText = plaintText.Insert(i, ".");
                }
            }
            if (plaintText[plaintText.Length - 1] == 'x')
            {
                plaintText = plaintText.Remove(plaintText.Length - 1);
            }
            //removing the dot that we placed
            plaintText = plaintText.Replace(".", "");
            return plaintText;
        }

        public string Encrypt(string plainText, string key)
        {
            //  throw new NotImplementedException();
            string alphabet = "abcdefghiklmnopqrstuvwxyz";
            alphabet.ToCharArray();
            key.ToCharArray();
            int key_len = key.Length;
            List<char> PT = new List<char>();
            PT.AddRange(plainText);
            int state_key = 0;
            int state_alphbet = 0;
            HashSet<char> added = new HashSet<char>();
            char[,] arr = new char[5, 5];
            // Constructing the 5x5 matrix key square
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {

                    bool flag = true;

                    if (state_key < key_len)
                    {
                        // flag = true;

                        while (flag)
                        {
                            if (!added.Contains(key[state_key]))
                            {
                                arr[i, j] = key[state_key];
                                added.Add(key[state_key]);
                                flag = false;
                            }
                            state_key++;
                            if (state_key == key_len)
                            {
                                break;

                            }

                        }



                    }

                    if (flag)
                    {


                        while (flag)
                        {
                            if (!added.Contains(alphabet[state_alphbet]))
                            {
                                arr[i, j] = alphabet[state_alphbet];
                                added.Add(alphabet[state_alphbet]);
                                flag = false;
                            }
                            state_alphbet++;
                            if (state_alphbet == alphabet.Length)
                            {
                                break;

                            }

                        }

                    }

                }
            }
            // Pre-processing the plain text
            for (int i = 0; i < PT.Count; i++)
            {

                if (PT[i].Equals('j'))
                {
                    PT[i] = 'i';
                }

                if (PT[i].Equals(' '))
                {
                    PT.RemoveAt(i);
                }
            }
            // Applying the Playfair encryption rules
            for (int i = 0; i < PT.Count; i += 2)
            {
                try
                {
                    if (PT[i] == PT[i + 1])
                    {
                        PT.Insert(i + 1, 'x');
                    }
                }
                catch (Exception ex)
                {
                    PT.Add('x');
                }

            }
            List<char> encrypted = new List<char>();
            int first_i = 0, first_j = 0, second_i = 0, second_j = 0;
            // Encrypting
            for (int k = 0; k < PT.Count; k += 2)
            {
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (arr[i, j] == PT[k])
                        {
                            first_i = i;
                            first_j = j;
                        }
                        else if (arr[i, j] == PT[k + 1])
                        {
                            second_i = i;
                            second_j = j;
                        }
                    }

                }
                if (first_i == second_i)
                {
                    encrypted.Add(arr[first_i, ((first_j + 1) % 5)]);
                    encrypted.Add(arr[second_i, ((second_j + 1) % 5)]);

                }
                else if (first_j == second_j)
                {
                    encrypted.Add(arr[((first_i + 1) % 5), first_j]);
                    encrypted.Add(arr[((second_i + 1) % 5), second_j]);
                }
                else
                {
                    encrypted.Add(arr[first_i, second_j]);
                    encrypted.Add(arr[second_i, first_j]);
                }


            }
            string ret = "";
            for (int i = 0; i < encrypted.Count; i++)
            {
                ret += encrypted[i];
            }
            return ret;
        }
    }
}