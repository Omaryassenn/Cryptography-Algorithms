using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            int numOfRows = 0;
            int numOfColumns = 0;
            cipherText = cipherText.ToLower();

            // Determine the number of columns based on the length of the cipher text
            // by checking divisibility from 2 to 7 (assuming the key length is between 2 and 7)
            for (int i = 2; i < 8; i++)
            {
                if (cipherText.Length % i == 0)
                {
                    numOfColumns = i;
                }
            }

            numOfRows = cipherText.Length / numOfColumns;
            char[,] plainArr = new char[numOfRows, numOfColumns];
            char[,] cipherArr = new char[numOfRows, numOfColumns];
            List<int> key = new List<int>(numOfColumns);

            int n = 0;
            // Fill the plain array by iterating through the rows and columns
            // and assigning characters from the plain text
            for (int i = 0; i < numOfRows; i++)
            {
                for (int j = 0; j < numOfColumns; j++)
                {
                    if (n < plainText.Length)
                    {
                        plainArr[i, j] = plainText[n];
                        n++;
                    }
                }
            }

            n = 0;
            // Fill the cipher array by iterating through the columns and rows
            // and assigning characters from the cipher text
            for (int i = 0; i < numOfColumns; i++)
            {
                for (int j = 0; j < numOfRows; j++)
                {
                    if (n < cipherText.Length)
                    {
                        cipherArr[j, i] = cipherText[n];
                        n++;
                    }
                }
            }

            int count = 0;
            // Analyze the arrays to find the possible key values
            // by comparing each column in the plain and cipher arrays
            for (int i = 0; i < numOfColumns; i++)
            {
                for (int k = 0; k < numOfColumns; k++)
                {
                    for (int j = 0; j < numOfRows; j++)
                    {
                        if (plainArr[j, i] == cipherArr[j, k])
                        {
                            count++;
                        }

                        if (count == numOfRows)
                        {
                            key.Add(k + 1);
                        }
                    }

                    count = 0;
                }
            }

            // If no key values were found, add placeholder values of 0 to the key list
            if (key.Count == 0)
            {
                for (int i = 0; i < numOfColumns + 2; i++)
                {
                    key.Add(0);
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            double keyLen = key.Count;
            Dictionary<int, int> dec_index = new Dictionary<int, int>();

            // Create a dictionary to map the key values to their respective indices
            for (int i = 0; i < keyLen; i++)
            {
                dec_index.Add(key[i], i);
            }

            // Pad the cipher text if its length is not divisible by the key length
            while (true)
            {
                if ((cipherText.Length % keyLen) != 0)
                {
                    cipherText += 'x';
                }
                else
                {
                    break;
                }
            }

            int ctLen = (int)Math.Ceiling(cipherText.Length / keyLen);
            int x = 0;

            char[,] matrix = new char[ctLen, (int)keyLen];

            // Fill the matrix by assigning characters from the cipher text
            // based on the key mapping and the column index
            for (int j = 0; j < keyLen; j++)
            {
                for (int i = 0; i < ctLen; i++)
                {
                    int c = dec_index[j + 1];
                    matrix[i, c] = cipherText[x];
                    x++;
                }
            }

            string res = "";
            // Read the matrix row by row and concatenate the characters
            for (int i = 0; i < ctLen; i++)
            {
                for (int j = 0; j < keyLen; j++)
                {
                    res += matrix[i, j];
                }
            }

            return res.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            double keyLen = key.Count;
            int ptLen = (int)Math.Ceiling(plainText.Length / keyLen);
            char[,] matrix = new char[ptLen, (int)keyLen];
            int x = 0;

            // Pad the plain text if its length is not divisible by the key length
            for (int i = 0; i < ptLen; i++)
            {
                if ((plainText.Length % keyLen) != 0)
                {
                    plainText += 'x';
                }
            }

            // Fill the matrix by assigning characters from the plain text
            // based on the row index and the key mapping
            for (int i = 0; i < ptLen; i++)
            {
                for (int j = 0; j < keyLen; j++)
                {
                    matrix[i, j] = plainText[x];
                    x++;
                }
            }

            char[] ct = new char[plainText.Length];
            // Rearrange the matrix columns based on the key values
            // and construct the encrypted text
            for (int j = 0; j < keyLen; j++)
            {
                int c = key[j] - 1;

                for (int i = 0; i < ptLen; i++)
                {
                    ct[ptLen * c + i] = matrix[i, j];
                }
            }

            string result = new string(ct);
            return result;
        }
    }
}
