using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            // This method analyzes the given plaintext and ciphertext to determine the encryption key used.
            // It iterates through all possible combinations of keys and checks if the encrypted plaintext matches the given ciphertext.

            List<int> key, ct;

            // Iterate through all possible values for each element of the key
            for (int l = 0; l < 26; l++)
            {
                for (int m = 0; m < 26; m++)
                {
                    for (int n = 0; n < 26; n++)
                    {
                        for (int o = 0; o < 26; o++)
                        {
                            // Create a new key using the current values of l, m, n, o
                            key = new List<int>() { l, m, n, o };

                            // Encrypt the plaintext using the current key
                            ct = Encrypt(plainText, key);

                            // Check if the encrypted plaintext matches the given ciphertext
                            bool equal = ct.SequenceEqual(cipherText);
                            if (equal)
                            {
                                // If the encrypted plaintext matches the given ciphertext, return the key
                                return key;
                            }
                        }
                    }
                }
            }

            // If no matching key is found, throw an exception
            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            // This method decrypts the given ciphertext using the provided key.

            int m = (int)Math.Sqrt(key.Count), n = cipherText.Count / m;
            int[,] key_arr = listToMatrixRows(key), plain_arr = listToMatrixbyCols(cipherText, m);

            // Check if the key is invertible
            if (!matrix_is_invertable(key_arr, m))
                throw new InvalidAnlysisException();

            // If the key is 2x2, use the inverse2 function to compute the inverse
            if (m == 2)
                key_arr = inverse2(key_arr);
            // If the key is 3x3, use the inverse3 function to compute the inverse
            else if (m == 3)
                key_arr = inverse3(key_arr, m);

            // Multiply the inverse key with the ciphertext to get the decrypted plaintext
            List<int> result = multiplyMatrices(key_arr, plain_arr, m, n);
            return result;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            // This method encrypts the given plaintext using the provided key.

            int m = (int)Math.Sqrt(key.Count), n = plainText.Count / m;
            int[,] key_arr = listToMatrixRows(key), plain_arr = listToMatrixbyCols(plainText, m);

            // Multiply the key with the plaintext to get the encrypted ciphertext
            List<int> result = multiplyMatrices(key_arr, plain_arr, m, n);
            return result;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            // This method analyzes a 3x3 key using a specific plaintext and ciphertext pair.

            List<int> Key;
            int[,] cipherMatrix = listToMatrixRows(cipher3),
            plainMatrix = listToMatrixbyCols(plain3, 3), plainMatrixInv = inverse3(plainMatrix, 3);

            // Transpose the inverse of the plaintext matrix
            plainMatrixInv = transposematrix(plainMatrixInv);

            // Compute the key by multiplying the transposed inverse of the plaintext matrix with the ciphertext matrix
            int[,] key = matrixMultiplication(plainMatrixInv, cipherMatrix);

            // Convert the key matrix to a list
            Key = matrixToList(key);

            // Return the key
            return Key;
        }
        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }

        //----------------------------------------------------------------
        int get_b(int det)
        {
            // This function calculates the modular multiplicative inverse of 'det' modulo 26.
            // It finds the value 'b' such that (b * det) % 26 == 1.

            int b = 0;

            // Iterate until a value of 'b' is found such that (b * det) % 26 == 1
            while ((b * det) % 26 != 1)
            {
                b++;

                // If 'b' reaches 26 without finding a suitable value, break the loop
                if (b == 26)
                    break;
            }

            return b;
        }

        List<int> matrixToList(int[,] matrix)
        {
            // This function converts a 2D matrix into a 1D list by traversing the matrix column-wise.

            List<int> list = new List<int>();
            int rows = matrix.GetLength(0), cols = matrix.GetLength(1);

            for (int i = 0; i < cols; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    // Add each element of the matrix to the list
                    list.Add(matrix[j, i]);
                }
            }

            return list;
        }

        int[,] transposematrix(int[,] matrix)
        {
            // This function transposes a given matrix by swapping rows with columns.

            int[,] arr2 = new int[matrix.GetLength(0), matrix.GetLength(1)];

            for (int i = 0; i < matrix.GetLength(1); i++)
            {
                for (int j = 0; j < matrix.GetLength(0); j++)
                {
                    // Swap elements between rows and columns to obtain the transpose
                    arr2[j, i] = matrix[i, j];
                }
            }

            return arr2;
        }

        int[,] matrixMultiplication(int[,] matrix1, int[,] matrix2)
        {
            // This function performs matrix multiplication between two matrices 'matrix1' and 'matrix2'.

            int rows1 = matrix1.GetLength(0), cols1 = matrix1.GetLength(1);
            int rows2 = matrix2.GetLength(0), cols2 = matrix2.GetLength(1);

            if (cols1 != rows2)
            {
                // Matrices cannot be multiplied if the number of columns of the first matrix is not equal to the number of rows of the second matrix
                Console.WriteLine("Matrices cannot be multiplied");
            }

            int[,] result = new int[rows1, cols2];

            for (int i = 0; i < rows1; i++)
            {
                for (int j = 0; j < cols2; j++)
                {
                    for (int k = 0; k < cols1; k++)
                    {
                        // Perform the dot product of rows of the first matrix with columns of the second matrix
                        // The result is taken modulo 26 to ensure it stays within the range of alphabets (A-Z)
                        result[i, j] = ((result[i, j] + matrix1[i, k] * matrix2[k, j]) + 26000) % 26;
                    }
                }
            }

            return result;
        }
        int get_det(int[,] matrix, int m)
        {
            if (m == 3)
            {
                // Calculate determinant for a 3x3 matrix
                int det = 0;
                det += matrix[0, 0] * matrix[1, 1] * matrix[2, 2];
                det += matrix[0, 1] * matrix[1, 2] * matrix[2, 0];
                det += matrix[0, 2] * matrix[1, 0] * matrix[2, 1];
                det -= matrix[0, 2] * matrix[1, 1] * matrix[2, 0];
                det -= matrix[0, 1] * matrix[1, 0] * matrix[2, 2];
                det -= matrix[0, 0] * matrix[1, 2] * matrix[2, 1];
                det = (det + 26000) % 26; // Apply modular arithmetic
                return det;
            }
            else
            {
                // Calculate determinant for a 2x2 matrix
                return ((matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0]) + 26000) % 26;
            }
        }

        bool gcd(int det)
        {
            // This function checks if the greatest common divisor (GCD) of 'det' and 26 is equal to 1.
            // It returns true if the GCD is 1, indicating that 'det' is relatively prime to 26.

            int a = 26, b = det;

            while (b != 0)
            {
                int temp = b;
                b = a % b;
                a = temp;
            }

            int gcd = a;

            // Check if the GCD is 1
            if (gcd == 1)
                return true;
            else
                return false;
        }

        bool matrix_is_invertable(int[,] matrix, int m)
        {
            int det = get_det(matrix, m);
            bool x = true;
            int b = get_b(det);
            // Check if any element of the matrix is outside the range of 0 to 26
            for (int i = 0; i < matrix.GetLength(1); i++)
            {
                for (int j = 0; j < matrix.GetLength(0); j++)
                {
                    if (matrix[i, j] < 0 || matrix[i, j] > 26)
                    {
                        x = false;
                        break;
                    }
                }
            }
            // Check if the determinant is zero, the determinant's modular multiplicative inverse exists,
            // all elements of the matrix are within the valid range, and the modular multiplicative inverse is within the valid range
            if (det == 0 || !gcd(det) || !x || b > 26 || b < 0)
                return false;
            else
                return true;
        }
        // Method to calculate the inverse of a matrix of size 3x3
        int[,] inverse3(int[,] matrix, int m)
        {
            // Calculate the determinant and the modular multiplicative inverse of the determinant
            int b = get_b(get_det(matrix, m));

            int[,] result = new int[matrix.GetLength(0), matrix.GetLength(1)];

            // Calculate the adjugate of the matrix
            result[0, 0] = ((matrix[1, 1] * matrix[2, 2] - matrix[1, 2] * matrix[2, 1]) + 26000) % 26;
            result[0, 1] = (((matrix[1, 0] * matrix[2, 2] - matrix[1, 2] * matrix[2, 0]) * -1) + 26000) % 26;
            result[0, 2] = ((matrix[1, 0] * matrix[2, 1] - matrix[1, 1] * matrix[2, 0]) + 26000) % 26;
            result[1, 0] = (((matrix[0, 1] * matrix[2, 2] - matrix[0, 2] * matrix[2, 1]) * -1) + 26000) % 26;
            result[1, 1] = ((matrix[0, 0] * matrix[2, 2] - matrix[0, 2] * matrix[2, 0]) + 26000) % 26;
            result[1, 2] = (((matrix[0, 0] * matrix[2, 1] - matrix[0, 1] * matrix[2, 0]) * -1) + 26000) % 26;
            result[2, 0] = ((matrix[0, 1] * matrix[1, 2] - matrix[1, 1] * matrix[0, 2]) + 26000) % 26;
            result[2, 1] = (((matrix[0, 0] * matrix[1, 2] - matrix[1, 0] * matrix[0, 2]) * -1) + 26000) % 26;
            result[2, 2] = ((matrix[1, 1] * matrix[0, 0] - matrix[1, 0] * matrix[0, 1]) + 26000) % 26;

            int[,] res = transposematrix(result);

            // Multiply each element by the modular multiplicative inverse of the determinant
            for (int i = 0; i < res.GetLength(0); i++)
            {
                for (int j = 0; j < res.GetLength(1); j++)
                {
                    res[i, j] = b * (res[i, j]) % 26;
                }
            }

            return res;
        }

        // Method to calculate the inverse of a matrix of size 2x2
        int[,] inverse2(int[,] matrix)
        {
            int[,] inverse = new int[2, 2];

            // Calculate the determinant and the modular multiplicative inverse of the determinant
            int det = get_det(matrix, 2);
            int b = get_b(det);

            // Calculate the adjugate of the matrix
            inverse[0, 0] = matrix[1, 1];
            inverse[0, 1] = ((-1 * matrix[0, 1]) + 26000) % 26;
            inverse[1, 0] = ((-1 * matrix[1, 0]) + 26000) % 26;
            inverse[1, 1] = matrix[0, 0];

            // Multiply each element by the modular multiplicative inverse of the determinant
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    inverse[i, j] = (b * inverse[i, j]) % 26;
                }
            }

            return inverse;
        }

        // Method to multiply two matrices
        List<int> multiplyMatrices(int[,] key, int[,] plain, int m, int n)
        {
            int[] result = new int[m * n];
            List<int> res = new List<int>();

            // Perform matrix multiplication
            for (int j = 0; j < n; j++)
            {
                for (int i = 0; i < m; i++)
                {
                    result[i * n + 0] = 0;
                    for (int k = 0; k < m; k++)
                    {
                        result[i * n + j] += key[i, k] * plain[k, j];
                    }
                    result[i * n + j] = result[i * n + j] % 26;
                    res.Add(result[i * n + j]);
                }
            }

            return res;
        }

        // Method to convert a list to a matrix by columns
        static int[,] listToMatrixbyCols(List<int> plain, int m)
        {
            int n = plain.Count / m, key_length = 0;
            int[,] arr = new int[m, n];

            // Fill the matrix column by column
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    arr[j, i] = plain[key_length];
                    key_length++;
                }
            }

            return arr;
        }

        // Method to convert a list to a matrix by rows
        static int[,] listToMatrixRows(List<int> key)
        {
            int m = (int)Math.Sqrt(key.Count), key_length = 0;
            int[,] arr = new int[m, m];

            // Fill the matrix row by row
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    arr[i, j] = key[key_length];
                    key_length++;
                }
            }

            return arr;
        }
    }
    }
