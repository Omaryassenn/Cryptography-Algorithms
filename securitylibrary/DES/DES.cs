using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            List<int> cipher_list = initial_permutation(cipherText);
            int round = 16;

            List<int> cipher_R = new List<int>();
            List<int> cipher_L = new List<int>();
            List<int> tmp ;

            for (int i = 0; i < 32; i++)
            {
                cipher_L.Add(cipher_list[i]);
                cipher_R.Add(cipher_list[i + 32]);
            }
            for (; round > 0; round--)
            {
                List<int> keyOfRound = permuted_choice1(key, round);
                tmp = cipher_R;
                cipher_R = round1(cipher_R, cipher_L, keyOfRound);
                cipher_L = tmp;



            }
            cipher_list.Clear();
            cipher_list.AddRange(cipher_R);
            cipher_list.AddRange(cipher_L);
            List<int> result = new List<int>();
            for (int i = 0; i < cipher_list.Count; i++)
            {
                result.Add(cipher_list[final_permutation[i] - 1]);
            }
            int j = 0;
            string hex = "0x";
            while (j < result.Count)
            {
                string binaryNumber = "";
                for (int f = 0; f < 4; f++, j++)
                {
                    binaryNumber += result[j];
                }

                hex += bintohex(binaryNumber);

            }
            return hex;
        }

        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            List<int> plain_list = initial_permutation(plainText);
            int round = 1;

            List<int> plain_R = new List<int>();
            List<int> plain_L = new List<int>();
            List<int> tmp = new List<int>();

            for (int i = 0; i < 32; i++)
            {
                plain_L.Add(plain_list[i]);
                plain_R.Add(plain_list[i + 32]);
            }
            for (; round <= 16; round++)
            {
                List<int> keyOfRound = permuted_choice1(key, round);
                tmp = plain_R;
                plain_R = round1(plain_R, plain_L, keyOfRound);
                plain_L = tmp;



            }
            plain_list.Clear();
            plain_list.AddRange(plain_R);
            plain_list.AddRange(plain_L);
            List<int> result = new List<int>();
            for (int i = 0; i < plain_list.Count; i++)
            {
                result.Add(plain_list[final_permutation[i] - 1]);
            }
            int j = 0;
            string hex = "0x";
            while (j < result.Count)
            {
                string binaryNumber = "";
                for (int f = 0; f < 4; f++, j++)
                {
                    binaryNumber += result[j];
                }

                hex += bintohex(binaryNumber);

            }
            return hex;
        }

        public static char bintohex(string bin)
        {
            char res = ' ';
            switch (bin)
            {
                case "0000":
                    res = '0';
                    break;
                case "0001":
                    res = '1';
                    break;
                case "0010":
                    res = '2';
                    break;
                case "0011":
                    res = '3';
                    break;
                case "0100":
                    res = '4';
                    break;
                case "0101":
                    res = '5';
                    break;
                case "0110":
                    res = '6';
                    break;
                case "0111":
                    res = '7';
                    break;
                case "1000":
                    res = '8';
                    break;
                case "1001":
                    res = '9';
                    break;
                case "1010":
                    res = 'A';
                    break;
                case "1011":
                    res = 'B';
                    break;
                case "1100":
                    res = 'C';
                    break;
                case "1101":
                    res = 'D';
                    break;
                case "1110":
                    res = 'E';
                    break;
                case "1111":

                    res = 'F';
                    break;


            }
            return res;
        }

        public static readonly List<int> final_permutation = new List<int>
        {
            40 ,    8  , 48,    16,    56   ,24,    64,   32,
            39  ,   7,   47,    15,    55,   23,    63,   31,
            38,     6,   46,    14,    54,   22,    62,   30,
            37,     5 ,  45,    13,    53,   21,    61,   29,
            36,     4,   44,    12,    52,   20,    60,   28,
            35 ,    3,   43,    11,    51,   19,    59,   27,
            34  ,   2 ,  42,    10,    50,   18,    58,   26,
            33,     1,   41,     9,    49,   17,    57,   25
        };

        public static readonly int[,] SBox1 = new int[,]
        {
            { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
            {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
            {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
            { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 }
        };
        public static readonly int[,] SBox2 = new int[,]
        {
    { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
    {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
    {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
    { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 }
        };
        public static readonly int[,] SBox3 = new int[,]
        {
            {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
            {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
            {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
            { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
        };
        public static readonly int[,] SBox4 = new int[,]
{
    { 7 ,13 ,14 ,3 ,0, 6 ,9 ,10 ,1 ,2 ,8 ,5 ,11 ,12 ,4, 15},
    { 13, 8 ,11 ,5 ,6 ,15 ,0 ,3 ,4 ,7 ,2 ,12 ,1 ,10, 14, 9},
    { 10, 6 ,9 ,0 ,12 ,11 ,7 ,13 ,15 ,1 ,3 ,14 ,5, 2, 8, 4},
    { 3 ,15 ,0 ,6 ,10 ,1 ,13 ,8 ,9, 4 ,5 ,11 ,12 ,7 ,2, 14}
};
        public static readonly int[,] SBox5 = new int[,]
{
    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
    {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
    {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
    {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
};
        public static readonly int[,] SBox6 = new int[,]
{
    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
    {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
    {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
    {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}

};
        public static readonly int[,] SBox7 = new int[,]
        {
               {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
               {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
               {1, 4, 11, 13, 12, 3, 7, 14 ,10, 15, 6, 8 ,0, 5, 9, 2 },
               {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0 ,15, 14 ,2, 3 ,12}
        };
        public static readonly int[,] SBox8 = new int[,]
        {
           {13, 2, 8, 4 ,6 ,15 ,11, 1, 10, 9 ,3, 14, 5, 0, 12, 7},
           { 1, 15, 13, 8, 10 ,3 ,7 ,4 ,12 ,5, 6, 11 ,0 ,14 ,9 ,2},
           { 7, 11, 4, 1, 9, 12, 14 ,2 ,0, 6, 10, 13, 15 ,3 ,5 ,8},
           { 2, 1, 14, 7, 4, 10, 8, 13, 15 ,12, 9 ,0 ,3 ,5 ,6 ,11}
        };
        public static readonly List<int> final_p = new List<int>
        {

                         16,   7,  20,  21,
                         29 , 12,  28,  17,
                          1 , 15 , 23 , 26,
                          5  ,18 , 31,  10,
                          2  , 8 , 24,  14,
                         32 , 27 ,  3  , 9,
                         19  ,13 , 30 , 6,
                         22  ,11 ,  4 , 25,
        };

        public static List<int> round1(List<int> Right, List<int> Left, List<int> key)
        {
            List<int> ER_KEY = new List<int>();
            List<int> res = new List<int>();
            List<int> E_R = exepension(Right);
            for (int i = 0; i < E_R.Count; i++)
            {
                ER_KEY.Add(E_R[i] ^ key[i]);
                //  Console.Write(ER_KEY[i] + "  ");
            }
            int x = 0;


            List<int> ER32 = new List<int>();

            while (x < 8)
            {
                int row_num; int col_num; int decimal_num;
                List<int> tmp = new List<int>();
                string row_ = "";
                string col_ = "";

                switch (x)
                {
                    case 0:

                        row_ += ER_KEY[0];
                        row_ += ER_KEY[5];
                        col_ += ER_KEY[1];
                        col_ += ER_KEY[2];
                        col_ += ER_KEY[3];
                        col_ += ER_KEY[4];
                        row_num = Convert.ToInt32(row_, 2);
                        col_num = Convert.ToInt32(col_, 2);
                        decimal_num = SBox1[row_num, col_num];
                        while (decimal_num > 0)
                        {
                            tmp.Insert(0, decimal_num % 2);
                            decimal_num /= 2;
                        }
                        while (tmp.Count < 4) { tmp.Insert(0, 0); }
                        ER32.AddRange(tmp);

                        for (int i = 0; i < 6; i++)
                        {
                            ER_KEY.RemoveAt(0);
                        }
                        x++;
                        break;
                    case 1:
                        row_ += ER_KEY[0];
                        row_ += ER_KEY[5];
                        col_ += ER_KEY[1];
                        col_ += ER_KEY[2];
                        col_ += ER_KEY[3];
                        col_ += ER_KEY[4];
                        row_num = Convert.ToInt32(row_, 2);
                        col_num = Convert.ToInt32(col_, 2);
                        decimal_num = SBox2[row_num, col_num];
                        while (decimal_num > 0)
                        {
                            tmp.Insert(0, decimal_num % 2);
                            decimal_num /= 2;
                        }
                        while (tmp.Count < 4) { tmp.Insert(0, 0); }
                        ER32.AddRange(tmp);

                        for (int i = 0; i < 6; i++)
                        {
                            ER_KEY.RemoveAt(0);
                        }
                        x++;
                        break;
                    case 2:
                        row_ += ER_KEY[0];
                        row_ += ER_KEY[5];
                        col_ += ER_KEY[1];
                        col_ += ER_KEY[2];
                        col_ += ER_KEY[3];
                        col_ += ER_KEY[4];
                        row_num = Convert.ToInt32(row_, 2);
                        col_num = Convert.ToInt32(col_, 2);
                        decimal_num = SBox3[row_num, col_num];
                        while (decimal_num > 0)
                        {
                            tmp.Insert(0, decimal_num % 2);
                            decimal_num /= 2;
                        }
                        while (tmp.Count < 4) { tmp.Insert(0, 0); }
                        ER32.AddRange(tmp);

                        for (int i = 0; i < 6; i++)
                        {
                            ER_KEY.RemoveAt(0);
                        }
                        x++;
                        break;
                    case 3:
                        row_ += ER_KEY[0];
                        row_ += ER_KEY[5];
                        col_ += ER_KEY[1];
                        col_ += ER_KEY[2];
                        col_ += ER_KEY[3];
                        col_ += ER_KEY[4];
                        row_num = Convert.ToInt32(row_, 2);
                        col_num = Convert.ToInt32(col_, 2);
                        decimal_num = SBox4[row_num, col_num];
                        while (decimal_num > 0)
                        {
                            tmp.Insert(0, decimal_num % 2);
                            decimal_num /= 2;
                        }
                        while (tmp.Count < 4) { tmp.Insert(0, 0); }
                        ER32.AddRange(tmp);

                        for (int i = 0; i < 6; i++)
                        {
                            ER_KEY.RemoveAt(0);
                        }
                        x++;
                        break;
                    case 4:
                        row_ += ER_KEY[0];
                        row_ += ER_KEY[5];
                        col_ += ER_KEY[1];
                        col_ += ER_KEY[2];
                        col_ += ER_KEY[3];
                        col_ += ER_KEY[4];
                        row_num = Convert.ToInt32(row_, 2);
                        col_num = Convert.ToInt32(col_, 2);
                        decimal_num = SBox5[row_num, col_num];
                        while (decimal_num > 0)
                        {
                            tmp.Insert(0, decimal_num % 2);
                            decimal_num /= 2;
                        }
                        while (tmp.Count < 4) { tmp.Insert(0, 0); }
                        ER32.AddRange(tmp);

                        for (int i = 0; i < 6; i++)
                        {
                            ER_KEY.RemoveAt(0);
                        }
                        x++;
                        break;
                    case 5:
                        row_ += ER_KEY[0];
                        row_ += ER_KEY[5];
                        col_ += ER_KEY[1];
                        col_ += ER_KEY[2];
                        col_ += ER_KEY[3];
                        col_ += ER_KEY[4];
                        row_num = Convert.ToInt32(row_, 2);
                        col_num = Convert.ToInt32(col_, 2);
                        decimal_num = SBox6[row_num, col_num];
                        while (decimal_num > 0)
                        {
                            tmp.Insert(0, decimal_num % 2);
                            decimal_num /= 2;
                        }
                        while (tmp.Count < 4) { tmp.Insert(0, 0); }
                        ER32.AddRange(tmp);

                        for (int i = 0; i < 6; i++)
                        {
                            ER_KEY.RemoveAt(0);
                        }
                        x++;
                        break;
                    case 6:
                        row_ += ER_KEY[0];
                        row_ += ER_KEY[5];
                        col_ += ER_KEY[1];
                        col_ += ER_KEY[2];
                        col_ += ER_KEY[3];
                        col_ += ER_KEY[4];
                        row_num = Convert.ToInt32(row_, 2);
                        col_num = Convert.ToInt32(col_, 2);
                        decimal_num = SBox7[row_num, col_num];
                        while (decimal_num > 0)
                        {
                            tmp.Insert(0, decimal_num % 2);
                            decimal_num /= 2;
                        }
                        while (tmp.Count < 4) { tmp.Insert(0, 0); }
                        ER32.AddRange(tmp);

                        for (int i = 0; i < 6; i++)
                        {
                            ER_KEY.RemoveAt(0);
                        }
                        x++;
                        break;
                    case 7:
                        row_ += ER_KEY[0];
                        row_ += ER_KEY[5];
                        col_ += ER_KEY[1];
                        col_ += ER_KEY[2];
                        col_ += ER_KEY[3];
                        col_ += ER_KEY[4];
                        row_num = Convert.ToInt32(row_, 2);
                        col_num = Convert.ToInt32(col_, 2);
                        decimal_num = SBox8[row_num, col_num];
                        while (decimal_num > 0)
                        {
                            tmp.Insert(0, decimal_num % 2);
                            decimal_num /= 2;
                        }
                        while (tmp.Count < 4) { tmp.Insert(0, 0); }
                        ER32.AddRange(tmp);

                        for (int i = 0; i < 6; i++)
                        {
                            ER_KEY.RemoveAt(0);
                        }
                        x++;
                        break;






                }

            }
            for (int i = 0; i < final_p.Count; i++)
            {
                res.Add(ER32[final_p[i] - 1]);
            }
            List<int> final55555 = new List<int>();
            for (int i = 0; i < Left.Count; i++)
            {
                final55555.Add(res[i] ^ Left[i]);
                //  Console.Write(ER_KEY[i] + "  ");
            }







            return final55555;



        }

        public static List<int> exepension(List<int> Right)
        {
            List<int> res = new List<int>();
            List<int> E_table = new List<int>();
            E_table.Add(32); E_table.Add(1); E_table.Add(2); E_table.Add(3); E_table.Add(4); E_table.Add(5);
            E_table.Add(4); E_table.Add(5); E_table.Add(6); E_table.Add(7); E_table.Add(8); E_table.Add(9);
            E_table.Add(8); E_table.Add(9); E_table.Add(10); E_table.Add(11); E_table.Add(12); E_table.Add(13);
            E_table.Add(12); E_table.Add(13); E_table.Add(14); E_table.Add(15); E_table.Add(16); E_table.Add(17);
            E_table.Add(16); E_table.Add(17); E_table.Add(18); E_table.Add(19); E_table.Add(20); E_table.Add(21);
            E_table.Add(20); E_table.Add(21); E_table.Add(22); E_table.Add(23); E_table.Add(24); E_table.Add(25);
            E_table.Add(24); E_table.Add(25); E_table.Add(26); E_table.Add(27); E_table.Add(28); E_table.Add(29);
            E_table.Add(28); E_table.Add(29); E_table.Add(30); E_table.Add(31); E_table.Add(32); E_table.Add(1);
            for (int i = 0; i < E_table.Count; i++)
            {
                res.Add(Right[E_table[i] - 1]);
            }

            return res;

        }
        public static List<int> permuted_choice2(List<int> key)
        {
            List<int> pc2 = PC2_table();
            List<int> res = new List<int>();
            for (int i = 0; i < pc2.Count; i++)
            {
                res.Add(key[pc2[i] - 1]);
            }
            return res;
        }


        public static List<int> left_circular_shift(List<int> C, List<int> D, int round)
        {
            List<int> shift = new List<int>();
            shift.Add(1); shift.Add(1); shift.Add(2); shift.Add(2);
            shift.Add(2); shift.Add(2); shift.Add(2); shift.Add(2);
            shift.Add(1); shift.Add(2); shift.Add(2); shift.Add(2);
            shift.Add(2); shift.Add(2); shift.Add(2); shift.Add(1);
            for (int i = 0; i < shift[round - 1]; i++)
            {
                C.Add(C[0]);
                C.RemoveAt(0);
                D.Add(D[0]);
                D.RemoveAt(0);

            }
            List<int> res = new List<int>();
            foreach (var i in C)
            {
                res.Add(i);
            }
            foreach (var i in D)
            {
                res.Add(i);
            }
            return res;



        }

        public static List<int> permuted_choice1(string key, int round)
        {
            List<int> binary_key = HexToBin(key);
            List<int> result_c = new List<int>();
            List<int> result_d = new List<int>();
            List<int> C = C_table();
            List<int> D = D_table();
            for (int i = 0; i < C.Count; i++)
            {
                result_c.Add(binary_key[C[i] - 1]);
                //  Console.Write(result_c[i] + "  ");
            }
            // Console.WriteLine("///////");
            for (int i = 0; i < D.Count; i++)
            {
                result_d.Add(binary_key[D[i] - 1]);
                //Console.Write(result_d[i] + "  ");
            }
            List<int> shifted_key = new List<int>();
            for (int i = 0; i < round; i++)
            {

                shifted_key = left_circular_shift(result_c, result_d, i + 1);
                result_c.Clear(); result_d.Clear();
                for (int j = 0; j < 28; j++)
                {
                    result_c.Add(shifted_key[j]);
                    result_d.Add(shifted_key[j + 28]);
                }


            }


            List<int> keyOfRound = permuted_choice2(shifted_key);
            return keyOfRound;


        }
        public static List<int> initial_permutation(string plainText)
        {
            List<int> initial_table = ip_table();
            List<int> binary_plain = HexToBin(plainText);
            List<int> result = new List<int>();
            for (int i = 0; i < binary_plain.Count; i++)
            {
                result.Add(binary_plain[initial_table[i] - 1]);
            }

            return result;

        }

        public static List<int> PC2_table()
        {
            List<int> r = new List<int>();


            r.Add(14); r.Add(17); r.Add(11); r.Add(24); r.Add(1); r.Add(5);
            r.Add(3); r.Add(28); r.Add(15); r.Add(6); r.Add(21); r.Add(10);
            r.Add(23); r.Add(19); r.Add(12); r.Add(4); r.Add(26); r.Add(8);
            r.Add(16); r.Add(7); r.Add(27); r.Add(20); r.Add(13); r.Add(2);
            r.Add(41); r.Add(52); r.Add(31); r.Add(37); r.Add(47); r.Add(55);
            r.Add(30); r.Add(40); r.Add(51); r.Add(45); r.Add(33); r.Add(48);
            r.Add(44); r.Add(49); r.Add(39); r.Add(56); r.Add(34); r.Add(53);
            r.Add(46); r.Add(42); r.Add(50); r.Add(36); r.Add(29); r.Add(32);

            return r;

        }
        public static List<int> C_table()
        {
            List<int> r = new List<int>();


            r.Add(57); r.Add(49); r.Add(41); r.Add(33); r.Add(25); r.Add(17); r.Add(9);
            r.Add(1); r.Add(58); r.Add(50); r.Add(42); r.Add(34); r.Add(26); r.Add(18);
            r.Add(10); r.Add(2); r.Add(59); r.Add(51); r.Add(43); r.Add(35); r.Add(27);
            r.Add(19); r.Add(11); r.Add(3); r.Add(60); r.Add(52); r.Add(44); r.Add(36);

            return r;

        }
        public static List<int> D_table()
        {
            List<int> r = new List<int>();

            r.Add(63); r.Add(55); r.Add(47); r.Add(39); r.Add(31); r.Add(23); r.Add(15);
            r.Add(7); r.Add(62); r.Add(54); r.Add(46); r.Add(38); r.Add(30); r.Add(22);
            r.Add(14); r.Add(6); r.Add(61); r.Add(53); r.Add(45); r.Add(37); r.Add(29);
            r.Add(21); r.Add(13); r.Add(5); r.Add(28); r.Add(20); r.Add(12); r.Add(4);

            return r;

        }

        public static List<int> ip_table()
        {
            List<int> r = new List<int>();
            r.Add(58); r.Add(50); r.Add(42); r.Add(34); r.Add(26); r.Add(18); r.Add(10); r.Add(2); r.Add(60); r.Add(52); r.Add(44); r.Add(36); r.Add(28); r.Add(20); r.Add(12); r.Add(4);
            r.Add(62); r.Add(54); r.Add(46); r.Add(38); r.Add(30); r.Add(22); r.Add(14); r.Add(6); r.Add(64); r.Add(56); r.Add(48); r.Add(40); r.Add(32); r.Add(24); r.Add(16); r.Add(8);
            r.Add(57); r.Add(49); r.Add(41); r.Add(33); r.Add(25); r.Add(17); r.Add(9); r.Add(1); r.Add(59); r.Add(51); r.Add(43); r.Add(35); r.Add(27); r.Add(19); r.Add(11); r.Add(3);
            r.Add(61); r.Add(53); r.Add(45); r.Add(37); r.Add(29); r.Add(21); r.Add(13); r.Add(5); r.Add(63); r.Add(55); r.Add(47); r.Add(39); r.Add(31); r.Add(23); r.Add(15); r.Add(7);


            return r;
        }


        public static List<int> HexToBin(string hexdec)
        {
            int i = 2;
            List<int> res = new List<int>();

            while (i < hexdec.Length)
            {

                switch (hexdec[i])
                {
                    case '0':
                        res.Add(0);
                        res.Add(0);
                        res.Add(0);
                        res.Add(0);
                        break;
                    case '1':
                        res.Add(0);
                        res.Add(0);
                        res.Add(0);
                        res.Add(1);
                        break;
                    case '2':
                        res.Add(0);
                        res.Add(0);
                        res.Add(1);
                        res.Add(0);
                        break;
                    case '3':
                        res.Add(0);
                        res.Add(0);
                        res.Add(1);
                        res.Add(1);
                        break;
                    case '4':
                        res.Add(0);
                        res.Add(1);
                        res.Add(0);
                        res.Add(0);
                        break;
                    case '5':
                        res.Add(0);
                        res.Add(1);
                        res.Add(0);
                        res.Add(1);
                        break;
                    case '6':
                        res.Add(0);
                        res.Add(1);
                        res.Add(1);
                        res.Add(0);
                        break;
                    case '7':
                        res.Add(0);
                        res.Add(1);
                        res.Add(1);
                        res.Add(1);
                        break;
                    case '8':
                        res.Add(1);
                        res.Add(0);
                        res.Add(0);
                        res.Add(0);
                        break;
                    case '9':
                        res.Add(1);
                        res.Add(0);
                        res.Add(0);
                        res.Add(1);
                        break;
                    case 'A':
                    case 'a':
                        res.Add(1);
                        res.Add(0);
                        res.Add(1);
                        res.Add(0);
                        break;
                    case 'B':
                    case 'b':
                        res.Add(1);
                        res.Add(0);
                        res.Add(1);
                        res.Add(1);
                        break;
                    case 'C':
                    case 'c':
                        res.Add(1);
                        res.Add(1);
                        res.Add(0);
                        res.Add(0);
                        break;
                    case 'D':
                    case 'd':
                        res.Add(1);
                        res.Add(1);
                        res.Add(0);
                        res.Add(1);
                        break;
                    case 'E':
                    case 'e':
                        res.Add(1);
                        res.Add(1);
                        res.Add(1);
                        res.Add(0);
                        break;
                    case 'F':
                    case 'f':
                        res.Add(1);
                        res.Add(1);
                        res.Add(1);
                        res.Add(1);
                        break;
                    default:
                        continue;

                }
                i++;
            }
            return res;
        }


    }
}