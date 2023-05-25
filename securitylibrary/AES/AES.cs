using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        static int[,] S_box_Inverse = new int[16, 16] {
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
        };

        int[,] S_box = new int[16, 16] {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
            {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
            {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
            {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
            {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
            {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
            {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
            {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
            {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
            {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
            {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
            {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
            {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
            {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
            {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
        };

        int[,] RC = new int[4, 10] {
            {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};




        int[,] Mix_Mat = new int[4, 4] {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}};

        int[,] Inverse_Mix_Mat = new int[4, 4] {
            {0x0e, 0x0b, 0x0d, 0x09},
            {0x09, 0x0e, 0x0b, 0x0d},
            {0x0d, 0x09, 0x0e, 0x0b},
            {0x0b, 0x0d, 0x09, 0x0e}};
        int[,] key_extra = new int[44, 4];


        static string _1b = "00011011";
        int[,] round_plain(string plain_text)
        {
            int[,] arr = new int[4, 4];
            int cnt = 2;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    arr[j, i] = Convert.ToInt32(("0x" + plain_text[cnt++] + plain_text[cnt++]), 16);
            return arr;
        }
        void add_key_to_arr(string key)
        {
            int[,] key_arr = new int[4, 4];
            key_arr = round_key(key);
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    key_extra[i, j] = key_arr[i, j];
        }
        int[,] round_key(string key)
        {
            int[,] arr = new int[4, 4];
            int cnt = 2;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    arr[i, j] = Convert.ToInt32(("0x" + key[cnt++] + key[cnt++]), 16);
            return arr;
        }
        int RC_ind = 0;
        void key_round_to_start()
        {
            int[] col_3 = new int[4];
            int[] f_col_key = new int[4];
            int[] col_rson = new int[4];
            int[] res = new int[4];

            for (int i = 4; i < 44; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    col_3[j] = key_extra[i - 1, j];

                    f_col_key[j] = key_extra[i - 4, j];

                    if (RC_ind < 10)
                        col_rson[j] = RC[j, RC_ind];
                }


                if (i % 4 == 0)
                {
                    col_3 = Rotate_colmun(col_3);
                    col_3 = Substitude_Col(col_3);
                    res = xor(col_3, f_col_key, col_rson, true);
                    RC_ind++;
                }
                else
                    res = xor(col_3, f_col_key, col_rson, false);

                for (int j = 0; j < 4; j++)
                {
                    key_extra[i, j] = res[j];
                }
            }
        }
        int[] Rotate_colmun(int[] col)
        {

            int Temp = col[0];
            for (int i = 0; i < 3; i++)
                col[i] = col[i + 1];
            col[3] = Temp;
            return col;
        }
        int[] xor(int[] col, int[] f_col_key, int[] col_rson, bool is_4)
        {
            int[] res = new int[4];
            for (int i = 0; i < 4; i++)
            {
                string value;

                if (is_4 == true)
                    value = Convert.ToString(col[i] ^ f_col_key[i] ^ col_rson[i], 16);
                else
                    value = Convert.ToString(col[i] ^ f_col_key[i], 16);

                res[i] = Convert.ToInt32(value, 16);
            }
            return res;
        }
        int[] Substitude_Col(int[] col)
        {
            int[] res = new int[4];

            int I_s_box;
            int j_s_box;
            for (int i = 0; i < 4; i++)
            {

                string value = Convert.ToString(col[i], 16);
                if (value.Length == 1)
                {
                    I_s_box = 0;

                    j_s_box = Convert.ToInt32(value[0].ToString(), 16);
                }
                else
                {

                    I_s_box = Convert.ToInt32(value[0].ToString(), 16);
                    j_s_box = Convert.ToInt32(value[1].ToString(), 16);
                }

                res[i] = S_box[I_s_box, j_s_box];
            }
            return res;
        }
        int[,] round_dec(int[,] arr, int Number_of_round, int Number_dec_round)
        {
            arr = RoundKey(arr, Number_of_round);

            if (Number_dec_round == 0)
            {
                arr = mix_Cols_Inverse(arr);
            }
            arr = shift_left(arr, 1);
            arr = substitute_matrix_4_4(arr, 1);
            return arr;
        }
        int[,] get_key(int index_of_round)
        {
            int[,] arr = new int[4, 4];
            int r = 0;
            for (int i = index_of_round * 4; i < index_of_round * 4 + 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    arr[j, r] = key_extra[i, j];
                }
                r++;
            }
            return arr;
        }
        int[,] RoundKey(int[,] matrix, int Round_index)
        {
            int[,] key_round;
            key_round = get_key(Round_index);
            string Temp;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    Temp = Convert.ToString(key_round[i, j] ^ matrix[i, j], 16);
                    key_round[i, j] = Convert.ToInt32(Temp, 16);
                }
            }
            return key_round;
        }
        int[,] f_Round_Dec(int[,] Rounded_Cip)
        {
            Rounded_Cip = RoundKey(Rounded_Cip, 0);
            return Rounded_Cip;
        }
        public override string Decrypt(string cipherText, string key)
        {
            int[,] Rounded_Cip = round_plain(cipherText);
            add_key_to_arr(key);

            key_round_to_start();

            Rounded_Cip = round_dec(Rounded_Cip, 10, 1);
            int i = 10;
            while (--i != 0)
            {
                Rounded_Cip = round_dec(Rounded_Cip, i, 0);
            }

            Rounded_Cip = f_Round_Dec(Rounded_Cip);
            string s = conv_Mat_to_String(Rounded_Cip);
            return s;
        }
        int multiply_Two(int x)
        {
            int ret;
            UInt32 temp = Convert.ToUInt32(x << 1);
            ret = (int)(temp & 0xFF);
            if (x > 127)
                ret = Convert.ToInt32(ret ^ 27);
            return ret;
        }
        int[,] mix_Cols_Inverse(int[,] Shifted_mat)
        {
            int[] array_of_Xor = new int[4];
            int[,] mixedCols = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        int x0 = Shifted_mat[k, i];
                        int x1 = multiply_Two(x0);
                        int x2 = multiply_Two(x1);
                        int x3 = multiply_Two(x2);
                        if (Inverse_Mix_Mat[j, k] == 0x9)
                        {
                            array_of_Xor[k] = x3 ^ x0;
                        }
                        else if (Inverse_Mix_Mat[j, k] == 0xB)
                        {
                            array_of_Xor[k] = x3 ^ x0 ^ x1;
                        }
                        else if (Inverse_Mix_Mat[j, k] == 0xD)
                        {
                            array_of_Xor[k] = x3 ^ x2 ^ x0;

                        }

                        else if (Inverse_Mix_Mat[j, k] == 0xE)
                        {
                            array_of_Xor[k] = x3 ^ x2 ^ x1;
                        }
                    }

                    int mult = array_of_Xor[0] ^ array_of_Xor[1] ^ array_of_Xor[2] ^ array_of_Xor[3];
                    mixedCols[j, i] = mult;
                }
            }
            return mixedCols;
        }
        int[,] shift_left(int[,] mat, int inverse)
        {
            int[,] arr = new int[4, 4];
            int[] row = new int[4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    row[j] = mat[i, j];
                }
                if (inverse == 0)

                    row = shift_Row(row, i);
                else
                    row = shift_Row_Inverse(row, i);

                for (int j = 0; j < 4; j++)
                {
                    arr[i, j] = row[j];
                }
            }
            return arr;
        }
        int[,] substitute_matrix_4_4(int[,] matrix, int Number_of_box)
        {
            int[,] arr = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string Temp = Convert.ToString(matrix[i, j], 16);
                    int I_sbox, j_sbox;
                    if (Temp.Length == 1)
                    {
                        I_sbox = 0;
                        j_sbox = Convert.ToInt32(Temp[0].ToString(), 16);
                    }
                    else
                    {
                        I_sbox = Convert.ToInt32(Temp[0].ToString(), 16);
                        j_sbox = Convert.ToInt32(Temp[1].ToString(), 16);
                    }

                    if (Number_of_box == 0)
                        arr[i, j] = S_box[I_sbox, j_sbox];
                    else
                        arr[i, j] = S_box_Inverse[I_sbox, j_sbox];

                }
            }
            return arr;
        }
        int[] shift_Row_Inverse(int[] row, int n)
        {
            UInt32 Number = 0;
            for (int i = 0; i < 4; i++)
            {

                Number += Convert.ToUInt32(row[i]);
                if (i != 3)
                    Number = Number << 8;
            }
            Number = ((Number >> (n * 8)) | (Number) << (32 - (n * 8)));

            int[] newR = new int[4];
            int c = 4;
            while (--c != -1)
            {
                newR[c] = (int)(Number & 0xFF);
                Number = Number >> 8;
            }
            return newR;
        }
        int[] shift_Row(int[] row, int ind)
        {
            UInt32 Number = 0;
            for (int i = 0; i < 3; i++)
            {
                Number += Convert.ToUInt32(row[i]);
                Number = Number << 8;
            }
            Number += Convert.ToUInt32(row[3]);

            Number = ((Number << (ind * 8)) | (Number) >> (32 - (ind * 8)));

            int[] newR = new int[4];

            int c = 4;
            while (--c != -1)
            {
                newR[c] = (int)(Number & 0xFF);
                Number = Number >> 8;
            }
            return newR;
        }
        string conv_Mat_to_String(int[,] arr)
        {
            StringBuilder str = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    var value = Convert.ToString(arr[j, i], 16);
                    if (value.Length < 2)
                    {
                        str.Append("0" + value);
                    }
                    else str.Append(value);
                }
            }
            return str.ToString().ToUpper().Insert(0, "0x");
        }
       

        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            plainText = plainText.Remove(0, 2);
            key = key.Remove(0, 2);
            List<int> binary_plain = HexToBin(plainText);
            List<int> binary_key = HexToBin(key);
            int round = 0;

            string roundKey = AddRoundKey(binary_key, binary_plain);

            for (; round < 10; round++)
            {
                key = key_schedule(key, round);
                roundKey = encryption_process(roundKey, key, round);

            }
            string res = "0x" + roundKey;
            return res;
        }
        /**/
       
        //
        public static string encryption_process(string state, string key, int round)
        {
            //1- subbytes -> s-box
            string subbyte_res = subByte(state);
            //2-shiftrows
            string[,] shifted_state = shiftrows(subbyte_res);
            string hh = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    hh += shifted_state[j, i];
                }
            }
            //3-mix columns
            if (round != 9)
            {
                string[,] mixedCol = MixColumns(shifted_state);
                hh = "";
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        hh += mixedCol[j, i];

                    }
                }
            }
            //4-addroundkey
            List<int> binary_key = HexToBin(key);
            List<int> binary_state = HexToBin(hh);
            string rounded = AddRoundKey(binary_key, binary_state);
            return rounded;
        }
        public static string key_schedule(string key, int roundnum)
        {
            string bla = "";
            string[,] key_matrix = new string[4, 4];
            int cnt = 0;
            string[,] endCol = new string[4, 1];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (i == 3 && j == 0)
                    {
                        endCol[3, 0] += key[cnt];
                        endCol[3, 0] += key[cnt + 1];
                        key_matrix[j, i] += key[cnt];
                        key_matrix[j, i] += key[cnt + 1];
                        cnt += 2;
                    }
                    else if (i == 3 && j == 1)
                    {
                        endCol[0, 0] += key[cnt];
                        endCol[0, 0] += key[cnt + 1];
                        key_matrix[j, i] += key[cnt];
                        key_matrix[j, i] += key[cnt + 1];
                        cnt += 2;

                    }
                    else if (i == 3 && j == 2)
                    {
                        endCol[1, 0] += key[cnt];
                        endCol[1, 0] += key[cnt + 1];
                        key_matrix[j, i] += key[cnt];
                        key_matrix[j, i] += key[cnt + 1];
                        cnt += 2;

                    }
                    else if (i == 3 && j == 3)
                    {

                        endCol[2, 0] += key[cnt];
                        endCol[2, 0] += key[cnt + 1];
                        key_matrix[j, i] += key[cnt];
                        key_matrix[j, i] += key[cnt + 1];
                        cnt += 2;

                    }
                    else
                    {
                        key_matrix[j, i] += key[cnt];
                        key_matrix[j, i] += key[cnt + 1];
                        cnt += 2;

                    }
                }
            }

            //
            string endcol = "";
            endcol += endCol[0, 0]; endcol += endCol[1, 0]; endcol += endCol[2, 0]; endcol += endCol[3, 0];
            endcol = subByte(endcol);
            for (int i = 0, j = 0; i < 4; i++)
            {
                endCol[i, 0] = "";
                endCol[i, 0] += endcol[j]; endCol[i, 0] += endcol[j + 1];
                j += 2;
            }

            //
            string[,] column = new string[4, 1];
            string[,] newColumn = new string[4, 1];
            string[,] rconCol = new string[4, 1];
            string[,] roundMatrix = new string[4, 4];

            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    if (col != 0)
                    {
                        newColumn[row, 0] = roundMatrix[row, col - 1];
                    }
                    column[row, 0] = key_matrix[row, col];
                    rconCol[row, 0] = RCON[row, roundnum];
                }

                if (col == 0)
                {

                    column = XOR(column, endCol);
                    column = XOR(column, rconCol);
                }
                else
                {
                    column = XOR(column, newColumn);
                }

                for (int i = 0; i < 4; i++)
                {
                    roundMatrix[i, col] = column[i, 0];
                }

            }
            for (
                int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    bla += roundMatrix[j, i];
                }
            }
            return bla;

        }
        public static List<int> HexToBin(string hexdec)
        {
            int i = 0;
            if (hexdec.Length == 2)
            { i = 0; }
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
        public static string subByte(string state)
        {
            string result = "";
            int tmp2; int tmp;
            for (int i = 0; i < state.Length; i += 2)
            {

                tmp2 = Convert.ToInt32(state[i + 1].ToString(), 16);
                tmp = Convert.ToInt32(state[i].ToString(), 16);

                result += s_box[(tmp * 16) + tmp2];

            }
            return result;
        }
        public static readonly List<string> s_box = new List<string>() {

            "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76",
            "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0",
            "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15",
            "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75",
            "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84",
            "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf",
            "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8",
            "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2",
            "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73",
            "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db",
            "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79",
            "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08",
            "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a",
            "70", "3e", "b5", "66", "48","03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e",
            "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df",
            "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"
 };
        public static string AddRoundKey(List<int> key, List<int> plain)
        {
            List<int> xor_res = new List<int>();
            for (int i = 0; i < key.Count; i++)
            {
                xor_res.Add(key[i] ^ plain[i]);
            }
            int j = 0;
            string hex = "";
            while (j < xor_res.Count)
            {
                string binaryNumber = "";
                for (int f = 0; f < 4; f++, j++)
                {
                    binaryNumber += xor_res[j];
                }

                hex += bintohex(binaryNumber);

            }
            return hex;

        }
        public static readonly int[,] mixColumnsMatrix = new int[,] {
            { 2, 3, 1, 1 },
            {1,2,3,1 },
            {1,1,2,3 },
            {3,1,1,2 }


        };
        public static readonly string[,] RCON = new string[4, 10]
        {{"01","02","04","08","10","20","40","80","1b","36" },
          {"00","00","00","00","00","00","00","00","00","00" },
          {"00","00","00","00","00","00","00","00","00","00" },
          {"00","00","00","00","00","00","00","00","00","00" }};
        public static string[,] XOR(string[,] mat1, string[,] mat2)
        {
            //throw new NotImplementedException();
            String[,] XORMat = new string[mat1.GetLength(0), mat1.GetLength(1)];
            long num1, num2, num3;
            String result;
            for (int i = 0; i < mat1.GetLength(0); i++)
            {
                for (int j = 0; j < mat1.GetLength(1); j++)
                {
                    num1 = Convert.ToInt64(mat1[i, j], 16);
                    num2 = Convert.ToInt64(mat2[i, j], 16);
                    num3 = num1 ^ num2;
                    result = num3.ToString("X");
                    result = result.ToLower();
                    if (result.Length == 1)
                    {
                        XORMat[i, j] += "0";
                        XORMat[i, j] += result;
                    }
                    else
                    {
                        XORMat[i, j] += result;
                    }
                }
            }
            return XORMat;

        }

        public static string[,] MixColumns(string[,] matrix)
        {
            // Convert hex to binary
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    List<int> r = HexToBin(matrix[i, j]);

                    matrix[i, j] = "";
                    for (int h = 0; h < r.Count; h++)
                    {
                        matrix[i, j] += r[h];
                    }
                }
            }

            // Create a new matrix for mixed columns
            string[,] mixedCol = new string[4, 4];

            // Perform Galois Field multiplication
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // Initialize variables
                    string temp = "";
                    string[] results = new string[4];
                    string[,] tempMatrix = new string[4, 4];

                    // Copy matrix
                    for (int x = 0; x < 4; x++)
                    {
                        for (int y = 0; y < 4; y++)
                        {
                            tempMatrix[x, y] = matrix[x, y];
                        }
                    }

                    // Perform multiplication
                    for (int k = 0; k < 4; k++)
                    {
                        switch (mixColumnsMatrix[j, k])
                        {
                            case 2:
                                results[k] = times2_binary(tempMatrix[k, i]);
                                break;
                            case 3:
                                temp = matrix[k, i];
                                results[k] = times2_binary(tempMatrix[k, i]);
                                break;
                            case 1:
                                results[k] = matrix[k, i];
                                break;
                        }
                    }

                    // XOR the results
                    var cell = results.Skip(1).Aggregate(results.First(), (a, b) => xorBinary(a, b));
                    cell = xorBinary(cell, temp);


                    // Convert binary to hex

                    for (int l = 0; l < cell.Length; l += 4)
                    {
                        mixedCol[j, i] += bintohex(cell.Substring(l, 4));

                    }
                }
            }

            return mixedCol;
        }
        public static string times2_binary(string val)
        {
            //throw new NotImplementedException();
            string temp_val = val;
            bool check1 = false;
            if (val.ElementAt(0) == '1')
            {
                check1 = true;
            }
            temp_val = temp_val.Remove(0, 1);
            temp_val = temp_val.Insert(temp_val.Length, "0");

            if (check1)
            {
                //xor
                temp_val = xorBinary_gf2(temp_val);
            }
            return temp_val;
        }
        public static string xorBinary(string str1, string str2)
        {
            for (int m = 0; m < str1.Length; m++)
            {
                if (str1.ElementAt(m) == str2.ElementAt(m))
                {
                    str1 = str1.Remove(m, 1);
                    str1 = str1.Insert(m, "0");
                }
                else
                {
                    str1 = str1.Remove(m, 1);
                    str1 = str1.Insert(m, "1");
                }
            }
            return str1;
        }
        public static string xorBinary_gf2(string str)
        {
            for (int m = 0; m < _1b.Length; m++)
            {
                if (_1b.ElementAt(m) == str.ElementAt(m))
                {
                    str = str.Remove(m, 1);
                    str = str.Insert(m, "0");
                }
                else
                {
                    str = str.Remove(m, 1);
                    str = str.Insert(m, "1");
                }
            }
            return str;
        }
        public static string[,] shiftrows(string state)
        {
            string[,] vertical_arr = new string[4, 4];
            int cnt = 0;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    vertical_arr[i, j] += state[cnt];
                    vertical_arr[i, j] += state[cnt + 1];
                    cnt += 2;
                   // Console.Write(vertical_arr[i, j]+"  ");
                }
                // Console.WriteLine("");
            }
            string tmp = vertical_arr[1, 0];
            vertical_arr[1, 0] = vertical_arr[1, 1];
            vertical_arr[1, 1] = vertical_arr[1, 2];
            vertical_arr[1, 2] = vertical_arr[1, 3];
            vertical_arr[1, 3] = tmp;
            //
            string tmp2 = vertical_arr[2, 2];
            tmp = vertical_arr[2, 3];
            vertical_arr[2, 2] = vertical_arr[2, 0];
            vertical_arr[2, 3] = vertical_arr[2, 1];
            vertical_arr[2, 0] = tmp2;
            vertical_arr[2, 1] = tmp;
            //
            tmp = vertical_arr[3, 3];
            tmp2 = vertical_arr[3, 1];
            string tmp3 = vertical_arr[3, 2];
            vertical_arr[3, 1] = vertical_arr[3, 0];
            vertical_arr[3, 2] = tmp2;
            vertical_arr[3, 3] = tmp3;
            vertical_arr[3, 0] = tmp;
            return vertical_arr;
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
    }
}