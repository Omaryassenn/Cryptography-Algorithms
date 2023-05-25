using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            return Encrypt(cipherText, key);
        }
        public override string Encrypt(string plainText, string key)
        {
            bool flag = true;
            if (plainText.StartsWith("0x") && (key.StartsWith("0x")))
            {
                flag = false;

                plainText = ConvertHex(plainText);
                key = ConvertHex(key);
            }
            var pt = StringToByteArray(plainText);
            var k = StringToByteArray(key);
            var ct = new byte[pt.Length];
            int i, j = 0;
            int[] arr = new int[256];
            for (int x = 0; x < 256; x++)
            {
                arr[x] = x;
            }
            for (int x = 0; x < 256; x++)
            {
                j = (j + arr[x] + k[x % k.Length]) % 256;
                Swap(arr, x, j);
            }
            i = j = 0;
            for (int x = 0; x < pt.Length; x++)
            {
                i = (i + 1) % 256;
                j = (j + arr[i]) % 256;
                Swap(arr, i, j);
                ct[x] = (byte)(pt[x] ^ arr[(arr[i] + arr[j]) % 256]);
            }
            if (!flag)
                return "0x" + BitConverter.ToString(ct).Replace("-", "");
            return Encoding.GetEncoding("ISO-8859-1").GetString(ct);
        }
        static string ConvertHex(String hexa)
        {
            if (hexa.StartsWith("0x"))
                hexa = hexa.Substring(2);
            var bytes = new byte[hexa.Length / 2];
            for (int i = 0; i < hexa.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexa.Substring(i, 2), 16);
            }
            return Encoding.GetEncoding("ISO-8859-1").GetString(bytes);
        }
        void Swap(int[] arr, int i, int j)
        {
            int temp = arr[i];
            arr[i] = arr[j];
            arr[j] = temp;
        }
        static byte[] StringToByteArray(string str)
        {
            byte[] byteArray = new byte[str.Length];
            for (int i = 0; i < str.Length; i++)
            {
                byteArray[i] = (byte)str[i];
            }
            return byteArray;
        }
    }
}