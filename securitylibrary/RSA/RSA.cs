using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;



namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            //M raised to the power of e, using the modulus n.
            int cipher = Modpower(M, e, n);
            return cipher;
        }
        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            int message = Modpower(C, GetMultiplicativeInverse(e, phi), n);
            return message;
        }
        int Modpower(int b, int e, int m)
        {
            int r = 1;
            for (int i = 0; i < e; i++)
            {
                r = (r * b) % m;
            }
            return r;
        }
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int A1 = 1, A2 = 0, A3 = baseN;
            int B1 = 0, B2 = 1, B3 = number;
            while (true)
            {
                if (B3 == 0)
                    return -1; // no  found inverse

                else if (B3 == 1)
                {
                    if (B2 > 1)
                        return B2;

                    else
                        B2 += baseN;

                    return B2; // return inverse 
                }
                int T1, T2, T3;
                int q = A3 / B3;//division product

                T1 = A1 - (q * B1);
                T2 = A2 - (q * B2);
                T3 = A3 - (q * B3);

                A1 = B1;
                A2 = B2;
                A3 = B3;

                B1 = T1;
                B2 = T2;
                B3 = T3;
            }
        }
    }
}
