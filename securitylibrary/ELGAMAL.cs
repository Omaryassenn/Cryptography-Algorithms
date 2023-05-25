using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        static int modInverse(int b, int l)
        {

            for (int a = 1; a < l; a++)

                if (((b % l) * (a % l)) % l == 1)
                    return a;
            return -1;
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> Encry_Vals = new List<long>();
            int c1 = 1, c2 = 1;

            // Calculate c1 = alpha^k % q
            for (int u = 0; u < k; u++)
                c1 = (c1 * alpha) % q;

            // Calculate c2 = (y^k * m) % q
            for (int j = 0; j < k; j++)
                c2 = (c2 * y) % q;
            c2 = (c2 * m) % q;

            Encry_Vals.Add(c1);
            Encry_Vals.Add(c2);
            return Encry_Vals;
        }

        public int Decrypt(int c1, int c2, int x, int q)
        {
            int r = 1;

            // Calculate r = c1^x % q
            for (int i = 0; i < x; i++)
                r = (r * c1) % q;

            // Calculate kInverse = r^-1 % q
            int kInverse = modInverse(r, q);

            // Calculate m = (c2 * kInverse) % q
            int m = (c2 * kInverse) % q;
            return m;
        }
    }
}