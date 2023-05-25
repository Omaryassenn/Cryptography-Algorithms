using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            int ya = ModExp(alpha, xa, q);
            int yb = ModExp(alpha, xb, q);
            //xa=2^6mod 19=7
            //yb=2^13mod19=3
            //replace 
            // Compute shared secret keys
            int ka = ModExp(yb, xa, q);
            int kb = ModExp(ya, xb, q);
            //ka=3^6mod19=7
            //kb=7^13mod19=7
            // Return the shared secret keys as a list
            return new List<int> { ka, kb };

        }
        private int ModExp(int a, int b, int m)
        {

            int res = 1;
            for (int i = 0; i < b; i++)
            {
                res = (res * a) % m;
            }
            return res;

            //throw new NotImplementedException();
        }
    }
}