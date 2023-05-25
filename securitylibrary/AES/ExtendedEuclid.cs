using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //  throw new NotImplementedException();
            int A1 = 1, A2 = 0, A3 = baseN;
            int B1 = 0, B2 = 1, B3 = number;
            while (true)
            {
                if (B3 == 0)
                {
                    return -1; // no  found inverse
                }
                else if (B3 == 1)
                {
                    if (B2 > 1)
                    {
                        return B2;
                    }
                    else
                    {
                        B2 += baseN;
                    }
                    return B2; // return inverse
                    /* while (b2 < 0)
                     }
                     return b2;*/
                }
                int T1, T2, T3;// a1 a2 a3 b1 b2 b4 q
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