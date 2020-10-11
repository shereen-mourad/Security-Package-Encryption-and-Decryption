using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int PowerMod(int x, int y, int mod)
        {
            int pow = 1;

            for (int i = 0; i < y; i++)
            {
                pow = pow * x;
                pow = pow % mod;
            }

            return pow;
        }

        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();

            int n = 1;
            n = p * q;

            int Cipher;
            Cipher = PowerMod(M, e, n);

            return Cipher;
        }

        public int ModMultInverse(int e, int phi_n)
        {
            double inv = 1.0;

            for( int i=1; i <= e; i++ )
            {
                inv = i * phi_n;
                inv += 1;
                inv = inv / e;

                if (inv % 1 == 0)
                    break;
            }

            return ((int)inv);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //throw new NotImplementedException();

            int n = 1;
            int phiN = 1;

            n = p * q;
            phiN = (p - 1) * (q - 1);

            int d;
            d = ModMultInverse(e, phiN);

            int M;
            M = PowerMod(C, d, n);

            return M;

        }
    }
}
