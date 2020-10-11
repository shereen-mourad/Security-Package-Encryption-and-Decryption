using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
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
        
        /* variables
               q -> mod prime
               alpha -> generator
               xa -> private key of A
               xb -> private key of B
               pubA -> public key of A
               pubB -> public key of B
               sA -> to get secret key for A
               sB -> to get secret key for B  */

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();

            int pubA, pubB, sA, sB;
            List<int> Result = new List<int>();

            //public key = alpha ^ xa mod q
            pubA = PowerMod(alpha, xa, q);
            pubB = PowerMod(alpha, xb, q);

            // secret key A = pubB ^ xa mod q  
            sA = PowerMod(pubB, xa, q);
            // secret key B = pubA ^ xb mod q
            sB = PowerMod(pubA, xb, q);

            Result.Add(sA);
            Result.Add(sB);

            return Result;
        }
    }
}
