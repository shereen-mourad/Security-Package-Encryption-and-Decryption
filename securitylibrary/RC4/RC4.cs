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
        public void Swap(int s, int j)
        {
            int var;

            var = s;
            s = j;
            j = var;
        }

        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            return Encrypt(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            int l = key.Length;
            int Plainl = plainText.Length;

            //check if key is hex
            string HexKey = "";
            char TransformKey;
            string StrKey = "";
            if (key[0] == '0' && key[1] == 'x')
            {
                //3ashan a7welha string
                for (int i = 2; i < l; i += 2)
                {
                    HexKey += key[i];
                    HexKey += key[i + 1];
                    TransformKey = (char)Int32.Parse(HexKey, System.Globalization.NumberStyles.AllowHexSpecifier);
                    StrKey += TransformKey;
                }
                key = StrKey;
            }

            //check if plain is hex
            bool NotHexa = true;

            string HexPlain = "";
            char TransformPlain;
            string StrPlain = "";
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                NotHexa = false;

                //3ashan a7welha string
                for (int i = 2; i < Plainl; i += 2)
                {
                    HexPlain += plainText[i];
                    HexPlain += plainText[i + 1];
                    TransformPlain = (char)Int32.Parse(HexPlain, System.Globalization.NumberStyles.AllowHexSpecifier);
                    StrPlain += TransformPlain;
                }
                plainText = StrPlain;
            }

            //step 1 initialize S and T
            int[] S = new int[256];
            int[] T = new int[256];

            for (int i = 0; i < 256; i++)
            {
                S[i] = i;
                //T[i] = key[i % l];
            }

            int m = 0;
            while (m < 256)
            {
                for (int i = 0; i < l; i++)
                {
                    T[m] = key[i];
                    m++;
                }
            }

            //step 2 permutaion KSA
            int j = 0;
            int temp;
            for(int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                //Swap(S[i], S[j]);
                temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            //step 3 keyStream k (PRGA)
            int x = 0;
            int y = 0;
            int[] newKey = new int[Plainl];
            int t;
            
            for(int i = 0; i < Plainl; i++)
            {
                x = (x + 1) % 256;
                y = (y + S[x]) % 256;
                //Swap(S[x], S[y]);
                temp = S[x];
                S[x] = S[y];
                S[y] = temp;

                t = (S[x] + S[y]) % 256;
                newKey[i] = S[t];
            }

            //ha7awel el plain int 3ashan a2dar a3mel XOR
            int[] IntPlain = new int[Plainl];
            for (int i = 0; i < Plainl; i++)
            {
                IntPlain[i] = Convert.ToInt32(plainText[i]);
            }

            //step 4 apply XOR ( plain[i] XOR key[i] )
            int[] XOR = new int[Plainl];
            for (int i = 0; i < Plainl; i++)
            {
                XOR[i] = IntPlain[i] ^ newKey[i];
            }

            String Cipher = "";
            //3ashan arg3 el cipherText bel hex
            if (NotHexa == false)
            {
                Cipher += "0x";
                for (int i = 0; i < Plainl; i++)
                {
                    Cipher += XOR[i].ToString("X");
                }

                return Cipher;
            }

            //lw el plain ma kantesh hex
            else
            {
                for (int i = 0; i < Plainl; i++)
                {
                    Cipher += (char)XOR[i];
                }

                return Cipher;
            }
        }
    }
}
