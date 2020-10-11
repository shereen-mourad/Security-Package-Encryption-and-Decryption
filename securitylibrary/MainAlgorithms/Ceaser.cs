using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();

            string cipherText = string.Empty;
            int asci_p;
            int cipher_index;

            for (int i=0;i<plainText.Length;i++)
            {
                //bageeb index el plain
                //97 3ashan el plain btb2a lower letters, a = 97
                asci_p = plainText[i] - 97;

                //bageeb index el cipher
                cipher_index = (asci_p + key) % 26;

                //ba7wel index el cipher le char
                cipherText += (char)(cipher_index + 97);
            }

            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            //return Encrypt(cipherText, 26 - key);

            string plainText = string.Empty;
            int asci_c;
            int plain_index;

            for (int i = 0; i < cipherText.Length; i++)
            {
                //bageeb index el cipher
                //65 3ashan el cipher btb2a upper letters, A = 65
                asci_c = cipherText[i] - 65;

                //bageeb index el plain
                plain_index = asci_c - key;
                //check lw 3ada el 26
                if (plain_index < 0)
                    plain_index += 26;

                //ba7wel index el plain le char
                plainText += (char)(plain_index + 97);

            }

            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            int key = 0;

            //bageeb el ascii bta3 ay 7arf plain w cipher
            int plain = plainText[0] - 96;
            int cipher = cipherText[0] - 64;

            //c = (index p + key) %26
            key = cipher - plain;

            //check enoh ma 3adash el 26
            if (key < 0)
                key += 26;

            return key;
        }

        //public char Ciphers(char _char,int key)
        //{
        //    if(!char.IsLetter(_char))
        //    {
        //        return _char;
        //    }
        //    char c;
        //    if (char.IsUpper(_char))
        //        c = 'A';
        //    else
        //        c = 'a';
        //    return (char)((((_char + key) - c) % 26) + c);
        //}
    }
}
