using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            string al = "abcdefghijklmnopqrstuvwxyz";
            string key = "";
            int s = 0,res=0;
            string t = "";

            for (int i = 0; i < cipherText.Length; i++)
            {
                s = (al.IndexOf(cipherText[i]) - al.IndexOf(plainText[i])) + 26;
                res = s % 26;
                key += al[res];
            }
            t+= key[0];
            for (int i = 1; i < key.Length; i++)
            {
                if(cipherText==Encrypt(plainText,t))
                {
                    return t;
                }
                t += key[i];

            }
            return key;
           
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string al = "abcdefghijklmnopqrstuvwxyz";
            int count = 0;
            while(cipherText.Length!=key.Length)
            {
                key += key[count];
                count++;
            }
            int res = 0, s = 0;
            string plain_text = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                s = (al.IndexOf(cipherText[i]) - al.IndexOf(key[i]))+26;
                res = s % 26;
                plain_text +=al[res];

            }
            return plain_text;
        }

        public string Encrypt(string plainText, string key)
        {
            string al = "abcdefghijklmnopqrstuvwxyz";
            string cipher_text = "";
            int count = 0;
            while(plainText.Length!=key.Length)
            {
                key += key[count];
                    count++;
            }
            int res=0, s = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                s = al.IndexOf(plainText[i])+al.IndexOf(key[i]);
                res = s % 26;
                cipher_text += al[res];
                
            }
            return cipher_text;
        }
    }
}