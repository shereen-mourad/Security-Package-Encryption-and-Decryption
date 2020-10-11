using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;
            int i = 0;
            //bnsawy el cipher belly rag3 mn el encrypt
            do
            {
                { if (cipherText.ToLower() == Encrypt(plainText, key)) break; key++; }
                i++;
            } while (i < plainText.Length);


            return key;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {/*
            for (int i = 0; i < cipherText.Length; i++)
            {
                plainT = plainT + cipherText[i * key % cipherText.Length];
              //plainT = plainT + cipherText[(i * (cipherText.Length)/key) % cipherText.Length];
                    //plainT = (cipherText.Length / key).ToString();
            }*/

            string plainT = "";
            int newkey = (int)Math.Ceiling(cipherText.Length / (float)key);
            int i = 0;
            //blf 3la asas elequation 3shan ageb elkey elgded ,w len elklma bs bnot bel key elgded
            while (i < newkey)
            {
                for (int j = i; j < cipherText.Length; j = j + newkey) plainT = plainT + cipherText[j]; i++;
            }
            return plainT;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, int key)
        {
            int row = key;
            int coloum = plainText.Length;
            string enctext = "";
            char[,] arr = new char[row, coloum];
            int charachter = 0;
            // if (plainText[charachter].Equals(" "))

            //blf 3la 3dd 7rof elklma w el key
            int i = 0;
            while (i < coloum)
            {
                for (int j = 0; j < row; j++) if (charachter != coloum) arr[j, i] = plainText[charachter++]; i++;
            }
            //b2raa el3ks row kamel w bmshy colom , by row 

            int loo = 0;
            while (loo < row)
            {
                for (int j = 0; j < coloum; j++) { if (arr[loo, j] != '\0') enctext = enctext + arr[loo, j]; }
                loo++;
            }
            return enctext;
            //throw new NotImplementedException();
        }
    }
}
