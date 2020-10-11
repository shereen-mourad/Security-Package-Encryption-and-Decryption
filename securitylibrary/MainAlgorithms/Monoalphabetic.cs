using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            cipherText = cipherText.ToLower();
            //da el feeh el mapping
            Dictionary<char, char> key = new Dictionary<char, char>();
            //da el feeh el character used wala la2
            Dictionary<char, bool> used = new Dictionary<char, bool>();

            //koloh not used fel awel
            for (char i = 'a'; i <= 'z'; i++)
            {
                used[i] = false;
            }

            //ba3ady 3ala el plain text ashoof meen used w a3mel 3aleeh check true
            for (int i=0;i<plainText.Length;i++)
            {
                key[plainText[i]] = cipherText[i];
                used[cipherText[i]] = true;
            }

            //3ashan ba2y el letters el mesh fel cipher
            for(char i='a';i<='z';i++)
            {
                if(!key.ContainsKey(i))
                {
                    for(char c='a';c<='z';c++)
                    {
                        if(used[c]== false)
                        {
                            key[i] = c;
                            used[c] = true;
                            break;
                        }
                    }
                }
            }

            //haraga3 feeha el key
            string ret = string.Empty;
            for(char i='a';i<='z';i++)
            {
                ret += key[i];
            }

            return ret;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            cipherText = cipherText.ToLower();
            int size = cipherText.Length;
            char[] plainText = new char[size];

            for (int i = 0; i < size; i++)
            {
                //if (char.IsLetter(cipherText[i]) == false)
                  //  plainText[i] = cipherText[i];
                //else
                //{
                    int n = key.IndexOf(cipherText[i]) + 97;
                    plainText[i] = (char)n;
                    //int n = cipherText[i] + 97;
                    //plainText[i] = key[n];
                //}
            }

            return new string(plainText);
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            int size = plainText.Length;
            char[] cipherText = new char[size];

            for(int i = 0; i<size; i++)
            {
                //if (char.IsLetter(plainText[i]) == false)
                  //  cipherText[i] = plainText[i];
                //else
                //{
                    int n = plainText[i] - 97;
                    cipherText[i] = key[n];
                //}
            }

            return new string(cipherText).ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();

            string freq = "zqjxkvbywgpfmucdlhrsnioate";
            cipher = cipher.ToLower();

            //3dad kol letter ad eh
            Dictionary<char, int> count = new Dictionary<char, int>();
            Dictionary<char, char> keys = new Dictionary<char, char>();

            //lw mesh mawgood yeb2a count = 0
            for(int i=0;i<cipher.Length;i++)
            {
                if(!count.ContainsKey(cipher[i]))
                {
                    count[cipher[i]] = 0;
                }
                count[cipher[i]]++;
            }

            int iterator = 0;
            //sort el dictionary
            //babadel el letters bel freq string
            foreach (KeyValuePair<char, int> item in count.OrderBy(key => key.Value))
            {
                keys[item.Key] = freq[iterator];
                iterator++;
            }

            string ret = string.Empty;

            for(int i=0;i<cipher.Length;i++)
            {
                ret += keys[cipher[i]];
            }
            return ret;
        }
    }
}
