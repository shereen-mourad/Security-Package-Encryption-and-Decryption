using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        //men 8eer el 'j'
        string alphabets = "abcdefghiklmnopqrstuvwxyz";
        //ha5ood feeh makan kol letter fel matrix row w ba3deeh column
        int[] char_location;
        //el matrix el ben5azen feeh el key w el alphabets men 8eer duplication
        char[,] Matrix = new char[5, 5];

        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            //return Ciphers(cipherText, key, false);

            string cipher = ConstructMatrix(cipherText, key);
            string plainText = string.Empty;
            //iterator
            int x = 0; 
            
            for (int m = 0; m < cipher.Length; m+=2)
            {
                //same column
                if (char_location[x + 1] == char_location[x + 3])
                {
                    //awel 7arf
                    if ((char_location[x] - 1) < 0)
                        plainText += Matrix[(4), char_location[x + 1]];
                    else
                        plainText += Matrix[(char_location[x] - 1), char_location[x + 1]];

                    //tany 7arf
                    if ((char_location[x + 2] - 1) < 0)
                        plainText += Matrix[(4), char_location[x + 3]];
                    else
                        plainText += Matrix[(char_location[x + 2] - 1), char_location[x + 3]];
                }

                //same row
                else if (char_location[x] == char_location[x + 2])
                {
                    //awel 7arf
                    if ((char_location[x + 1] - 1) < 0)
                        plainText += Matrix[char_location[x], (4)];
                    else
                        plainText += Matrix[char_location[x], (char_location[x + 1] - 1)];

                    //tany 7arf
                    if ((char_location[x + 3] - 1) < 0)
                        plainText += Matrix[char_location[x + 2], (4)];
                    else
                        plainText += Matrix[char_location[x + 2], (char_location[x + 3] - 1)];
                }

                //rectangle
                else
                {
                    //awel 7arf
                    plainText += Matrix[char_location[x], char_location[x + 3]];
                    //tany 7arf
                    plainText += Matrix[char_location[x + 2], char_location[x + 1]];
                }

                x += 4;
            }

            string ret_cipher = string.Empty;
            int i = 0;

            //3ashan a-check el duplicates
            while (i < plainText.Length - 2)
            {
                //lw el x fel nos ma been duplicates
                if (plainText[i] == plainText[i + 2] && plainText[i + 1] == 'x')
                {
                    ret_cipher += plainText[i];
                    i ++;
                }

                //lw el x fel nos bas letter asasy
                else if (plainText[i] != plainText[i + 2] && plainText[i + 1] == 'x')
                {
                    ret_cipher += plainText[i];
                    ret_cipher += plainText[i + 1];
                    i ++;
                }

                //lw mafeesh x
                else if (plainText[i + 1] != 'x')
                {
                    ret_cipher += plainText[i];
                    ret_cipher += plainText[i + 1];
                    i ++;
                }

                i++;
            }

            //check en el x fel a5er
            //lw mafeesh x fel a5er
            if (plainText[plainText.Length - 1] != 'x')
            {
                ret_cipher += plainText[plainText.Length - 2];
                ret_cipher += plainText[plainText.Length - 1];
            }

            //lw feeh x fel a5er
            else
                ret_cipher += plainText[plainText.Length - 2];


            return ret_cipher;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            //return Ciphers(plainText, key, true);

            string plain = ConstructMatrix(plainText, key);
            string cipherText = string.Empty;
            //iterator
            int x = 0; 

            for(int i =0; i<plain.Length;i+=2)
            {
                //same column
                if(char_location[x+1] == char_location[x+3])
                {
                    cipherText += Matrix[(char_location[x] + 1) % 5, char_location[x + 1]];
                    cipherText += Matrix[(char_location[x+2] + 1) % 5, char_location[x + 3]];
                }

                //same row
                else if(char_location[x] == char_location[x + 2])
                {
                    cipherText += Matrix[char_location[x], (char_location[x + 1] + 1) % 5];
                    cipherText += Matrix[char_location[x + 2], (char_location[x + 3] + 1) % 5];
                }

                //rectangle
                else
                {
                    cipherText += Matrix[char_location[x], char_location[x + 3]];
                    cipherText += Matrix[char_location[x + 2], char_location[x + 1]];
                }

                x += 4;
            }

            //3ashan el cipher beyb2a upper
            return cipherText.ToUpper();

            //return cipherText.ToLower();
        }

        public string ConstructMatrix(string plainText, string key)
        {
            //awel 7aga hasheel spaces
            plainText = string.Join("", plainText.Split(default(string[]), StringSplitOptions.RemoveEmptyEntries));

            //ha7awel el plaintext w el key le char array
            char[] text_arr = plainText.ToLower().ToCharArray();
            char[] key_arr = key.ToLower().ToCharArray();

            //habadel kol i b j fel text
            for (int m=0; m<text_arr.Length; m++)
            {
                if (text_arr[m] == 'j')
                    text_arr[m] = 'i';
            }

            //w el key
            for (int m = 0; m < key_arr.Length; m++)
            {
                if (key_arr[m] == 'j')
                    key_arr[m] = 'i';
            }

            //basheel el duplicates men el key
            string key_s = string.Join("", key_arr.Distinct());
            
            //ba-concatenate el key ma3 el alphabets w asheel el duplicates
            string TheMatrix = string.Join("", (key_s + alphabets).ToCharArray().Distinct());

            int iterator = 0;

            for(int k = 0; k < 5; k++)
            {
                for(int j=0; j<5; j++)
                {
                    Matrix[k, j] = TheMatrix[iterator];
                    iterator++;
                }
                                               }

            string plain = string.Empty;
            string plain1 = string.Empty;

            //hashoof lw el text odd aw lw feeh char duplicated
            plain = Check_X(text_arr, plain1);

            //t3aly n5aleeha function
            
            //int i = 0;
            
            //while (i<text_arr.Length)
            //{
            //    if (i == text_arr.Length - 1 || text_arr[i] == text_arr[i + 1])
            //    {
            //        plain += text_arr[i].ToString() + 'x';
            //        i++;
            //    }
            //    else
            //    {
            //        plain += text_arr[i].ToString() + text_arr[i + 1].ToString();
            //        i += 2;
            //    }

            //}

            //ta3aly n5aleeha function
            int size = plain.Length * 2;
            char_location = new int[size];
            //function men hena

            GetLocation(plain);

            //iterator = 0;
            ////3ashan lw la2eet el char fel matrix
            //bool found = false;

            ////ha-check mkan el char fel matrix w a7tafez beeh
            //for (int l=0; l<plain.Length; l++)
            //{
            //    for(int m=0; m<5; m++)
            //    {
            //        for(int n=0; n<5; n++)
            //        {
            //            if(plain[l] == Matrix[m,n])
            //            {
            //                char_location[iterator] = m;
            //                iterator++;
            //                char_location[iterator] = n;
            //                iterator++;
            //                found = true;
            //                break;
            //            }
            //        }

            //        if(found)
            //        {
            //            found = false;
            //            break;
            //        }
            //    }
            //}

            return plain;
        }

        public string Check_X(char[] text_arr,string plain)
        {
            int i = 0;

            while (i < text_arr.Length)
            {
                if (i == text_arr.Length - 1 || text_arr[i] == text_arr[i + 1])
                {
                    plain += text_arr[i].ToString() + 'x';
                    i++;
                }
                else
                {
                    plain += text_arr[i].ToString() + text_arr[i + 1].ToString();
                    i += 2;
                }

            }

            return plain;
        }

        public void GetLocation(string plain)
        {
            int iterator = 0;
            //3ashan lw la2eet el char fel matrix
            bool found = false;

            //ha-check mkan el char fel matrix w a7tafez beeh
            for (int l = 0; l < plain.Length; l++)
            {
                for (int m = 0; m < 5; m++)
                {
                    for (int n = 0; n < 5; n++)
                    {
                        if (plain[l] == Matrix[m, n])
                        {
                            char_location[iterator] = m;
                            iterator++;
                            char_location[iterator] = n;
                            iterator++;
                            found = true;
                            break;
                        }
                    }

                    if (found)
                    {
                        found = false;
                        break;
                    }
                }
            }
        }

        //public int Modulus(int x, int y)
        //{
        //    //for calculations
        //    return (x % y + y) % y;
        //}

        //public List<int> Occurences(string s, char c)
        //{
        //    List<int> count = new List<int>();
        //    int sum_index = 0;

        //    while((sum_index = s.IndexOf(c,sum_index)) != -1)
        //    {
        //        count.Add(sum_index++);
        //    }

        //    return count;
        //}

        //public string RemoveDuplicates(string s, List<int> count)
        //{
        //    string ret = s;

        //    for (int i = count.Count - 1; i >= 1; i--)
        //        ret = ret.Remove(count[i], 1);

        //    return ret;
        //}

        //public char[,] GetKeyMatrix(string key)
        //{
        //    char[,] key_arr = new char[5, 5];
        //    string alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        //    string temp = string.Empty;

        //    if (string.IsNullOrEmpty(key))
        //        temp = "CIPHER";
        //    else
        //        temp = key.ToUpper();

        //    temp = temp.Replace("J", "");
        //    temp += alphabets;

        //    for(int i=0; i<25; i++)
        //    {
        //        List<int> count = Occurences(temp, alphabets[i]);
        //        temp = RemoveDuplicates(temp, count);
        //    }

        //    temp = temp.Substring(0, 25);

        //    for(int i = 0; i<25; i++)
        //    {
        //        key_arr[(i / 5), (i % 5)] = temp[i];
        //    }

        //    return key_arr;
        //}

        //public void Position(ref char[,] key_arr, char c, ref int row, ref int col)
        //{
        //    if (c == 'J')
        //        Position(ref key_arr, 'J', ref row, ref col);

        //    for(int i=0; i<5; i++)
        //    {
        //        for(int j=0; j<5; j++)
        //        {
        //            if(key_arr[i,j] == c)
        //            {
        //                row = i;
        //                col = j;
        //            }
        //        }
        //    }
        //}

        //public char[] IfSameRow(ref char[,] key_arr, int row, int col1, int col2, int encrypt)
        //{
        //    return new char[] { key_arr[row, Modulus((col1 + encrypt), 5)], key_arr[row, Modulus((col2 + encrypt), 5)] };
        //}

        //public char[] IfSameColumn(ref char[,] key_arr, int col, int row1, int row2, int encrypt)
        //{
        //    return new char[] { key_arr[Modulus((row1 + encrypt), 5),col], key_arr[Modulus((row2 + encrypt), 5),col] };
        //}

        //public char[] IfSameRowSameColumn(ref char[,] key_arr, int row, int col, int encrypt)
        //{
        //    return new char[] { key_arr[Modulus((row + encrypt), 5), Modulus((row + encrypt), 5)], key_arr[Modulus((row + encrypt), 5), Modulus((row + encrypt), 5)] };
        //}

        //public char[] IfDiffRowSameColumn(ref char[,] key_arr, int row1, int col1, int row2, int col2)
        //{
        //    return new char[] { key_arr[row1,col2], key_arr[row2,col1] };
        //}

        //public string RemoveCharacters(string text)
        //{
        //    string result = text;
        //    int size = result.Length;

        //    for(int i=0; i<size; i++)
        //    {
        //        if (!char.IsLetter(result[i]))
        //            result = result.Remove(i, 1);
        //    }

        //    return result;
        //}

        //public string ModifyResult(string text, string result)
        //{
        //    StringBuilder ret = new StringBuilder(result);
        //    int size = text.Length;

        //    for(int i=0; i<size; i++)
        //    {
        //        if (!char.IsLetter(text[i]))
        //            ret = ret.Insert(i, text[i].ToString());

        //        if (char.IsLower(text[i]))
        //            ret[i] = char.ToLower(ret[i]);
        //    }

        //    return ret.ToString();
        //}

        //public string Ciphers(string plainText, string key, bool encrypt)
        //{
        //    string cipherText = string.Empty;
        //    char[,] key_arr = GetKeyMatrix(key);
        //    string temp = RemoveCharacters(plainText);
        //    int q;
        //    int size = temp.Length;

        //    if (encrypt)
        //        q = 1;
        //    else
        //        q = -1;

        //    if ((size % 2) != 0)
        //        temp += "X";

        //    for(int i=0; i<size; i+=2)
        //    {
        //        int r1 = 0;
        //        int c1 = 0;
        //        int r2 = 0;
        //        int c2 = 0;

        //        Position(ref key_arr, char.ToUpper(temp[i]), ref r1, ref c1);
        //        Position(ref key_arr, char.ToUpper(temp[i+1]), ref r2, ref c2);

        //        if (r1 == r2 && c1 == c2)
        //            cipherText += new string(IfSameRowSameColumn(ref key_arr, r1, c1, q));

        //        else if (r1 == r2)
        //            cipherText += new string(IfSameRow(ref key_arr, r1, c1, c2, q));

        //        else if (c1 == c2)
        //            cipherText += new string(IfSameColumn(ref key_arr, c1, r1, r2, q));

        //        else
        //            cipherText += new string(IfDiffRowSameColumn(ref key_arr, r1, c1, r2, c2));
        //    }

        //    cipherText = ModifyResult(plainText, cipherText);

        //    return cipherText;
        //}
    }
}
