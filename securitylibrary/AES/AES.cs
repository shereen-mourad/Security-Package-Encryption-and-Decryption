using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public static string[,] Mix_col_arr;
        public static string[,] arrshift;
        public static int[,] S;
        public override string Decrypt(string cipherText, string key)
        {
            string[] keyexp = new string[11];
            keyexp[0] = key; for (int i = 0; i < 10; i++) keyexp[i + 1] = KeyExpansion(keyexp[i], i);
            string[,] plain1 = new string[4, 4];

            if (cipherText[1] == 'x' || cipherText[1] == 'X') cipherText = cipherText.Substring(2, 32);
            for (int h = 0, k = 0; h < 4; h++)
            {
                for (int j = 0; j < 4; j++, k += 2)
                {
                    string ss = cipherText[k].ToString() + cipherText[k + 1];
                    plain1[h, j] = ss;
                }
            }
            cipherText = AddroundKey(plain1, keyexp[10]);
            if (cipherText[1] != 'x' && cipherText[1] != 'X') cipherText = "0x" + cipherText;

            cipherText = InvShiftRows(cipherText);
            cipherText = InvSubBytes(cipherText);

            for (int i = 9; i > 0; i--)
            {
                if (cipherText[1] == 'x' || cipherText[1] == 'X') cipherText = cipherText.Substring(2, 32);
                for (int h = 0, k = 0; h < 4; h++)
                {
                    for (int j = 0; j < 4; j++, k += 2)
                    {
                        string ss = cipherText[k].ToString() + cipherText[k + 1];
                        plain1[h, j] = ss;
                    }
                }
                cipherText = AddroundKey(plain1, keyexp[i]);
                if (cipherText[1] != 'x' && cipherText[1] != 'X') cipherText = "0x" + cipherText;
                cipherText = InvMixColumns(cipherText);
                // if (cipherText[1] == 'x' || cipherText[1] == 'X') cipherText =cipherText.Substring(2,32);
                cipherText = InvShiftRows(cipherText);
                cipherText = InvSubBytes(cipherText);
            }
            if (cipherText[1] == 'x' || cipherText[1] == 'X') cipherText = cipherText.Substring(2, 32);
            for (int h = 0, k = 0; h < 4; h++)
            {
                for (int j = 0; j < 4; j++, k += 2)
                {
                    string ss = cipherText[k].ToString() + cipherText[k + 1];
                    plain1[h, j] = ss;
                }
            }
            cipherText = AddroundKey(plain1, keyexp[0]);
            return "0x" + cipherText;
        }

        public override string Encrypt(string plainText, string key)
        {
            string[,] plain1 = new string[4, 4];
            if (plainText[1] == 'x' || plainText[1] == 'X') plainText = plainText.Substring(2, 32);
            for (int h = 0, k = 0; h < 4; h++)
            {
                for (int j = 0; j < 4; j++, k += 2)
                {
                    string ss = plainText[k].ToString() + plainText[k + 1];
                    plain1[h, j] = ss;
                }
            }
            plainText = AddroundKey(plain1, key);
            for (int i = 0; i < 9; i++)
            {
                plainText = SubWord(plainText);
                plainText = ShiftRows(plainText);
                plainText = mix_col(plainText);
                if (plainText[1] == 'x' || plainText[1] == 'X') plainText = plainText.Substring(2, 32);
                key = KeyExpansion(key, i);
                for (int h = 0, k = 0; h < 4; h++)
                {
                    for (int j = 0; j < 4; j++, k += 2)
                    {
                        string ss = plainText[k].ToString() + plainText[k + 1];
                        plain1[h, j] = ss;
                    }
                }
                plainText = AddroundKey(plain1, key);
            }
            plainText = SubWord(plainText);
            plainText = ShiftRows(plainText);
            key = KeyExpansion(key, 9);
            for(int i = 0, k = 0; i < 4; i++)
            {
                for(int j =  0; j < 4; j++,  k+=2)
                {
                    string ss = plainText[k].ToString() + plainText[k + 1];
                    plain1[i,j] = ss;
                }
            }
            plainText = AddroundKey(plain1, key);
            return "0x"+plainText;
        }

        private static int Mul01(int b)
        {
            return b;
        }

        private static int Mul02(int b)
        {
            b = b << 1;
            if ((b & 256) != 0)
            {
                b -= 256;
                b ^= 27;
            }
            return b;

        }

        private static int Mul03(int b)
        {
            return (Mul02(b) ^ b);
        }


        public static string hextodec(string value)
        {


            int decValue = int.Parse(value, System.Globalization.NumberStyles.HexNumber);
            string num = decValue.ToString();
            return num;
        }
        public static string DecimalToHexadecimal(int dec)
        {
            if (dec < 1) return "0";

            int hex = dec;
            string hexStr = string.Empty;

            while (dec > 0)
            {
                hex = dec % 16;

                if (hex < 10)
                    hexStr = hexStr.Insert(0, Convert.ToChar(hex + 48).ToString());
                else
                    hexStr = hexStr.Insert(0, Convert.ToChar(hex + 55).ToString());

                dec /= 16;

            }

            return hexStr;
        }
        public static string SubWord(string plainn)
        {
            List<string> new_plain = new List<string>();
            List<string> sub_plain = new List<string>();
            string[,] SBOX = {
           { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
           { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
           { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
           {  "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"},
           { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
           { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
           { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
           { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
           { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
           { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
           { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
           { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
           {  "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"},
           { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
           { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
           { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" }
        };
            for (int i = 0; i < plainn.Length; i++)
            {
                if (plainn[i] == 'A' || plainn[i] == 'a')
                    new_plain.Add("10");
                else if (plainn[i] == 'B' || plainn[i] == 'b')
                    new_plain.Add("11");
                else if (plainn[i] == 'C' || plainn[i] == 'c')
                    new_plain.Add("12");
                else if (plainn[i] == 'D' || plainn[i] == 'd')
                    new_plain.Add("13");
                else if (plainn[i] == 'E' || plainn[i] == 'e')
                    new_plain.Add("14");
                else if (plainn[i] == 'F' || plainn[i] == 'f')
                    new_plain.Add("15");
                else
                    new_plain.Add(plainn[i].ToString());


            }
            for (int k = 0; k < new_plain.Count - 1; k += 2)
            {
                sub_plain.Add(SBOX[int.Parse(new_plain[k]), int.Parse(new_plain[k + 1])]);
            }
            string temp_string = "";
            for (int i = 0; i < sub_plain.Count; i++)
            {
                temp_string += sub_plain[i];
            }

             return temp_string;
        }

        public static string mix_col(string f)
        {
            string s = ShiftRows(f);
            string[,] arrshift_temp = new string[4, 4];
            int count_arf2 = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                                       
                    arrshift_temp[j, i] = f[count_arf2].ToString() + f[count_arf2 + 1].ToString();
                    count_arf2 += 2;
                }
            }
            int[,] temp_arr = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp_arr[i, j] = int.Parse(hextodec(arrshift_temp[i, j]));
                }
                               
            }
            string[,] tp = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tp[i, j] = temp_arr[i, j].ToString();

                }
            }
            S = new int[4, 4];
            Mix_col_arr = new string[4, 4];

            for (int c = 0; c < 4; c++)
            {               

                S[0, c] = (Mul02(int.Parse(tp[0, c])) ^ Mul03(int.Parse(tp[1, c])) ^
                                           Mul01(int.Parse(tp[2, c])) ^ Mul01(int.Parse(tp[3, c])));
                                
                S[1, c] = (Mul01(int.Parse(tp[0, c])) ^ Mul02(int.Parse(tp[1, c])) ^
                                         Mul03(int.Parse(tp[2, c])) ^ Mul01(int.Parse(tp[3, c])));
                                
                S[2, c] = (Mul01(int.Parse(tp[0, c])) ^ Mul01(int.Parse(tp[1, c])) ^
                                           Mul02(int.Parse(tp[2, c])) ^ Mul03(int.Parse(tp[3, c])));
                S[3, c] = (Mul03(int.Parse(tp[0, c])) ^ Mul01(int.Parse(tp[1, c])) ^
                                           Mul01(int.Parse(tp[2, c])) ^ Mul02(int.Parse(tp[3, c])));
                               
            }
            // berg3 2lmatrix tany ldecimal
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Mix_col_arr[i, j] = DecimalToHexadecimal(S[i, j]);
                }
                               
            }
            // by4of lw fi 2y item 22l mn 2 y7t zero 2bel 2lrakm
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (Mix_col_arr[i, j].Length < 2)
                    {
                        Mix_col_arr[i, j] = "0" + Mix_col_arr[i, j];
                    }
                    
                }

            }
            s = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    s += Mix_col_arr[j, i];
                }
            }
            return s;
        }

        public static string ShiftRows(string s)
        {
            int count = 0;
            double m = Math.Sqrt(s.Length / 2);
            string[,] arr = new string[(int)m, (int)m];
            List<string> temp_list = new List<string>();
            string t = "";
            for (int i = 0; i < s.Length - 1; i += 2)
            {
                t = s[i].ToString() + s[i + 1].ToString();
                temp_list.Add(t);
            }
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {


                    arr[j, i] = temp_list[count];
                    count++;


                }


            }
           
            arrshift = new string[(int)m, (int)m];
            for (int i = 0; i < 1; i++)
            {
                int j = 0;
                while (j < m)
                {
                    arrshift[i, j] = arr[i, j];
                    j++;
                }
            }


            // blef b 2loops 3 elba2y  w abd2 a3mml shiftlift  w bn3ml mod 3shan ydeny elindex s7 awl wa7ed yt7t fe a5r wa7ed whakaza [1,3]=[1,0]
            for (int i = 1; i < m; i++)
            {


                int j = 0;
                while (j < m)
                {
                    arrshift[i, j] = arr[i, ((j + i) % (int)m)];
                    j++;


                }


            }
            string qq = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    qq += arrshift[j, i];
                }


            }
            return qq;
        }

        public static string[] RotWord(string[] word)
        {
            string[] result = new string[4];
            result[0] = word[1];
            result[1] = word[2];
            result[2] = word[3];
            result[3] = word[0];
            return result;
        }
        static string KeyExpansion(string key, int round)
        {
            string[,] S_box ={
            {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
            {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
            {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
            {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
            {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
            {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
            {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
            {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
            {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
            {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
            {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
            {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
            {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
            {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
            {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
            {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}
            };
            string[,] R_con =
           {
                { "01" , "02" , "04" , "08" , "10" , "20" , "40" , "80" , "1b" , "36"},
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" }



            };
            string[,] new_key = new string[4, 4];
            for (int i = 0, l = 2; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string s = key[l].ToString() + key[l + 1].ToString();
                    new_key[j, i] = s;
                    l += 2;
                }
            }
            string[] temp_key = new string[4];
            for (int i = 0; i < 4; i++)
            {
                temp_key[i] = new_key[i, 3];



            }
            temp_key = RotWord(temp_key);
            string rot_temp = "";
            for (int i = 0; i < 4; i++)
            {
                rot_temp += temp_key[i];



            }
            string subtemp = "";
            rot_temp = rot_temp.ToUpper();
            for (int i = 0; i < rot_temp.Length; i += 2)
            {
                int ind1 = rot_temp[i] - '0';
                if (ind1 > 15) ind1 -= 7;
                int ind2 = rot_temp[i + 1] - '0';
                if (ind2 > 15) ind2 -= 7;
                subtemp += S_box[ind1, ind2];
            }
            string[,] res_key = new string[4, 4];
            for (int i = 0, j = 0; i < 4; i++, j += 2)
            {
                int ky = Convert.ToInt32(new_key[i, 0], 16);
                int sub = Convert.ToInt32(subtemp.Substring(j, 2), 16);
                int rcon = Convert.ToInt32(R_con[i, round], 16);
                int x = ky ^ sub ^ rcon;
                string s = Convert.ToString(x, 16);
                if (x < 16) res_key[i, 0] = "0" + s;
                else res_key[i, 0] = s;
            }
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int reskey = Convert.ToInt32(res_key[j, i - 1], 16);
                    int ky = Convert.ToInt32(new_key[j, i], 16);
                    int x = ky ^ reskey;
                    string s = Convert.ToString(x, 16);
                    if (x < 16) res_key[j, i] = "0" + s;
                    else res_key[j, i] = s;
                }
            }
            string Result_Key = "0x";
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    Result_Key += res_key[j, i];



            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    Console.Write(res_key[i, j]);
                Console.WriteLine();



            }
            Console.WriteLine();
            return Result_Key;
        }

        public static string AddroundKey(string[,] plain, string key)
        {

            string plain1d = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain1d += plain[i, j];
                }
            }
            string result = "";
           /// if (plain1d[1] == 'x' || plain1d[1] == 'X') plain1d = plain1d.Substring(2, 32);
            for (int i = 0; i < plain1d.Length; i += 2)
            {
                int pla = Convert.ToInt32(plain1d.Substring(i, 2), 16);
                int keynum = Convert.ToInt32(key.Substring(i + 2, 2), 16);
                int xr = pla ^ keynum;
                string x = "";
                if (xr < 16) x = "0" + Convert.ToString(xr, 16);
                else x = Convert.ToString(xr, 16);
                result += x;



            }
            return result;
        }
        public static string InvSubBytes(string plainn)
        {
            List<string> new_plain = new List<string>();
            List<string> sub_plain = new List<string>();
            string[,] Sbox_inv ={
                {"52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb"},
                {"7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb"},
                {"54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e"},
                {"08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25"},
                {"72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92"},
                {"6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84"},
                {"90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06"},
                {"d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b"},
                {"3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73"},
                {"96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e"},
                {"47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b"},
                {"fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4"},
                {"1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f"},
                {"60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef"},
                {"a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61"},
                {"17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"},
            };
            for (int i = 0; i < plainn.Length; i++)
            {
                if (plainn[i] == 'A' || plainn[i] == 'a')
                    new_plain.Add("10");
                else if (plainn[i] == 'B' || plainn[i] == 'b')
                    new_plain.Add("11");
                else if (plainn[i] == 'C' || plainn[i] == 'c')
                    new_plain.Add("12");
                else if (plainn[i] == 'D' || plainn[i] == 'd')
                    new_plain.Add("13");
                else if (plainn[i] == 'E' || plainn[i] == 'e')
                    new_plain.Add("14");
                else if (plainn[i] == 'F' || plainn[i] == 'f')
                    new_plain.Add("15");
                else
                    new_plain.Add(plainn[i].ToString());


            }
            for (int k = 2; k < new_plain.Count - 1; k += 2)
            {
                sub_plain.Add(Sbox_inv[int.Parse(new_plain[k]), int.Parse(new_plain[k + 1])]);
            }
            string temp_string = "0x";
            for (int i = 0; i < sub_plain.Count; i++)
            {
                temp_string += sub_plain[i];
            }

            return temp_string;

        }  // InvS
        public static string InvShiftRows(string res)
        {
            string[,] temp = new string[4, 4];
            string[,] p = new string[4, 4];
            int count = 0;
            List<string> temp_list = new List<string>();
            string t = "";
            for (int i = 2; i < res.Length; i += 2)
            {
                t = res[i].ToString() + res[i + 1].ToString();
                temp_list.Add(t);
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    p[j, i] = temp_list[count];
                    count++;

                }

            }
            // sub_plain = new List<string>();
            //for (int i = 0; i < 4; i++)
            //{
            //    for (int j = 0; j < 4; j++)
            //    {

            //        Console.Write(arr[i, j]+" ");

            //    }
            //    Console.WriteLine();
            //}
            // Console.WriteLine("/............................../");

            // arrshift = new string[(int)m, (int)m];
            for (int i = 0; i < 1; i++)
            {
                int j = 0;
                while (j < 4)
                {
                    temp[i, j] = p[i, j];
                    j++;
                }
            }

            //}
            string tww = "0x";
            //for (int r = 0; r < 4; ++r)  // copy State into temp[]
            //{
            //    for (int c = 0; c < 4; ++c)
            //    {
            //        temp[r, c] = p[r, c];
            //    }
            //}
            for (int r = 1; r < 4; ++r)  // shift temp into State
            {
                for (int c = 0; c < 4; ++c)
                {
                    temp[r, (c + r) % 4] = p[r, c];

                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tww += temp[j, i];
                }
            }
            return tww;
        }
        public string InvMixColumns(string res)
        {
            string[,] arrshift_temp = new string[4, 4];

            int[,] temp_arr = new int[4, 4];
            int count_arf2 = 2;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    arrshift_temp[j, i] = res[count_arf2].ToString() + res[count_arf2 + 1].ToString();
                    count_arf2 += 2;

                }
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp_arr[j, i] = int.Parse(hextodec(arrshift_temp[j, i]));
                }

            }
            string[,] tp = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tp[i, j] = temp_arr[i, j].ToString();

                }
            }
            int[,] p = new int[4, 4];
            string[,] Mix_col_arrd = new string[4, 4];


            for (int c = 0; c < 4; ++c)
            {
                p[0, c] = (gfmultby0e(int.Parse(tp[0, c])) ^ gfmultby0b(int.Parse(tp[1, c])) ^
                                           gfmultby0d(int.Parse(tp[2, c])) ^ gfmultby09(int.Parse(tp[3, c])));
                p[1, c] = (gfmultby09(int.Parse(tp[0, c])) ^ gfmultby0e(int.Parse(tp[1, c])) ^
                                           gfmultby0b(int.Parse(tp[2, c])) ^ gfmultby0d(int.Parse(tp[3, c])));
                p[2, c] = (gfmultby0d(int.Parse(tp[0, c])) ^ gfmultby09(int.Parse(tp[1, c])) ^
                                           gfmultby0e(int.Parse(tp[2, c])) ^ gfmultby0b(int.Parse(tp[3, c])));
                p[3, c] = (gfmultby0b(int.Parse(tp[0, c])) ^ gfmultby0d(int.Parse(tp[1, c])) ^
                                           gfmultby09(int.Parse(tp[2, c])) ^ gfmultby0e(int.Parse(tp[3, c])));
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Mix_col_arrd[i, j] = DecimalToHexadecimal(p[i, j]);


                }

            }
            // by4of lw fi 2y item 22l mn 2 y7t zero 2bel 2lrakm
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (Mix_col_arrd[i, j].Length != 2)
                    {
                        Mix_col_arrd[i, j] = "0" + Mix_col_arrd[i, j];
                    }


                }

            }
            string poi = "0x";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    poi += Mix_col_arrd[j, i];
                }
            }
            return poi;
        }  // InvMixColumns

        public static int gfmultby09(int b)
        {
            return (Mul02(Mul02(Mul02(b))) ^ b);
        }
        public static int gfmultby0b(int b)
        {
            return (Mul02(Mul02(Mul02(b))) ^
                           Mul02(b) ^
                           b);
        }
        public static int gfmultby0d(int b)
        {
            return (Mul02(Mul02(Mul02(b))) ^
                           Mul02(Mul02(b)) ^
                           (b));
        }
        public static int gfmultby0e(int b)
        {
            return (Mul02(Mul02(Mul02(b))) ^
                           Mul02(Mul02(b)) ^
                           Mul02(b));
        }
    }
}
