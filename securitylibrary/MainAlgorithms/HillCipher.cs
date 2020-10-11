using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;
using MathNet.Numerics.LinearAlgebra.Factorization;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int n = 2;
            int[,] plain_text = new int[n, (plainText.Count / n)];
            int[,] chipher_text = new int[n, (cipherText.Count / n)];
            int[,] temp_plaintext = new int[n, n];
            float[,] temp2_plaintext = new float[n, n];
            int[,] temp_ciphertext = new int[n, n];
            int[,] key = new int[n, n];
            int counter = 0;
            List<int> keyListout = new List<int>();
            List<int> CipherCHeck = new List<int>();
            List<int> plain_text_list = new List<int>();
            List<int> cipheir_text_list = new List<int>();


            for (int i = 0; i < (plainText.Count / n); i++)
            {

                for (int j = 0; j < n; j++)
                {
                    plain_text[j, i] = plainText[counter];
                    chipher_text[j, i] = cipherText[counter++];
                }
            }

            for (int i = 0; i < (plainText.Count / n) - 1; i++)
            {
                temp_plaintext[0, 0] = plain_text[0, i];
                temp_plaintext[1, 0] = plain_text[1, i];
                temp_ciphertext[0, 0] = chipher_text[0, i];
                temp_ciphertext[1, 0] = chipher_text[1, i];
                for (int j = i + 1; j < plainText.Count / n; j++)
                {
                    temp_plaintext[0, 1] = plain_text[0, j];
                    temp_plaintext[1, 1] = plain_text[1, j];


                    temp_ciphertext[0, 1] = chipher_text[0, j];
                    temp_ciphertext[1, 1] = chipher_text[1, j];

                    double det = Determinant_matrix(n, temp_plaintext);
                    det %= 26;
                    if (det < 0)
                        det += 26;
                    int b = 0;
                    b = Inverse_mat((int)det);
                    if (b == -101)
                        continue;
                    if (b < 0)
                        b += 26;
                    int inv = 0;
                    float A, B, C, D;
                    A = (temp_plaintext[0, 0]);
                    B = (temp_plaintext[0, 1]);
                    C = (temp_plaintext[1, 0]);
                    D = (temp_plaintext[1, 1]);
                    inv = (int)b;
                    A *= inv;
                    B *= inv * -1;
                    C *= inv * -1;
                    D *= inv;
                    A %= 26;
                    B %= 26;
                    C %= 26;
                    D %= 26;
                    if (A < 0||B<0||C<0||D<0)
                        A += 26;
                   
                    (temp2_plaintext[0, 0]) = D;
                    (temp2_plaintext[0, 1]) = B;
                    (temp2_plaintext[1, 0]) = C;
                    (temp2_plaintext[1, 1]) = A;


                    keyListout = Muti_matrix(2, temp2_plaintext, temp_ciphertext);
                    CipherCHeck = Encrypt(plainText, keyListout);
                    int count = 0;
                    for (int k = 0; k < plainText.Count; k++)
                    {
                        if (CipherCHeck[k] == cipherText[k])
                            count++;
                    }
                    if (count == plainText.Count)
                        return keyListout;
                }
            }

            throw new InvalidAnlysisException();
        }
        int Inverse_mat(int b)
        {

            int A1 = 1;
            int A2 = 0;
            int A3 = 26;
            int B1 = 0;
            int B2 = 1;
            int B3 = b;
            double T1, T2, T3;
            double Q;
            while (true)
            {
                if (B3 == 0)
                    return -101;
                else if (B3 == 1)
                    return B2;
                Q = A3 / B3;
                T1 = A1 - Q * B1;
                T2 = A2 - Q * B2;
                T3 = A3 - Q * B3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = (int)T1;
                B2 = (int)T2;
                B3 = (int)T3;
            }

        }
        List<int> Muti_matrix(int n, float[,] PlainText, int[,] CipherText)
        {

            double[,] key = new double[n, n];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    key[i, j] = 0;
                    for (int k = 0; k < n; k++)
                    {
                        key[i, j] += CipherText[i, k] * PlainText[k, j];

                    }
                    key[i, j] %= 26;

                }
            }

            List<int> newtemp_key = new List<int>();

            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    newtemp_key.Add((int)key[i, j]);

                }

            }
            return newtemp_key;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)

        {

            List<int> key1 = new List<int>(key.Count);
            int m = Convert.ToInt32(Math.Sqrt(key.Count));
            int[,] keyMatrix = new int[m, m];
            //ba7utaha henna f 2D matrix cipher[]
            int counter = 0;
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    if ((key[counter] >= 0) && (key[counter] <= 26))
                        keyMatrix[i, j] = key[counter++];
                    else if (key[counter] > 26)
                    {
                        //All elements are less than 26

                        int x = key[counter];
                        x %= 26;
                        keyMatrix[i, j] = x;
                        counter++;
                    }
                    else
                    {
                        //All elements are nonnegative 

                        break;

                    }
                }
            }  //2l output bta3 2l determinant
            double output_result = Determinant_matrix(m, keyMatrix);
            output_result %= 26;
            if (output_result < 0)
                output_result += 26;

            int GCD = Greatest_common_divisor((int)output_result);

            //TESTCASE : HillCipherError3
            // No common factors between det(k) and 26(GCD(26, det(k)) = 1)

            if (GCD != 1)
                throw new Exception();

            if (m == 2)
            {

                float inverse = 0;
                float A, B, C, D;
                A = (keyMatrix[0, 0]);
                B = (keyMatrix[0, 1]);
                C = (keyMatrix[1, 0]);
                D = (keyMatrix[1, 1]);
                inverse = 1 / ((A * D) - (B * C));
                A *= inverse;
                B *= inverse * -1;
                C *= inverse * -1;
                D *= inverse;
                key[0] = (int)D;
                key[1] = (int)B;
                key[2] = (int)C;
                key[3] = (int)A;

                return Encrypt(cipherText, key);

            }
            //d henna heya el 3 
            double c = 0, b = 0, d = 0;
            d = 26 - output_result;

            counter = 1;
            for (int i = 0; i < cipherText.Count; i++)
            {

                if ((26 * counter + 1) % d != 0)
                    counter++;
                else
                    break;
            }
            c = (26 * counter + 1) / d;


            b = 26 - c;

            int[,] Sub_matrix = new int[m - 1, m - 1];
            double[,] keyMatrixOutput = new double[m, m];
            int Countj = 0;
            int Counti = 0;
           
            // loop el k de btlef 3l el row

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    // for every cell in key matrix(3*3)
                    int I = 0, J = 0;
                    for (int x = 0; x < 3; x++)
                        for (int y = 0; y < 3; y++)
                        {
                            // for every cell in key matrix 3*3 that
                            // doesn't share a column or row with cell[i,j]

                            if (!(x == i || y == j))
                            {
                                Sub_matrix[I, J] = keyMatrix[x, y];
                                // increment the column counter once
                                J++;
                                // if J == 2 add 1 to the row counter
                                I += (J / 2);
                                // set J to J%2 
                                J %= 2;
                                // naw I point to the row index and J point to the column index
                                
                            }


                        }
                    double ans = Determinant_matrix(m - 1, Sub_matrix);

                    double answer = (b * (Math.Pow(-1, (i + j)) * ans) % 26);
                    if (answer < 0)
                        answer += 26;
                    keyMatrixOutput[Counti, Countj] = answer;
                    Countj++;
                    if (Countj > 2)
                    {
                        Countj = 0;
                        Counti++;
                    }

                }
            }


            int w = keyMatrixOutput.GetLength(0);
            int h = keyMatrixOutput.GetLength(1);

            double[,] result = new double[h, w];

            for (int i = 0; i < w; i++)
            {
                for (int j = 0; j < h; j++)
                {
                    result[j, i] = keyMatrixOutput[i, j];
                }
            }
            
            keyMatrixOutput = result;
            counter = 0;
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    key[counter] = (int)keyMatrixOutput[i, j];
                    counter++;
                }
            }
            return Encrypt(cipherText, key);


        }

        //betgeb el determinant beta3 el matrix
        public double Determinant_matrix(int m, int[,] keyMatrix)
        {

            int[,] Sub_matrix = new int[m - 1, m - 1];
            double det = 0;
            if (m == 2)
            {
                return ((keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[1, 0] * keyMatrix[0, 1]));
            }

            else if (m == 3)
            {

                for (int k = 0; k < m; k++)
                {
                    int subi = 0;
                    for (int i = 1; i < m; i++)
                    {
                        int subj = 0;
                        for (int j = 0; j < m; j++)
                        {
                            if (j == k)
                            {
                                continue;
                            }
                            Sub_matrix[subi, subj] = keyMatrix[i, j];
                            subj++;
                        }
                        subi++;
                    }
                    double res = Determinant_matrix(m - 1, Sub_matrix);
                    det = det + (Math.Pow(-1, k) * keyMatrix[0, k] * res);
                }

            }
            return det;
        }

        public double[,] Transpose(double[,] matrix)
        {
            int w = matrix.GetLength(0);
            int h = matrix.GetLength(1);

            double[,] result = new double[h, w];

            for (int i = 0; i < w; i++)
            {
                for (int j = 0; j < h; j++)
                {
                    result[i, j] = matrix[i, j];
                }
            }

            return result;
        }
        private static int Greatest_common_divisor(int x)
        {
            int y = 26;
            while (x != 0 && y != 0)
            {
                if (x > y)
                    x %= y;
                else
                    y %= x;
            }

            return x == 0 ? y : x;

        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipher = new List<int>(plainText.Count);
            for (int i = 0; i < plainText.Count; i++)
            {
                cipher.Add(0);
            }
            //3shan ye3rf el key matrix kam x kam 
            int n = (int)Math.Sqrt(key.Count);
            int index = 0;
            for (int i = 0; i < plainText.Count; i += n)
            {
                int count = 0, value = 0;
                for (int j = 0; j <= key.Count; j++)
                {
                    if (count == n)
                    {
                        value %= 26;
                        if (value < 0)
                            value += 26;
                        cipher[index] = value;
                        count = 0;
                        value = 0;
                        index++;
                        if (j == key.Count)
                            break;

                    }
                    value += (plainText[i + count] * key[j]);
                    count++;

                }
            }
            return cipher;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int m = (int)Math.Sqrt(plainText.Count);
            double[,] cipherTextMatrix = new double[m, m];
            //ba7utaha henna f 2D matrix cip[]
            int counter = 0;
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    if ((cipherText[counter] >= 0) && (cipherText[counter] <= 26))
                        cipherTextMatrix[j, i] = cipherText[counter++];
                    else if (cipherText[counter] > 26)
                    {
                        //All elements are less than 26

                        int x = cipherText[counter];
                        x %= 26;
                        cipherTextMatrix[j, i] = x;
                        counter++;
                    }
                    else
                    {
                        //All elements are nonnegative 

                        break;

                    }
                }
            }

            int[,] plainTextMatrix = new int[m, m];
            //ba7utaha henna f 2D matrix cip[]
            counter = 0;
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    if ((plainText[counter] >= 0) && (plainText[counter] <= 26))
                        plainTextMatrix[i, j] = plainText[counter++];
                    else if (plainText[counter] > 26)
                    {
                        //All elements are less than 26

                        int x = plainText[counter];
                        x %= 26;
                        plainTextMatrix[i, j] = x;
                        counter++;
                    }
                    else
                    {
                        //All elements are nonnegative
                        break;

                    }
                }
            }
            double dyz = Determinant_matrix(m, plainTextMatrix);
            dyz %= 26;
            if (dyz < 0)
                dyz += 26;
            int gcd = Greatest_common_divisor((int)dyz);

            //TESTCASE : HillCipherError3
            // No common factors between det(k) and 26(GCD(26, det(k)) = 1)

            if (gcd != 1)
                throw new Exception();
            //d henna heya el 3 
            double c = 0, b = 0, d = 0;
            d = 26 - dyz;
            // c = 27 / d;
            counter = 1;

            for (int i = 0; i < plainText.Count; i++)
            {

                if ((26 * counter + 1) % d != 0)
                    counter++;
                else
                    break;
            }
            c = (26 * counter + 1) / d;


            b = 26 - c;
            int[,] SUBMat = new int[m - 1, m - 1];
            double[,] plainTextMatrixOutput = new double[m, m];
            int jCounter = 0;
            int iCounter = 0;

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    // for every cell in key matrix(3*3)
                    int I = 0, J = 0;
                    for (int x = 0; x < 3; x++)
                        for (int y = 0; y < 3; y++)
                        {
                            // for every cell in key matrix 3*3 that
                            // doesn't share a column or row with cell[i,j]

                            if (!(x == i || y == j))
                            {
                                SUBMat[I, J] = plainTextMatrix[x, y];
                                // increment the column counter once
                                J++;
                                // if J == 2 add 1 to the row counter
                                I += (J / 2);
                                // set J to J%2 (always cuz i'm a lazy man)
                                J %= 2;
                                // naw I point to the row index and J point to the column index
                                // have fun <3
                            }


                        }
                    double ans = Determinant_matrix(m - 1, SUBMat);

                    double answer = (b * (Math.Pow(-1, (i + j)) * ans) % 26);
                    if (answer < 0)
                        answer += 26;
                    plainTextMatrixOutput[iCounter, jCounter] = answer;
                    jCounter++;
                    if (jCounter > 2)
                    {
                        jCounter = 0;
                        iCounter++;
                    }

                }
            }


            plainTextMatrixOutput = Transpose(plainTextMatrixOutput);
            int cimxm = (int)Math.Sqrt(cipherText.Count);
            double[,] key = new double[m, cimxm];
            for (int i = 0; i < 3; i++)//K
            {
                for (int j = 0; j < m; j++)//I
                {
                    key[i, j] = 0;
                    for (int k = 0; k < m; k++)//J
                    {
                        key[i, j] += (cipherTextMatrix[j, k] * plainTextMatrixOutput[k, i]);
                        key[i, j] %= 26;
                    }
                    //  key[i, j]%=26;
                }
            }

            List<int> keys = new List<int>(9);

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    keys.Add((int)key[j, i]);

                }
            }
            return keys;

        }

    }
}
