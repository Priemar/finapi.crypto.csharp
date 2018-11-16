using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Your.Namespace
{
    /// <summary>
    /// FinApi Encryption/Decryption
    /// </summary>
    public static class CryptoUtils
    {
        /// <summary>
        /// Decrypt encrypted text with data decryption key
        /// Algorithm: AES128 PKCS5 (padding 5, FYI: PKCS7 supports PKCS5)
        /// FinAPI: Key length = 128bit
        /// Iterations: 1000
        /// </summary>
        /// <param name="encrypted">encrypted text</param>
        /// <param name="ddk">data decryption key</param>
        public static string Decrypt(string encrypted, string ddk)
        {
            string result;
            using (Aes aesAlg = Aes.Create())
            {
                //the salt is the ddk converted to hex
                //convert to hex and then to byte array
                var salt = Enumerable.Range(0, ddk.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(ddk.Substring(x, 2), 16)).ToArray();
                //hash the salt with 1000 iterations
                using (var pbkdf2 = new Rfc2898DeriveBytes(ddk, salt) { IterationCount = 1000 })
                {
                    //set the key based on the hash (16: bec. we need a 128 bit key =>  16 bytes * 8 = 128 bit! easy)
                    aesAlg.Key = pbkdf2.GetBytes(16);
                }
                //the encrypted text is a base64 string
                byte[] cipherText = Convert.FromBase64String(encrypted);
                //set iv and mode
                aesAlg.IV = salt;
                aesAlg.Mode = CipherMode.CBC;
                //as you can see in the summary PKCS7 supports PKCS5
                aesAlg.Padding = PaddingMode.PKCS7;
                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            result = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return result;
        }
        /// <summary>
        /// Encrypt
        /// Algorithm: AES128 PKCS5 (padding 5, FYI: PKCS7 supports PKCS5)
        /// FinAPI: Key length = 128bit
        /// Iterations: 1000
        /// </summary>
        /// <param name="text">unencrypted text</param>
        /// <param name="ddk">data decryption key</param>
        /// <returns></returns>
        public static string Encrypt(string text, string ddk)
        {
            string result;
            using (Aes aesAlg = Aes.Create())
            {
                //the salt is the ddk converted to hex
                //convert to hex and then to byte array
                var salt = Enumerable.Range(0, ddk.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(ddk.Substring(x, 2), 16)).ToArray();
                //hash the salt with 1000 iterations
                using (var pbkdf2 = new Rfc2898DeriveBytes(ddk, salt) { IterationCount = 1000 })
                {
                    //set the key based on the hash (16: bec. we need a 128 bit key =>  16 bytes * 8 = 128 bit! easy)
                    aesAlg.Key = pbkdf2.GetBytes(16);
                }
                //the encrypted text is a base64 string
                byte[] decryptedText = Encoding.UTF8.GetBytes(text);
                //set iv and mode
                aesAlg.IV = salt;
                aesAlg.Mode = CipherMode.CBC;
                //as you can see in the summary PKCS7 supports PKCS5
                aesAlg.Padding = PaddingMode.PKCS7;
                ICryptoTransform decryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream output = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(output, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(decryptedText, 0, decryptedText.Length);
                        cryptoStream.FlushFinalBlock();
                        //convert result bytes to base64
                        result = Convert.ToBase64String(output.ToArray());
                    }
                }
            }
            return result;
        }
    }
}
