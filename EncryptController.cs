using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using AutomationDash.Models.Encrypt;

namespace AutomationDash.Controllers
{
    public class EncryptController : Controller
    {
        private Encryption encryption = new Encryption();
        // GET: Encrypt
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Index(Encryption encryptions)
        {

            encryptions.EncryptedUsername = Encrypt(encryptions.Username, encryptions.Pin);
            encryptions.EncryptedPassword = Encrypt(encryptions.Password, encryptions.Pin);
            return View(encryptions);
        }

        private const int keysize = 256;
        private const int derivationIterations = 1000;

        // Will only have to use when creating new users
        private static string Encrypt(string plainText, string passPhrase)
        {
            var saltString = GenerateRandomByteArray();
            var ivString = GenerateRandomByteArray();
            var plainTextByteArray = Encoding.UTF8.GetBytes(plainText);

            var password = new Rfc2898DeriveBytes(passPhrase, saltString, derivationIterations);
            var keyBytes = password.GetBytes(keysize / 8);

            RijndaelManaged rijndaelManagedKey = new RijndaelManaged();
            MemoryStream memoryStream = new MemoryStream();

            rijndaelManagedKey.BlockSize = 256;
            rijndaelManagedKey.Mode = CipherMode.CBC;
            rijndaelManagedKey.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = rijndaelManagedKey.CreateEncryptor(keyBytes, ivString);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

            cryptoStream.Write(plainTextByteArray, 0, plainTextByteArray.Length);
            cryptoStream.FlushFinalBlock();

            var cipherTextBytes = saltString;
            cipherTextBytes = cipherTextBytes.Concat(ivString).ToArray();
            cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();

            memoryStream.Close();
            cryptoStream.Close();

            return Convert.ToBase64String(cipherTextBytes);
        }


        private static string Decrypt(string cipherText, string passPhrase)
        {
            try
            {
                var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
                var saltStringByteArray = cipherTextBytesWithSaltAndIv.Take(keysize / 8).ToArray();
                var ivStringByteArray = cipherTextBytesWithSaltAndIv.Skip(keysize / 8).Take(keysize / 8).ToArray();
                var cipherTextBytes =
                    cipherTextBytesWithSaltAndIv.Skip((keysize / 8) * 2)
                        .Take(cipherTextBytesWithSaltAndIv.Length - ((keysize / 8) * 2))
                        .ToArray();

                MemoryStream memoryStream = new MemoryStream(cipherTextBytes);
                var plainTextByteArray = new byte[cipherTextBytes.Length];

                var password = new Rfc2898DeriveBytes(passPhrase, saltStringByteArray, derivationIterations);
                var keyBytes = password.GetBytes(keysize / 8);

                RijndaelManaged rijndaelManagedKey = new RijndaelManaged();

                rijndaelManagedKey.BlockSize = 256;
                rijndaelManagedKey.Mode = CipherMode.CBC;
                rijndaelManagedKey.Padding = PaddingMode.PKCS7;

                var decryptor = rijndaelManagedKey.CreateDecryptor(keyBytes, ivStringByteArray);
                var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

                int decryptedBytes = cryptoStream.Read(plainTextByteArray, 0, plainTextByteArray.Length);

                memoryStream.Close();
                cryptoStream.Close();

                return Encoding.UTF8.GetString(plainTextByteArray, 0, decryptedBytes);
            }
            catch (Exception ex)
            {
                return null;
            }

        }


        private static byte[] GenerateRandomByteArray()
        {
            byte[] randomByteArray = new byte[32];
            using (RNGCryptoServiceProvider rngCryptoService = new RNGCryptoServiceProvider())
            {
                rngCryptoService.GetBytes(randomByteArray);
            }
            return randomByteArray;
        }

    }
}
