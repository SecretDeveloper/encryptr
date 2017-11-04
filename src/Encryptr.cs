using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

namespace Encryptr
{
    internal class Encryptr
    {    
        const int _saltLength = 128;
        const int _keyLength = 32;
        const int _ivLength = 16;
        const int _iterations = 100000;
        const int _checksumLength = 32;

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
        
        public static byte[] Encrypt(string plainText, string password)
        {
            if (string.IsNullOrEmpty(plainText)) throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");

            byte[] salt;
            byte[] key;
            byte[] iv;
            
            // Create new pseudo random salt, key and iv using password.
            using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, _saltLength, _iterations))
            {
                salt = keyDerivationFunction.Salt;
                key = keyDerivationFunction.GetBytes(_keyLength);
                iv = keyDerivationFunction.GetBytes(_ivLength);                
            }

            // get sha256 of unencrypted content.
            byte[] checksum = new byte[_checksumLength];
            using(var sha = new SHA256Managed())
                checksum = sha.ComputeHash(Encoding.Unicode.GetBytes(plainText));
            
            // encrypt the content using AES256
            byte[] cipher;
            using (var aes = new AesManaged(){Padding = PaddingMode.PKCS7, KeySize=256})
            using (var encryptor = aes.CreateEncryptor(key, iv))
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                using (var streamWriter = new StreamWriter(cryptoStream))
                {
                    streamWriter.Write(plainText);  // Write our text through cryptostream into encrypted content.
                }
                cipher = memoryStream.ToArray(); // get our encrypted content.
            }            

            return salt.Concat(checksum).Concat(cipher).ToArray(); // concat all the bytes!            
        }

        public static string Decrypt(byte[] input, string password)
        {
            if (input.Length < _saltLength + _checksumLength) throw new ArgumentNullException("input");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");

            // bytestream contains: [salt][checksum][cipher]
            byte[] salt = input.Take(_saltLength).ToArray();
            byte[] checksum = input.Skip(_saltLength).Take(_checksumLength).ToArray();
            var cipher = input.Skip(_saltLength+_checksumLength).ToArray();

            // Derive Key and IV from salt.
            byte[] key;
            byte[] iv;
            using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, salt, _iterations))
            {                
                key = keyDerivationFunction.GetBytes(_keyLength);
                iv = keyDerivationFunction.GetBytes(_ivLength);
            }

            // Decrypt content using AES256 
            string plain;
            using (var aes = new AesManaged(){Padding = PaddingMode.PKCS7, KeySize=256})
            using (var decryptor = aes.CreateDecryptor(key, iv))
            using (var memoryStream = new MemoryStream(cipher))
            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            using (var streamReader = new StreamReader(cryptoStream))
            {                
                plain = streamReader.ReadToEnd(); // Grab decrypted string
            }
                
            // Check checksum
            byte[] contentChecksum;
            using(var sha = new SHA256Managed())
                contentChecksum = sha.ComputeHash(Encoding.Unicode.GetBytes(plain));
                            
            if(contentChecksum.Length != _checksumLength || (ByteArrayToString(checksum) != ByteArrayToString(contentChecksum)))
                throw new ApplicationException(string.Format("ERROR: Invalid checksum found, content cannot be decrypted.  Expected '{0}' but found '{1}'"
                                                            , ByteArrayToString(checksum), ByteArrayToString(contentChecksum)));
        
            return plain;// return our decrypted content.                    
        }        
    }
}