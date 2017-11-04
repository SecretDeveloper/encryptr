using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

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

            // Derive a new Salt and IV from the Key
            using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, _saltLength, _iterations))
            {
                byte[] salt = keyDerivationFunction.Salt;
                byte[] key = keyDerivationFunction.GetBytes(_keyLength);
                byte[] iv = keyDerivationFunction.GetBytes(_ivLength);
                byte[] checksum = new byte[_checksumLength];

                // get sha256 of unencrypted content.
                using(var sha = new SHA256Managed())
                    checksum = sha.ComputeHash(Encoding.Unicode.GetBytes(plainText));
                
                using (var aesManaged = new AesManaged(){Padding = PaddingMode.PKCS7})
                using (var encryptor = aesManaged.CreateEncryptor(key, iv))
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(plainText);
                    }

                    var cipher = memoryStream.ToArray();                                        
                    salt = salt.Concat(checksum).Concat(cipher).ToArray(); // concat all the bytes!
                    return salt;
                }
            }
        }

        public static string Decrypt(byte[] input, string password)
        {
            if (input.Length < _saltLength + _checksumLength) throw new ArgumentNullException("input");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");

            // Extract the salt from our ciphertext            
            byte[] salt = input.Take(_saltLength).ToArray();
            byte[] checksum = input.Skip(_saltLength).Take(_checksumLength).ToArray();
            byte[] cipher = input.Skip(_saltLength+_checksumLength)
                                            .Take(input.Length - (_saltLength+_checksumLength))
                                            .ToArray();

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, salt, _iterations))
            {
                // Derive the previous IV from the Key and Salt
                byte[] keyBytes = keyDerivationFunction.GetBytes(_keyLength);
                byte[] ivBytes = keyDerivationFunction.GetBytes(_ivLength);
                
                // Create a decrytor to perform the stream transform.
                // Create the streams used for decryption.
                // The default Cipher Mode is CBC and the Padding is PKCS7 which are both good
                using (var aesManaged = new AesManaged(){Padding = PaddingMode.PKCS7})
                using (var decryptor = aesManaged.CreateDecryptor(keyBytes, ivBytes))
                using (var memoryStream = new MemoryStream(cipher))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (var streamReader = new StreamReader(cryptoStream))
                {
                    // Return the decrypted bytes from the decrypting stream.
                    var plain = streamReader.ReadToEnd();
                    
                    // Hash content
                    using(var sha = new SHA256Managed()){
                        byte[] contentChecksum = sha.ComputeHash(Encoding.Unicode.GetBytes(plain));
                        var expectedChecksum = ByteArrayToString(checksum);
                        var actualChecksum = ByteArrayToString(contentChecksum);
                        if(expectedChecksum.Length == _checksumLength && expectedChecksum != actualChecksum) 
                            throw new ApplicationException(
                                string.Format("ERROR: Invalid checksum found, content cannot be decrypted.  Expected '{0}' but found '{1}'", expectedChecksum, actualChecksum));
                    }

                    return plain;
                }
            }
        }        
    }
}