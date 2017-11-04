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
        
        public static string Encrypt(string plainText, string password)
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

                    var cipherTextBytes = memoryStream.ToArray();                                        
                    salt = salt.Concat(checksum).Concat(cipherTextBytes).ToArray();
                    return Convert.ToBase64String(salt);
                }
            }
        }

        public static string Decrypt(string input, string password)
        {
            if (string.IsNullOrEmpty(input)) throw new ArgumentNullException("input");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");

            // Extract the salt from our ciphertext
            byte[] inputBytes = Convert.FromBase64String(input);
            byte[] salt = inputBytes.Take(_saltLength).ToArray();
            byte[] checksum = inputBytes.Skip(_saltLength).Take(_checksumLength).ToArray();
            byte[] cipher = inputBytes.Skip(_saltLength+_checksumLength)
                                            .Take(inputBytes.Length - (_saltLength+_checksumLength))
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
                        if(expectedChecksum.Length == 256 && expectedChecksum != actualChecksum) 
                            throw new ApplicationException(
                                string.Format("ERROR: Invalid checksum found, content cannot be decrypted.  Expected '{0}' but found '{1}'", expectedChecksum, actualChecksum));
                    }

                    return plain;
                }
            }
        }

        public static void EncryptFile(string inputPath, string password, string outputPath)
        {
            if (string.IsNullOrEmpty(inputPath)) throw new ArgumentNullException("inputPath");
            if (string.IsNullOrEmpty(outputPath)) throw new ArgumentNullException("outputPath");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");

            // Derive a new Salt and IV from the Key
            using (var keyDerivationFunction = new Rfc2898DeriveBytes(password, _saltLength, _iterations))
            {
                var saltBytes = keyDerivationFunction.Salt;
                var keyBytes = keyDerivationFunction.GetBytes(_keyLength);
                var ivBytes = keyDerivationFunction.GetBytes(_ivLength);

                // Create an encryptor to perform the stream transform.
                // Create the streams used for encryption.
                using (var aesManaged = new AesManaged(){Padding = PaddingMode.PKCS7})
                using (var encryptor = aesManaged.CreateEncryptor(keyBytes, ivBytes))
                using (var inputStream = new FileStream(inputPath, FileMode.Open))
                {
                    // Hash content
                    var sha = new SHA256Managed();
                    byte[] checksum = sha.ComputeHash(inputStream);
                    inputStream.Seek(0, SeekOrigin.Begin); // reset location

                    using (var outputStream = new FileStream(outputPath, FileMode.Create))
                    using (var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))                
                    {                        
                        
                        outputStream.Write(saltBytes,0, _saltLength); // write salt at start of file - not encrypted.
                        outputStream.Write(checksum, 0, _checksumLength); // write checksum - not encrypted.                        

                        int data;                    
                        while((data = inputStream.ReadByte()) != -1)
                        {                            
                            cryptoStream.WriteByte((byte)data);
                        }
                    }
                }                
            }
        }
       

        public static void DecryptFile(string inputPath, string password, string outputPath)
        {
            if (string.IsNullOrEmpty(inputPath)) throw new ArgumentNullException("inputPath");
            if (string.IsNullOrEmpty(outputPath)) throw new ArgumentNullException("outputPath");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");

            byte[] saltBytes = new byte[_saltLength];        
            byte[] checksum = new byte[_checksumLength];
            string expectedChecksum;

            byte[] ivBytes = new byte[_ivLength];
            byte[] keyBytes = new byte[_keyLength];

            using (var aesManaged = new AesManaged(){Padding = PaddingMode.PKCS7})
            {
                Rfc2898DeriveBytes keyDerivationFunction;
                ICryptoTransform cryptoTransform;

                using (var inputStream = new FileStream(inputPath, FileMode.Open))
                {                
                    inputStream.Read(saltBytes, 0, _saltLength);                
                    inputStream.Read(checksum, 0, _checksumLength);

                    keyDerivationFunction = new Rfc2898DeriveBytes(password, saltBytes, _iterations);
                    keyBytes = keyDerivationFunction.GetBytes(_keyLength);
                    ivBytes = keyDerivationFunction.GetBytes(_ivLength);                        
                    cryptoTransform = aesManaged.CreateDecryptor(keyBytes, ivBytes);
                                        
                    using (var cryptoStream = new CryptoStream(inputStream, cryptoTransform, CryptoStreamMode.Read))                    
                    {                            
                        // Hash content
                        using(var sha = new SHA256Managed()){
                            byte[] fileChecksum = sha.ComputeHash(cryptoStream);
                            expectedChecksum = ByteArrayToString(checksum);
                            var actualChecksum = ByteArrayToString(fileChecksum);
                            if(expectedChecksum.Length == 256 && expectedChecksum != actualChecksum) 
                                throw new ApplicationException(
                                    string.Format("ERROR: Invalid checksum found, content cannot be decrypted.  Expected '{0}' but found '{1}'", expectedChecksum, actualChecksum));
                        }
                    }                
                }

                using (var inputStream = new FileStream(inputPath, FileMode.Open))
                using (var cryptoStream = new CryptoStream(inputStream, cryptoTransform, CryptoStreamMode.Read))                    
                {                                                    
                    inputStream.Seek(_saltLength + _checksumLength, SeekOrigin.Begin); // move to start of encrypted content.

                    using (var outputStream = new FileStream(outputPath, FileMode.Create))
                    {
                        int data;
                        while((data = cryptoStream.ReadByte()) != -1)
                        {                                    
                            outputStream.WriteByte((byte)data);
                        }
                    }
                } 
                keyDerivationFunction.Dispose();
                cryptoTransform.Dispose();
            }
        }
    }
}