using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Collections.Generic;
using CliParse;

namespace src
{
    [ParsableClass("Encryptr", "Simple encryption tool")]
    internal class EncryptrCommand:Parsable
    {
        [ParsableArgument("command", ShortName = 'c', DefaultValue = "e", ImpliedPosition = 1, Required=true)]
        public string Command { get; set; }
        
        [ParsableArgument("value", ShortName = 'v', DefaultValue = "", ImpliedPosition = 2, Required = true)]
        public string InputValue { get; set; }

        [ParsableArgument("password", ShortName = 'p', DefaultValue = "", ImpliedPosition = 3, Required = true)]
        public string Password { get; set; }

        [ParsableArgument("type", ShortName = 't', DefaultValue = "text")]
        public string InputType { get; set; }

        [ParsableArgument("output", ShortName = 'o', DefaultValue = "")]
        public string OutputValue { get; set; }

        /// Hacky way to parse command line but whatever...
        public override void PostParse(IEnumerable<string> args, CliParseResult result)
        {
            this.Command = (this.Command == "e") ?  "encrypt" : "decrypt";            
        }
    }

    class Program
    {
        static void Main(string[] args)
        {   
            try
            {
                //Console.WriteLine("Encryptr: file and text encryptor");
                var cmd = new EncryptrCommand();
                var result = cmd.CliParse(args);
                if(!result.Successful || result.ShowHelp)
                {
                    // Show help screen
                    Console.WriteLine(cmd.GetHelpInfo());
                    Console.WriteLine(string.Join(" ", result.CliParseMessages));
                    // exit
                    return;
                }


                if(cmd.Command == "encrypt"){
                    if(cmd.InputType == "text")  // string input
                    {
                        if(cmd.OutputValue == "") // write to console
                        {
                            Console.WriteLine(Encrypt(cmd.InputValue, cmd.Password));
                        }
                    }
                }
                else
                {
                        if(cmd.InputType == "text")  // string input
                    {
                        if(cmd.OutputValue == "") // write to console
                        {
                            Console.WriteLine(Decrypt(cmd.InputValue, cmd.Password));
                        }
                    }
                }

            }   
            catch(Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                Console.WriteLine("Stacktrace: " + ex.StackTrace);
                System.Environment.Exit(1);
            }            
        }



        const int _saltLength = 32;
        const int _iterations = 10000;
        static string Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText)) throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException("key");

            // Derive a new Salt and IV from the Key
            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, _saltLength, _iterations))
            {
                var saltBytes = keyDerivationFunction.Salt;
                var keyBytes = keyDerivationFunction.GetBytes(32);
                var ivBytes = keyDerivationFunction.GetBytes(16);

                // Create an encryptor to perform the stream transform.
                // Create the streams used for encryption.
                using (var aesManaged = new AesManaged())
                using (var encryptor = aesManaged.CreateEncryptor(keyBytes, ivBytes))
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    using (var streamWriter = new StreamWriter(cryptoStream))
                    {
                        // Send the data through the StreamWriter, through the CryptoStream, to the underlying MemoryStream
                        streamWriter.Write(plainText);
                    }

                    // Return the encrypted bytes from the memory stream, in Base64 form so we can send it right to a database (if we want).
                    var cipherTextBytes = memoryStream.ToArray();
                    Array.Resize(ref saltBytes, saltBytes.Length + cipherTextBytes.Length);
                    Array.Copy(cipherTextBytes, 0, saltBytes, _saltLength, cipherTextBytes.Length);

                    //saltBytes = saltBytes.Concat(cipherTextBytes).ToArray();

                    return Convert.ToBase64String(saltBytes);
                }
            }
        }

        static string Decrypt(string ciphertext, string key)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw new ArgumentNullException("cipherText");
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");

            // Extract the salt from our ciphertext
            var allTheBytes = Convert.FromBase64String(ciphertext);
            var saltBytes = allTheBytes.Take(_saltLength).ToArray();
            var ciphertextBytes = allTheBytes.Skip(_saltLength).Take(allTheBytes.Length - _saltLength).ToArray();

            using (var keyDerivationFunction = new Rfc2898DeriveBytes(key, saltBytes, _iterations))
            {
                // Derive the previous IV from the Key and Salt
                var keyBytes = keyDerivationFunction.GetBytes(32);
                var ivBytes = keyDerivationFunction.GetBytes(16);
                
                // Create a decrytor to perform the stream transform.
                // Create the streams used for decryption.
                // The default Cipher Mode is CBC and the Padding is PKCS7 which are both good
                using (var aesManaged = new AesManaged())
                using (var decryptor = aesManaged.CreateDecryptor(keyBytes, ivBytes))
                using (var memoryStream = new MemoryStream(ciphertextBytes))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (var streamReader = new StreamReader(cryptoStream))
                {
                    // Return the decrypted bytes from the decrypting stream.
                    return streamReader.ReadToEnd();
                }
            }
        }
    }
}
