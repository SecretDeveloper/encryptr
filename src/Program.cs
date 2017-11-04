using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using CliParse;

namespace Encryptr
{
    class Program
    {
        static void Main(string[] args)
        {   
            try
            {
                var cmd = new EncryptrCommand();
                var result = cmd.CliParse(args);
                if(!result.Successful || result.ShowHelp)
                {
                    Console.WriteLine(cmd.GetHelpInfo());
                    Console.WriteLine(string.Join(" ", result.CliParseMessages));
                    return;
                }

                if(cmd.Decrypt == false){
                    if(cmd.InputType == "text")  // string input
                    {
                        if(cmd.OutputValue == "") // write to console
                        {
                            Console.WriteLine(Encryptr.Encrypt(cmd.InputValue, cmd.Password));
                        }
                    }
                    else // file
                    {
                        Encryptr.EncryptFile(cmd.InputValue, cmd.Password, cmd.OutputValue);
                    }
                }
                else
                {
                    if(cmd.InputType == "text")  // string input
                    {
                        if(cmd.OutputValue == "") // write to console
                        {
                            Console.WriteLine(Encryptr.Decrypt(cmd.InputValue, cmd.Password));
                        }
                    }
                    else // file
                    {                        
                        Encryptr.DecryptFile(cmd.InputValue, cmd.Password, cmd.OutputValue);
                    }
                }

            }   
            catch(Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);                
                System.Environment.Exit(1);
            }            
        }
    }
}
