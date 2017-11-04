using System;
using System.Text;
using System.IO;
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

                var input = string.IsNullOrEmpty(cmd.Text)? File.ReadAllText(cmd.InputFile): cmd.Text;
                
                var sb = new StringBuilder();
                if(!cmd.Decrypt)
                    sb.Append(Convert.ToBase64String(Encryptr.Encrypt(input, cmd.Password)));                
                else // Decrypting
                    sb.Append(Encryptr.Decrypt(Convert.FromBase64String(input), cmd.Password));

                if(string.IsNullOrEmpty(cmd.OutputFile))
                    Console.WriteLine(sb.ToString());
                else
                    File.WriteAllText(cmd.OutputFile, sb.ToString());
            }   
            catch(Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message); 
                Console.WriteLine("Error: " + ex.StackTrace);                
                System.Environment.Exit(1);
            }            
        }
    }
}
