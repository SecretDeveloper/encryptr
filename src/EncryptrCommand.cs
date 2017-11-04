using System.Collections.Generic;
using CliParse;

namespace Encryptr
{
    [ParsableClass("Encryptr", "AES256 encryption tool.  Encrypted content is encoded as base64.",
    FooterText=@"Examples:
    Encryption:
    encryptr 'mypassword' 'my content to encrypt'
    Decryption:
    encryptr 'mypassword' 'BASE64_STRING' -d ")]
    internal class EncryptrCommand:Parsable
    {
        public EncryptrCommand()
        {
        }

        [ParsableArgument("password", ShortName = 'p', DefaultValue = "", ImpliedPosition = 1, Required = true, Description="The password used to encrypt and decrypt your content, do not forget it or all is lost!")]
        public string Password { get; set; }
                
        [ParsableArgument("text", ShortName = 't', DefaultValue = "", ImpliedPosition = 2, Required = false, Description="The text to be encrypted or decrypted.")]
        public string Text { get; set; }

        [ParsableArgument("decrypt", ShortName = 'd', Description="Decrypt flag")]
        public bool Decrypt { get; set; }

        [ParsableArgument("input", ShortName = 'i', DefaultValue = "Path to input FILE to be encrypted or decrypted.")]
        public string InputFile { get; set; }

        [ParsableArgument("output", ShortName = 'o', DefaultValue = "Path to output FILE where content will be written,  if ommitted content is written to STDOUT.")]
        public string OutputFile { get; set; }

        /// Hacky way to parse command line but whatever...
        public override void PostParse(IEnumerable<string> args, CliParseResult result)
        {
            
        }
    }
}
