using System.Collections.Generic;
using CliParse;

namespace Encryptr
{
    [ParsableClass("Encryptr", "Simple encryption tool")]
    internal class EncryptrCommand:Parsable
    {
        public EncryptrCommand()
        {
        }

        [ParsableArgument("password", ShortName = 'p', DefaultValue = "", ImpliedPosition = 1, Required = true)]
        public string Password { get; set; }
                
        [ParsableArgument("text", ShortName = 't', DefaultValue = "", ImpliedPosition = 2, Required = false)]
        public string Text { get; set; }

        [ParsableArgument("decrypt", ShortName = 'd')]
        public bool Decrypt { get; set; }

        [ParsableArgument("input", ShortName = 'i', DefaultValue = "")]
        public string InputFile { get; set; }

        [ParsableArgument("output", ShortName = 'o', DefaultValue = "")]
        public string OutputFile { get; set; }

        /// Hacky way to parse command line but whatever...
        public override void PostParse(IEnumerable<string> args, CliParseResult result)
        {
            
        }
    }
}
