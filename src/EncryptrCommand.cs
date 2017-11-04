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

        [ParsableArgument("decrypt", ShortName = 'd')]
        public bool Decrypt { get; set; }
        
        [ParsableArgument("value", ShortName = 'v', DefaultValue = "", ImpliedPosition = 1, Required = true)]
        public string InputValue { get; set; }

        [ParsableArgument("password", ShortName = 'p', DefaultValue = "", ImpliedPosition = 2, Required = true)]
        public string Password { get; set; }

        [ParsableArgument("type", ShortName = 't', DefaultValue = "text")]
        public string InputType { get; set; }

        [ParsableArgument("output", ShortName = 'o', DefaultValue = "")]
        public string OutputValue { get; set; }

        /// Hacky way to parse command line but whatever...
        public override void PostParse(IEnumerable<string> args, CliParseResult result)
        {
            
        }
    }
}
