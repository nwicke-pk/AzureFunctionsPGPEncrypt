using System;
using System.Collections.Generic;
using System.Text;

namespace AzureFunctionsPGPService
{
    public class PGPRequest
    {
        public string Action { get; set; }
        public string Key { get; set; }
        public string ContainerName { get; set; }
        public string SourceFileName { get; set; }
        public string DestinationFileName { get; set; }
        public string PassPhrase { get; set; }

    }
}
