using Pandora.Definitions.Attributes;
using Pandora.Definitions.Interfaces;
using Pandora.Definitions.Operations;
using System.Collections.Generic;
using System.Net;

namespace Pandora.Definitions.ResourceManager.PowerBIDedicated.v2021_01_01.Capacities
{
    internal class ListByResourceGroupOperation : Operations.GetOperation
    {
        public override ResourceID? ResourceId()
        {
            return new ResourceGroupId();
        }

        public override object? ResponseObject()
        {
            return new DedicatedCapacities();
        }

        public override string? UriSuffix()
        {
            return "/providers/Microsoft.PowerBIDedicated/capacities";
        }


    }
}
