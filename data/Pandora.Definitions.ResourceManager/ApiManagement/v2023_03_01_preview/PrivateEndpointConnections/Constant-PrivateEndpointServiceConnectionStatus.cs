using Pandora.Definitions.Attributes;
using System.ComponentModel;

namespace Pandora.Definitions.ResourceManager.ApiManagement.v2023_03_01_preview.PrivateEndpointConnections;

[ConstantType(ConstantTypeAttribute.ConstantType.String)]
internal enum PrivateEndpointServiceConnectionStatusConstant
{
    [Description("Approved")]
    Approved,

    [Description("Pending")]
    Pending,

    [Description("Rejected")]
    Rejected,
}
