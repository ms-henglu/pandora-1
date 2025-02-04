using Pandora.Definitions.Attributes;
using System.ComponentModel;

namespace Pandora.Definitions.ResourceManager.ContainerService.v2023_10_15.UpdateRuns;

[ConstantType(ConstantTypeAttribute.ConstantType.String)]
internal enum NodeImageSelectionTypeConstant
{
    [Description("Consistent")]
    Consistent,

    [Description("Latest")]
    Latest,
}
