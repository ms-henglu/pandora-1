using Pandora.Definitions.Attributes;
using System.ComponentModel;

namespace Pandora.Definitions.ResourceManager.Media.v2022_08_01.AccountFilters;

[ConstantType(ConstantTypeAttribute.ConstantType.String)]
internal enum FilterTrackPropertyCompareOperationConstant
{
    [Description("Equal")]
    Equal,

    [Description("NotEqual")]
    NotEqual,
}
