using Pandora.Definitions.Attributes;
using System.ComponentModel;

namespace Pandora.Definitions.ResourceManager.Web.v2023_01_01.Provider;

[ConstantType(ConstantTypeAttribute.ConstantType.String)]
internal enum StackPreferredOsConstant
{
    [Description("Linux")]
    Linux,

    [Description("Windows")]
    Windows,
}
