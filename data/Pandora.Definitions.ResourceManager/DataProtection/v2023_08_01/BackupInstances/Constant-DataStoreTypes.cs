using Pandora.Definitions.Attributes;
using System.ComponentModel;

namespace Pandora.Definitions.ResourceManager.DataProtection.v2023_08_01.BackupInstances;

[ConstantType(ConstantTypeAttribute.ConstantType.String)]
internal enum DataStoreTypesConstant
{
    [Description("ArchiveStore")]
    ArchiveStore,

    [Description("OperationalStore")]
    OperationalStore,

    [Description("VaultStore")]
    VaultStore,
}
