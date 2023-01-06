using Pandora.Definitions.Attributes;
using System.ComponentModel;

namespace Pandora.Definitions.ResourceManager.RecoveryServicesBackup.v2021_12_01.BackupPolicies;

[ConstantType(ConstantTypeAttribute.ConstantType.String)]
internal enum ScheduleRunTypeConstant
{
    [Description("Daily")]
    Daily,

    [Description("Hourly")]
    Hourly,

    [Description("Invalid")]
    Invalid,

    [Description("Weekly")]
    Weekly,
}
