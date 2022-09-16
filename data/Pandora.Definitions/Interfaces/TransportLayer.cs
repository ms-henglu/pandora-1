using System.ComponentModel;

namespace Pandora.Definitions.Interfaces;

public enum TransportLayer
{
    //<summary>
    // autorest is the default transport for now
    //</summary>
    [Description("autorest")]
    Autorest = 0,

    //<summary>
    // Pandora is the opinionated replacement for Autorest
    //</summary>
    [Description("pandora")]
    Pandora,
}