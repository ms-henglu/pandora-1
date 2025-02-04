using System.Collections.Generic;
using Pandora.Definitions.Interfaces;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.AutoManage.v2022_05_04.ConfigurationProfileAssignments;

internal class Definition : ResourceDefinition
{
    public string Name => "ConfigurationProfileAssignments";
    public IEnumerable<Interfaces.ApiOperation> Operations => new List<Interfaces.ApiOperation>
    {
        new CreateOrUpdateOperation(),
        new DeleteOperation(),
        new GetOperation(),
        new ListOperation(),
        new ListByClusterNameOperation(),
        new ListByMachineNameOperation(),
        new ListBySubscriptionOperation(),
        new ListByVirtualMachinesOperation(),
    };
    public IEnumerable<System.Type> Constants => new List<System.Type>
    {

    };
    public IEnumerable<System.Type> Models => new List<System.Type>
    {
        typeof(ConfigurationProfileAssignmentModel),
        typeof(ConfigurationProfileAssignmentListModel),
        typeof(ConfigurationProfileAssignmentPropertiesModel),
    };
}
