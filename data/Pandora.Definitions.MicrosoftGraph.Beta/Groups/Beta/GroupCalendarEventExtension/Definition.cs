// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

using Pandora.Definitions.Interfaces;
using Pandora.Definitions.MicrosoftGraph.Beta.CommonTypes;
using System;

namespace Pandora.Definitions.MicrosoftGraph.Beta.Groups.Beta.GroupCalendarEventExtension;

internal class Definition : ResourceDefinition
{
    public string Name => "GroupCalendarEventExtension";

    public IEnumerable<Interfaces.ApiOperation> Operations => new List<Interfaces.ApiOperation>
    {
        new CreateGroupByIdCalendarEventByIdExtensionOperation(),
        new DeleteGroupByIdCalendarEventByIdExtensionByIdOperation(),
        new GetGroupByIdCalendarEventByIdExtensionByIdOperation(),
        new GetGroupByIdCalendarEventByIdExtensionCountOperation(),
        new ListGroupByIdCalendarEventByIdExtensionsOperation(),
        new UpdateGroupByIdCalendarEventByIdExtensionByIdOperation()
    };

    public IEnumerable<System.Type> Constants => new List<System.Type>
    {

    };

    public IEnumerable<System.Type> Models => new List<System.Type>
    {

    };
}
