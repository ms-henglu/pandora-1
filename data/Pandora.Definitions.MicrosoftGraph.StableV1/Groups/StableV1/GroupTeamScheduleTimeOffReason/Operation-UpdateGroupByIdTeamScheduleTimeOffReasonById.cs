// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

using Pandora.Definitions.CustomTypes;
using Pandora.Definitions.Interfaces;
using Pandora.Definitions.MicrosoftGraph.StableV1.CommonTypes;
using System.Collections.Generic;
using System.Net;
using System;

namespace Pandora.Definitions.MicrosoftGraph.StableV1.Groups.StableV1.GroupTeamScheduleTimeOffReason;

internal class UpdateGroupByIdTeamScheduleTimeOffReasonByIdOperation : Operations.PatchOperation
{

    public override IEnumerable<HttpStatusCode> ExpectedStatusCodes() => new List<HttpStatusCode>
        {
            HttpStatusCode.OK,
        };
    public override Type? RequestObject() => typeof(TimeOffReasonModel);
    public override ResourceID? ResourceId() => new GroupIdTeamScheduleTimeOffReasonId();
    public override Type? ResponseObject() => typeof(TimeOffReasonModel);
    public override string? UriSuffix() => null;
}
