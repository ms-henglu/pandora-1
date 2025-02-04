using Pandora.Definitions.Attributes;
using Pandora.Definitions.CustomTypes;
using Pandora.Definitions.Interfaces;
using System;
using System.Collections.Generic;
using System.Net;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.TrafficManager.v2022_04_01.Profiles;

internal class CheckTrafficManagerNameAvailabilityV2Operation : Pandora.Definitions.Operations.PostOperation
{
    public override IEnumerable<HttpStatusCode> ExpectedStatusCodes() => new List<HttpStatusCode>
        {
                HttpStatusCode.OK,
        };

    public override Type? RequestObject() => typeof(CheckTrafficManagerRelativeDnsNameAvailabilityParametersModel);

    public override ResourceID? ResourceId() => new SubscriptionId();

    public override Type? ResponseObject() => typeof(TrafficManagerNameAvailabilityModel);

    public override string? UriSuffix() => "/providers/Microsoft.Network/checkTrafficManagerNameAvailabilityV2";


}
