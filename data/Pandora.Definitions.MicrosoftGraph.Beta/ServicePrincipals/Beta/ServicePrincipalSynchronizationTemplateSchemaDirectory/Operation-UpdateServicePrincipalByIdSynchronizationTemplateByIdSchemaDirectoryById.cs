// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

using Pandora.Definitions.CustomTypes;
using Pandora.Definitions.Interfaces;
using Pandora.Definitions.MicrosoftGraph.Beta.CommonTypes;
using System.Collections.Generic;
using System.Net;
using System;

namespace Pandora.Definitions.MicrosoftGraph.Beta.ServicePrincipals.Beta.ServicePrincipalSynchronizationTemplateSchemaDirectory;

internal class UpdateServicePrincipalByIdSynchronizationTemplateByIdSchemaDirectoryByIdOperation : Operations.PatchOperation
{

    public override IEnumerable<HttpStatusCode> ExpectedStatusCodes() => new List<HttpStatusCode>
        {
            HttpStatusCode.OK,
        };
    public override Type? RequestObject() => typeof(DirectoryDefinitionModel);
    public override ResourceID? ResourceId() => new ServicePrincipalIdSynchronizationTemplateIdSchemaDirectoryId();
    public override Type? ResponseObject() => typeof(DirectoryDefinitionModel);
    public override string? UriSuffix() => null;
}
