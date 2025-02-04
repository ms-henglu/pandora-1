// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Pandora.Definitions.Attributes;
using Pandora.Definitions.Attributes.Validation;
using Pandora.Definitions.CustomTypes;


namespace Pandora.Definitions.MicrosoftGraph.StableV1.CommonTypes;

internal class AdminModel
{
    [JsonPropertyName("edge")]
    public EdgeModel? Edge { get; set; }

    [JsonPropertyName("@odata.type")]
    public string? ODataType { get; set; }

    [JsonPropertyName("people")]
    public PeopleAdminSettingsModel? People { get; set; }

    [JsonPropertyName("serviceAnnouncement")]
    public ServiceAnnouncementModel? ServiceAnnouncement { get; set; }

    [JsonPropertyName("sharepoint")]
    public SharepointModel? Sharepoint { get; set; }
}
