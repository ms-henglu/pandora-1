// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

using System.Collections.Generic;
using Pandora.Definitions.Interfaces;

namespace Pandora.Definitions.MicrosoftGraph.Beta.Users.Beta.UserMobileAppTroubleshootingEventAppLogCollectionRequest;

internal class UserIdMobileAppTroubleshootingEventId : ResourceID
{
    public string? CommonAlias => null;
    public string ID => "/users/{userId}/mobileAppTroubleshootingEvents/{mobileAppTroubleshootingEventId}";

    public List<ResourceIDSegment> Segments => new List<ResourceIDSegment>
    {
        ResourceIDSegment.Static("staticUsers", "users"),
        ResourceIDSegment.UserSpecified("userId"),
        ResourceIDSegment.Static("staticMobileAppTroubleshootingEvents", "mobileAppTroubleshootingEvents"),
        ResourceIDSegment.UserSpecified("mobileAppTroubleshootingEventId")
    };
}
