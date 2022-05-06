using System.Collections.Generic;
using Pandora.Definitions.Interfaces;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.TrafficManager.v2018_08_01.HeatMaps;

internal class HeatMapTypeId : ResourceID
{
    public string? CommonAlias => null;

    public string ID => "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficManagerProfiles/{profileName}/heatMaps/{heatMapType}";

    public List<ResourceIDSegment> Segments => new List<ResourceIDSegment>
    {
                new()
                {
                    Name = "staticSubscriptions",
                    Type = ResourceIDSegmentType.Static,
                    FixedValue = "subscriptions"
                },

                new()
                {
                    Name = "subscriptionId",
                    Type = ResourceIDSegmentType.SubscriptionId
                },

                new()
                {
                    Name = "staticResourceGroups",
                    Type = ResourceIDSegmentType.Static,
                    FixedValue = "resourceGroups"
                },

                new()
                {
                    Name = "resourceGroupName",
                    Type = ResourceIDSegmentType.ResourceGroup
                },

                new()
                {
                    Name = "staticProviders",
                    Type = ResourceIDSegmentType.Static,
                    FixedValue = "providers"
                },

                new()
                {
                    Name = "staticMicrosoftNetwork",
                    Type = ResourceIDSegmentType.ResourceProvider,
                    FixedValue = "Microsoft.Network"
                },

                new()
                {
                    Name = "staticTrafficManagerProfiles",
                    Type = ResourceIDSegmentType.Static,
                    FixedValue = "trafficManagerProfiles"
                },

                new()
                {
                    Name = "profileName",
                    Type = ResourceIDSegmentType.UserSpecified
                },

                new()
                {
                    Name = "staticHeatMaps",
                    Type = ResourceIDSegmentType.Static,
                    FixedValue = "heatMaps"
                },

                new()
                {
                    Name = "heatMapType",
                    Type = ResourceIDSegmentType.Constant,
                    ConstantReference = typeof(HeatMapTypeConstant)
                },

    };
}
