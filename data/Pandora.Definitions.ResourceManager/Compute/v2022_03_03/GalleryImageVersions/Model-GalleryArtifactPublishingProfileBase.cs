using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Pandora.Definitions.Attributes;
using Pandora.Definitions.Attributes.Validation;
using Pandora.Definitions.CustomTypes;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.Compute.v2022_03_03.GalleryImageVersions;


internal class GalleryArtifactPublishingProfileBaseModel
{
    [DateFormat(DateFormatAttribute.DateFormat.RFC3339)]
    [JsonPropertyName("endOfLifeDate")]
    public DateTime? EndOfLifeDate { get; set; }

    [JsonPropertyName("excludeFromLatest")]
    public bool? ExcludeFromLatest { get; set; }

    [DateFormat(DateFormatAttribute.DateFormat.RFC3339)]
    [JsonPropertyName("publishedDate")]
    public DateTime? PublishedDate { get; set; }

    [JsonPropertyName("replicaCount")]
    public int? ReplicaCount { get; set; }

    [JsonPropertyName("replicationMode")]
    public ReplicationModeConstant? ReplicationMode { get; set; }

    [JsonPropertyName("storageAccountType")]
    public StorageAccountTypeConstant? StorageAccountType { get; set; }

    [JsonPropertyName("targetExtendedLocations")]
    public List<GalleryTargetExtendedLocationModel>? TargetExtendedLocations { get; set; }

    [JsonPropertyName("targetRegions")]
    public List<TargetRegionModel>? TargetRegions { get; set; }
}
