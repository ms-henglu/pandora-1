using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Pandora.Definitions.Attributes;
using Pandora.Definitions.Attributes.Validation;
using Pandora.Definitions.CustomTypes;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.PowerBIDedicated.v2021_01_01.PowerBIDedicated;


internal class CapacitySkuModel
{
    [JsonPropertyName("capacity")]
    public int? Capacity { get; set; }

    [JsonPropertyName("name")]
    [Required]
    public string Name { get; set; }

    [JsonPropertyName("tier")]
    public CapacitySkuTierConstant? Tier { get; set; }
}
