using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Pandora.Definitions.Attributes;
using Pandora.Definitions.Attributes.Validation;
using Pandora.Definitions.CustomTypes;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.Blueprints.v2018_11_01_preview.Assignment;


internal class AssignmentPropertiesModel
{
    [JsonPropertyName("blueprintId")]
    public string? BlueprintId { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("displayName")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("locks")]
    public AssignmentLockSettingsModel? Locks { get; set; }

    [JsonPropertyName("parameters")]
    [Required]
    public Dictionary<string, ParameterValueModel> Parameters { get; set; }

    [JsonPropertyName("provisioningState")]
    public AssignmentProvisioningStateConstant? ProvisioningState { get; set; }

    [JsonPropertyName("resourceGroups")]
    [Required]
    public Dictionary<string, ResourceGroupValueModel> ResourceGroups { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [JsonPropertyName("status")]
    public AssignmentStatusModel? Status { get; set; }
}
