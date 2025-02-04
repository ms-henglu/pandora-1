using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Pandora.Definitions.Attributes;
using Pandora.Definitions.Attributes.Validation;
using Pandora.Definitions.CustomTypes;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.ContainerApps.v2023_05_01.ContainerAppsRevisionReplicas;


internal class ReplicaContainerModel
{
    [JsonPropertyName("containerId")]
    public string? ContainerId { get; set; }

    [JsonPropertyName("execEndpoint")]
    public string? ExecEndpoint { get; set; }

    [JsonPropertyName("logStreamEndpoint")]
    public string? LogStreamEndpoint { get; set; }

    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("ready")]
    public bool? Ready { get; set; }

    [JsonPropertyName("restartCount")]
    public int? RestartCount { get; set; }

    [JsonPropertyName("runningState")]
    public ContainerAppContainerRunningStateConstant? RunningState { get; set; }

    [JsonPropertyName("runningStateDetails")]
    public string? RunningStateDetails { get; set; }

    [JsonPropertyName("started")]
    public bool? Started { get; set; }
}
