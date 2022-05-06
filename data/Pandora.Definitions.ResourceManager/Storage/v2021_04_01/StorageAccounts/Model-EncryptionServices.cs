using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Pandora.Definitions.Attributes;
using Pandora.Definitions.Attributes.Validation;
using Pandora.Definitions.CustomTypes;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.Storage.v2021_04_01.StorageAccounts;


internal class EncryptionServicesModel
{
    [JsonPropertyName("blob")]
    public EncryptionServiceModel? Blob { get; set; }

    [JsonPropertyName("file")]
    public EncryptionServiceModel? File { get; set; }

    [JsonPropertyName("queue")]
    public EncryptionServiceModel? Queue { get; set; }

    [JsonPropertyName("table")]
    public EncryptionServiceModel? Table { get; set; }
}
