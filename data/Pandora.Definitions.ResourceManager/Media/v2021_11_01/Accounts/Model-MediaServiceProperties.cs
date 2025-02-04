using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Pandora.Definitions.Attributes;
using Pandora.Definitions.Attributes.Validation;
using Pandora.Definitions.CustomTypes;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.Media.v2021_11_01.Accounts;


internal class MediaServicePropertiesModel
{
    [JsonPropertyName("encryption")]
    public AccountEncryptionModel? Encryption { get; set; }

    [JsonPropertyName("keyDelivery")]
    public KeyDeliveryModel? KeyDelivery { get; set; }

    [JsonPropertyName("mediaServiceId")]
    public string? MediaServiceId { get; set; }

    [JsonPropertyName("privateEndpointConnections")]
    public List<PrivateEndpointConnectionModel>? PrivateEndpointConnections { get; set; }

    [JsonPropertyName("provisioningState")]
    public ProvisioningStateConstant? ProvisioningState { get; set; }

    [JsonPropertyName("publicNetworkAccess")]
    public PublicNetworkAccessConstant? PublicNetworkAccess { get; set; }

    [JsonPropertyName("storageAccounts")]
    public List<StorageAccountModel>? StorageAccounts { get; set; }

    [JsonPropertyName("storageAuthentication")]
    public StorageAuthenticationConstant? StorageAuthentication { get; set; }
}
