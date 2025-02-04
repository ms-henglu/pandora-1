// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Pandora.Definitions.Attributes;
using Pandora.Definitions.Attributes.Validation;
using Pandora.Definitions.CustomTypes;


namespace Pandora.Definitions.MicrosoftGraph.Beta.CommonTypes;

internal class ApplePushNotificationCertificateModel
{
    [JsonPropertyName("appleIdentifier")]
    public string? AppleIdentifier { get; set; }

    [JsonPropertyName("certificate")]
    public string? Certificate { get; set; }

    [JsonPropertyName("certificateSerialNumber")]
    public string? CertificateSerialNumber { get; set; }

    [JsonPropertyName("certificateUploadFailureReason")]
    public string? CertificateUploadFailureReason { get; set; }

    [JsonPropertyName("certificateUploadStatus")]
    public string? CertificateUploadStatus { get; set; }

    [JsonPropertyName("expirationDateTime")]
    public DateTime? ExpirationDateTime { get; set; }

    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("lastModifiedDateTime")]
    public DateTime? LastModifiedDateTime { get; set; }

    [JsonPropertyName("@odata.type")]
    public string? ODataType { get; set; }

    [JsonPropertyName("topicIdentifier")]
    public string? TopicIdentifier { get; set; }
}
