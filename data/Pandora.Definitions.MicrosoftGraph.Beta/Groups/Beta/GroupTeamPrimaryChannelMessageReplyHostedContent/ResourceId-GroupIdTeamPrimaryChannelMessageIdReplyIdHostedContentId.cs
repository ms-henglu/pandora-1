// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

using System.Collections.Generic;
using Pandora.Definitions.Interfaces;

namespace Pandora.Definitions.MicrosoftGraph.Beta.Groups.Beta.GroupTeamPrimaryChannelMessageReplyHostedContent;

internal class GroupIdTeamPrimaryChannelMessageIdReplyIdHostedContentId : ResourceID
{
    public string? CommonAlias => null;
    public string ID => "/groups/{groupId}/team/primaryChannel/messages/{chatMessageId}/replies/{chatMessageId1}/hostedContents/{chatMessageHostedContentId}";

    public List<ResourceIDSegment> Segments => new List<ResourceIDSegment>
    {
        ResourceIDSegment.Static("staticGroups", "groups"),
        ResourceIDSegment.UserSpecified("groupId"),
        ResourceIDSegment.Static("staticTeam", "team"),
        ResourceIDSegment.Static("staticPrimaryChannel", "primaryChannel"),
        ResourceIDSegment.Static("staticMessages", "messages"),
        ResourceIDSegment.UserSpecified("chatMessageId"),
        ResourceIDSegment.Static("staticReplies", "replies"),
        ResourceIDSegment.UserSpecified("chatMessageId1"),
        ResourceIDSegment.Static("staticHostedContents", "hostedContents"),
        ResourceIDSegment.UserSpecified("chatMessageHostedContentId")
    };
}
