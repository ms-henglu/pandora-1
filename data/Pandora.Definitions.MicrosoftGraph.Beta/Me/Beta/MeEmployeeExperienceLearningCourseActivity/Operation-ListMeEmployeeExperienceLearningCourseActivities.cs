// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

using Pandora.Definitions.CustomTypes;
using Pandora.Definitions.Interfaces;
using Pandora.Definitions.MicrosoftGraph.Beta.CommonTypes;
using System;

namespace Pandora.Definitions.MicrosoftGraph.Beta.Me.Beta.MeEmployeeExperienceLearningCourseActivity;

internal class ListMeEmployeeExperienceLearningCourseActivitiesOperation : Operations.ListOperation
{
    public override string? FieldContainingPaginationDetails() => "nextLink";
    public override ResourceID? ResourceId() => null;
    public override Type NestedItemType() => typeof(LearningCourseActivityCollectionResponseModel);
    public override string? UriSuffix() => "/me/employeeExperience/learningCourseActivities";
}
