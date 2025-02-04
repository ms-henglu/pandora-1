using System.Collections.Generic;
using Pandora.Definitions.Interfaces;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.Cognitive.v2023_05_01.CognitiveServicesAccounts;

internal class Definition : ResourceDefinition
{
    public string Name => "CognitiveServicesAccounts";
    public IEnumerable<Interfaces.ApiOperation> Operations => new List<Interfaces.ApiOperation>
    {
        new AccountsCreateOperation(),
        new AccountsDeleteOperation(),
        new AccountsGetOperation(),
        new AccountsListOperation(),
        new AccountsListByResourceGroupOperation(),
        new AccountsListKeysOperation(),
        new AccountsListModelsOperation(),
        new AccountsListSkusOperation(),
        new AccountsListUsagesOperation(),
        new AccountsRegenerateKeyOperation(),
        new AccountsUpdateOperation(),
        new CheckDomainAvailabilityOperation(),
        new CheckSkuAvailabilityOperation(),
        new DeletedAccountsGetOperation(),
        new DeletedAccountsListOperation(),
        new DeletedAccountsPurgeOperation(),
        new ResourceSkusListOperation(),
    };
    public IEnumerable<System.Type> Constants => new List<System.Type>
    {
        typeof(AbusePenaltyActionConstant),
        typeof(KeyNameConstant),
        typeof(KeySourceConstant),
        typeof(ModelLifecycleStatusConstant),
        typeof(NetworkRuleActionConstant),
        typeof(PrivateEndpointConnectionProvisioningStateConstant),
        typeof(PrivateEndpointServiceConnectionStatusConstant),
        typeof(ProvisioningStateConstant),
        typeof(PublicNetworkAccessConstant),
        typeof(QuotaUsageStatusConstant),
        typeof(ResourceSkuRestrictionsReasonCodeConstant),
        typeof(ResourceSkuRestrictionsTypeConstant),
        typeof(RoutingMethodsConstant),
        typeof(SkuTierConstant),
        typeof(UnitTypeConstant),
    };
    public IEnumerable<System.Type> Models => new List<System.Type>
    {
        typeof(AbusePenaltyModel),
        typeof(AccountModel),
        typeof(AccountModelModel),
        typeof(AccountPropertiesModel),
        typeof(AccountSkuModel),
        typeof(AccountSkuListResultModel),
        typeof(ApiKeysModel),
        typeof(ApiPropertiesModel),
        typeof(CallRateLimitModel),
        typeof(CapacityConfigModel),
        typeof(CheckDomainAvailabilityParameterModel),
        typeof(CheckSkuAvailabilityParameterModel),
        typeof(CommitmentPlanAssociationModel),
        typeof(DeploymentModelModel),
        typeof(DomainAvailabilityModel),
        typeof(EncryptionModel),
        typeof(IPRuleModel),
        typeof(KeyVaultPropertiesModel),
        typeof(MetricNameModel),
        typeof(ModelDeprecationInfoModel),
        typeof(ModelSkuModel),
        typeof(MultiRegionSettingsModel),
        typeof(NetworkRuleSetModel),
        typeof(PrivateEndpointModel),
        typeof(PrivateEndpointConnectionModel),
        typeof(PrivateEndpointConnectionPropertiesModel),
        typeof(PrivateLinkServiceConnectionStateModel),
        typeof(QuotaLimitModel),
        typeof(RegenerateKeyParametersModel),
        typeof(RegionSettingModel),
        typeof(RequestMatchPatternModel),
        typeof(ResourceSkuModel),
        typeof(ResourceSkuRestrictionInfoModel),
        typeof(ResourceSkuRestrictionsModel),
        typeof(SkuModel),
        typeof(SkuAvailabilityModel),
        typeof(SkuAvailabilityListResultModel),
        typeof(SkuCapabilityModel),
        typeof(SkuChangeInfoModel),
        typeof(ThrottlingRuleModel),
        typeof(UsageModel),
        typeof(UsageListResultModel),
        typeof(UserOwnedStorageModel),
        typeof(VirtualNetworkRuleModel),
    };
}
