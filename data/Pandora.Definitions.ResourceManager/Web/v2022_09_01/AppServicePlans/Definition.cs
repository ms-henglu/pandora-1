using System.Collections.Generic;
using Pandora.Definitions.Interfaces;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.Web.v2022_09_01.AppServicePlans;

internal class Definition : ResourceDefinition
{
    public string Name => "AppServicePlans";
    public IEnumerable<Interfaces.ApiOperation> Operations => new List<Interfaces.ApiOperation>
    {
        new CreateOrUpdateOperation(),
        new CreateOrUpdateVnetRouteOperation(),
        new DeleteOperation(),
        new DeleteHybridConnectionOperation(),
        new DeleteVnetRouteOperation(),
        new GetOperation(),
        new GetHybridConnectionOperation(),
        new GetHybridConnectionPlanLimitOperation(),
        new GetRouteForVnetOperation(),
        new GetServerFarmSkusOperation(),
        new GetVnetFromServerFarmOperation(),
        new GetVnetGatewayOperation(),
        new ListOperation(),
        new ListByResourceGroupOperation(),
        new ListCapabilitiesOperation(),
        new ListHybridConnectionKeysOperation(),
        new ListHybridConnectionsOperation(),
        new ListRoutesForVnetOperation(),
        new ListUsagesOperation(),
        new ListVnetsOperation(),
        new ListWebAppsOperation(),
        new ListWebAppsByHybridConnectionOperation(),
        new RebootWorkerOperation(),
        new RestartWebAppsOperation(),
        new UpdateOperation(),
        new UpdateVnetGatewayOperation(),
        new UpdateVnetRouteOperation(),
    };
    public IEnumerable<System.Type> Constants => new List<System.Type>
    {
        typeof(AutoHealActionTypeConstant),
        typeof(AzureStorageStateConstant),
        typeof(AzureStorageTypeConstant),
        typeof(ClientCertModeConstant),
        typeof(ConnectionStringTypeConstant),
        typeof(DefaultActionConstant),
        typeof(FtpsStateConstant),
        typeof(HostTypeConstant),
        typeof(IPFilterTagConstant),
        typeof(ManagedPipelineModeConstant),
        typeof(ProvisioningStateConstant),
        typeof(RedundancyModeConstant),
        typeof(RouteTypeConstant),
        typeof(ScmTypeConstant),
        typeof(SiteAvailabilityStateConstant),
        typeof(SiteLoadBalancingConstant),
        typeof(SslStateConstant),
        typeof(StatusOptionsConstant),
        typeof(SupportedTlsVersionsConstant),
        typeof(UsageStateConstant),
    };
    public IEnumerable<System.Type> Models => new List<System.Type>
    {
        typeof(ApiDefinitionInfoModel),
        typeof(ApiManagementConfigModel),
        typeof(AppServicePlanModel),
        typeof(AppServicePlanPatchResourceModel),
        typeof(AppServicePlanPatchResourcePropertiesModel),
        typeof(AppServicePlanPropertiesModel),
        typeof(AutoHealActionsModel),
        typeof(AutoHealCustomActionModel),
        typeof(AutoHealRulesModel),
        typeof(AutoHealTriggersModel),
        typeof(AzureStorageInfoValueModel),
        typeof(CapabilityModel),
        typeof(CloningInfoModel),
        typeof(ConnStringInfoModel),
        typeof(CorsSettingsModel),
        typeof(CsmUsageQuotaModel),
        typeof(ExperimentsModel),
        typeof(ExtendedLocationModel),
        typeof(HandlerMappingModel),
        typeof(HostNameSslStateModel),
        typeof(HostingEnvironmentProfileModel),
        typeof(HybridConnectionModel),
        typeof(HybridConnectionKeyModel),
        typeof(HybridConnectionKeyPropertiesModel),
        typeof(HybridConnectionLimitsModel),
        typeof(HybridConnectionLimitsPropertiesModel),
        typeof(HybridConnectionPropertiesModel),
        typeof(IPSecurityRestrictionModel),
        typeof(KubeEnvironmentProfileModel),
        typeof(LocalizableStringModel),
        typeof(NameValuePairModel),
        typeof(PushSettingsModel),
        typeof(PushSettingsPropertiesModel),
        typeof(RampUpRuleModel),
        typeof(RequestsBasedTriggerModel),
        typeof(SiteModel),
        typeof(SiteConfigModel),
        typeof(SiteLimitsModel),
        typeof(SiteMachineKeyModel),
        typeof(SitePropertiesModel),
        typeof(SkuCapacityModel),
        typeof(SkuDescriptionModel),
        typeof(SlotSwapStatusModel),
        typeof(SlowRequestsBasedTriggerModel),
        typeof(StatusCodesBasedTriggerModel),
        typeof(StatusCodesRangeBasedTriggerModel),
        typeof(VirtualApplicationModel),
        typeof(VirtualDirectoryModel),
        typeof(VnetGatewayModel),
        typeof(VnetGatewayPropertiesModel),
        typeof(VnetInfoModel),
        typeof(VnetInfoResourceModel),
        typeof(VnetRouteModel),
        typeof(VnetRoutePropertiesModel),
    };
}
