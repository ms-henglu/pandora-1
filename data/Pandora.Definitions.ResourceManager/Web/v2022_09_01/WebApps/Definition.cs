using System.Collections.Generic;
using Pandora.Definitions.Interfaces;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.Web.v2022_09_01.WebApps;

internal class Definition : ResourceDefinition
{
    public string Name => "WebApps";
    public IEnumerable<Interfaces.ApiOperation> Operations => new List<Interfaces.ApiOperation>
    {
        new AddPremierAddOnOperation(),
        new AddPremierAddOnSlotOperation(),
        new AnalyzeCustomHostnameOperation(),
        new AnalyzeCustomHostnameSlotOperation(),
        new ApplySlotConfigToProductionOperation(),
        new ApplySlotConfigurationSlotOperation(),
        new ApproveOrRejectPrivateEndpointConnectionOperation(),
        new ApproveOrRejectPrivateEndpointConnectionSlotOperation(),
        new BackupOperation(),
        new BackupSlotOperation(),
        new CreateDeploymentOperation(),
        new CreateDeploymentSlotOperation(),
        new CreateFunctionOperation(),
        new CreateInstanceFunctionSlotOperation(),
        new CreateInstanceMSDeployOperationOperation(),
        new CreateInstanceMSDeployOperationSlotOperation(),
        new CreateMSDeployOperationOperation(),
        new CreateMSDeployOperationSlotOperation(),
        new CreateOneDeployOperationOperation(),
        new CreateOrUpdateOperation(),
        new CreateOrUpdateConfigurationOperation(),
        new CreateOrUpdateConfigurationSlotOperation(),
        new CreateOrUpdateDomainOwnershipIdentifierOperation(),
        new CreateOrUpdateDomainOwnershipIdentifierSlotOperation(),
        new CreateOrUpdateFunctionSecretOperation(),
        new CreateOrUpdateFunctionSecretSlotOperation(),
        new CreateOrUpdateHostNameBindingOperation(),
        new CreateOrUpdateHostNameBindingSlotOperation(),
        new CreateOrUpdateHostSecretOperation(),
        new CreateOrUpdateHostSecretSlotOperation(),
        new CreateOrUpdateHybridConnectionOperation(),
        new CreateOrUpdateHybridConnectionSlotOperation(),
        new CreateOrUpdatePublicCertificateOperation(),
        new CreateOrUpdatePublicCertificateSlotOperation(),
        new CreateOrUpdateRelayServiceConnectionOperation(),
        new CreateOrUpdateRelayServiceConnectionSlotOperation(),
        new CreateOrUpdateSlotOperation(),
        new CreateOrUpdateSourceControlOperation(),
        new CreateOrUpdateSourceControlSlotOperation(),
        new CreateOrUpdateSwiftVirtualNetworkConnectionWithCheckOperation(),
        new CreateOrUpdateSwiftVirtualNetworkConnectionWithCheckSlotOperation(),
        new CreateOrUpdateVnetConnectionOperation(),
        new CreateOrUpdateVnetConnectionGatewayOperation(),
        new CreateOrUpdateVnetConnectionGatewaySlotOperation(),
        new CreateOrUpdateVnetConnectionSlotOperation(),
        new DeleteOperation(),
        new DeleteBackupOperation(),
        new DeleteBackupConfigurationOperation(),
        new DeleteBackupConfigurationSlotOperation(),
        new DeleteBackupSlotOperation(),
        new DeleteContinuousWebJobOperation(),
        new DeleteContinuousWebJobSlotOperation(),
        new DeleteDeploymentOperation(),
        new DeleteDeploymentSlotOperation(),
        new DeleteDomainOwnershipIdentifierOperation(),
        new DeleteDomainOwnershipIdentifierSlotOperation(),
        new DeleteFunctionOperation(),
        new DeleteFunctionSecretOperation(),
        new DeleteFunctionSecretSlotOperation(),
        new DeleteHostNameBindingOperation(),
        new DeleteHostNameBindingSlotOperation(),
        new DeleteHostSecretOperation(),
        new DeleteHostSecretSlotOperation(),
        new DeleteHybridConnectionOperation(),
        new DeleteHybridConnectionSlotOperation(),
        new DeleteInstanceFunctionSlotOperation(),
        new DeleteInstanceProcessOperation(),
        new DeleteInstanceProcessSlotOperation(),
        new DeletePremierAddOnOperation(),
        new DeletePremierAddOnSlotOperation(),
        new DeletePrivateEndpointConnectionOperation(),
        new DeletePrivateEndpointConnectionSlotOperation(),
        new DeleteProcessOperation(),
        new DeleteProcessSlotOperation(),
        new DeletePublicCertificateOperation(),
        new DeletePublicCertificateSlotOperation(),
        new DeleteRelayServiceConnectionOperation(),
        new DeleteRelayServiceConnectionSlotOperation(),
        new DeleteSiteExtensionOperation(),
        new DeleteSiteExtensionSlotOperation(),
        new DeleteSlotOperation(),
        new DeleteSourceControlOperation(),
        new DeleteSourceControlSlotOperation(),
        new DeleteSwiftVirtualNetworkOperation(),
        new DeleteSwiftVirtualNetworkSlotOperation(),
        new DeleteTriggeredWebJobOperation(),
        new DeleteTriggeredWebJobSlotOperation(),
        new DeleteVnetConnectionOperation(),
        new DeleteVnetConnectionSlotOperation(),
        new DeployWorkflowArtifactsOperation(),
        new DeployWorkflowArtifactsSlotOperation(),
        new DiscoverBackupOperation(),
        new DiscoverBackupSlotOperation(),
        new GenerateNewSitePublishingPasswordOperation(),
        new GenerateNewSitePublishingPasswordSlotOperation(),
        new GetOperation(),
        new GetAppSettingKeyVaultReferenceOperation(),
        new GetAppSettingKeyVaultReferenceSlotOperation(),
        new GetAppSettingsKeyVaultReferencesOperation(),
        new GetAppSettingsKeyVaultReferencesSlotOperation(),
        new GetAuthSettingsOperation(),
        new GetAuthSettingsSlotOperation(),
        new GetAuthSettingsV2Operation(),
        new GetAuthSettingsV2SlotOperation(),
        new GetAuthSettingsV2WithoutSecretsOperation(),
        new GetAuthSettingsV2WithoutSecretsSlotOperation(),
        new GetBackupConfigurationOperation(),
        new GetBackupConfigurationSlotOperation(),
        new GetBackupStatusOperation(),
        new GetBackupStatusSlotOperation(),
        new GetConfigurationOperation(),
        new GetConfigurationSlotOperation(),
        new GetConfigurationSnapshotOperation(),
        new GetConfigurationSnapshotSlotOperation(),
        new GetContainerLogsZipOperation(),
        new GetContainerLogsZipSlotOperation(),
        new GetContinuousWebJobOperation(),
        new GetContinuousWebJobSlotOperation(),
        new GetDeploymentOperation(),
        new GetDeploymentSlotOperation(),
        new GetDiagnosticLogsConfigurationOperation(),
        new GetDiagnosticLogsConfigurationSlotOperation(),
        new GetDomainOwnershipIdentifierOperation(),
        new GetDomainOwnershipIdentifierSlotOperation(),
        new GetFtpAllowedOperation(),
        new GetFtpAllowedSlotOperation(),
        new GetFunctionOperation(),
        new GetFunctionsAdminTokenOperation(),
        new GetFunctionsAdminTokenSlotOperation(),
        new GetHostNameBindingOperation(),
        new GetHostNameBindingSlotOperation(),
        new GetHybridConnectionOperation(),
        new GetHybridConnectionSlotOperation(),
        new GetInstanceFunctionSlotOperation(),
        new GetInstanceInfoOperation(),
        new GetInstanceInfoSlotOperation(),
        new GetInstanceMSDeployLogOperation(),
        new GetInstanceMSDeployLogSlotOperation(),
        new GetInstanceMsDeployStatusOperation(),
        new GetInstanceMsDeployStatusSlotOperation(),
        new GetInstanceProcessOperation(),
        new GetInstanceProcessDumpOperation(),
        new GetInstanceProcessDumpSlotOperation(),
        new GetInstanceProcessModuleOperation(),
        new GetInstanceProcessModuleSlotOperation(),
        new GetInstanceProcessSlotOperation(),
        new GetInstanceWorkflowSlotOperation(),
        new GetMSDeployLogOperation(),
        new GetMSDeployLogSlotOperation(),
        new GetMSDeployStatusOperation(),
        new GetMSDeployStatusSlotOperation(),
        new GetMigrateMySqlStatusOperation(),
        new GetMigrateMySqlStatusSlotOperation(),
        new GetNetworkTracesOperation(),
        new GetNetworkTracesSlotOperation(),
        new GetNetworkTracesSlotV2Operation(),
        new GetNetworkTracesV2Operation(),
        new GetOneDeployStatusOperation(),
        new GetPremierAddOnOperation(),
        new GetPremierAddOnSlotOperation(),
        new GetPrivateAccessOperation(),
        new GetPrivateAccessSlotOperation(),
        new GetPrivateEndpointConnectionOperation(),
        new GetPrivateEndpointConnectionListOperation(),
        new GetPrivateEndpointConnectionListSlotOperation(),
        new GetPrivateEndpointConnectionSlotOperation(),
        new GetPrivateLinkResourcesOperation(),
        new GetPrivateLinkResourcesSlotOperation(),
        new GetProcessOperation(),
        new GetProcessDumpOperation(),
        new GetProcessDumpSlotOperation(),
        new GetProcessModuleOperation(),
        new GetProcessModuleSlotOperation(),
        new GetProcessSlotOperation(),
        new GetProductionSiteDeploymentStatusOperation(),
        new GetPublicCertificateOperation(),
        new GetPublicCertificateSlotOperation(),
        new GetRelayServiceConnectionOperation(),
        new GetRelayServiceConnectionSlotOperation(),
        new GetScmAllowedOperation(),
        new GetScmAllowedSlotOperation(),
        new GetSiteConnectionStringKeyVaultReferenceOperation(),
        new GetSiteConnectionStringKeyVaultReferenceSlotOperation(),
        new GetSiteConnectionStringKeyVaultReferencesOperation(),
        new GetSiteConnectionStringKeyVaultReferencesSlotOperation(),
        new GetSiteExtensionOperation(),
        new GetSiteExtensionSlotOperation(),
        new GetSitePhpErrorLogFlagOperation(),
        new GetSitePhpErrorLogFlagSlotOperation(),
        new GetSlotOperation(),
        new GetSlotSiteDeploymentStatusSlotOperation(),
        new GetSourceControlOperation(),
        new GetSourceControlSlotOperation(),
        new GetSwiftVirtualNetworkConnectionOperation(),
        new GetSwiftVirtualNetworkConnectionSlotOperation(),
        new GetTriggeredWebJobOperation(),
        new GetTriggeredWebJobHistoryOperation(),
        new GetTriggeredWebJobHistorySlotOperation(),
        new GetTriggeredWebJobSlotOperation(),
        new GetVnetConnectionOperation(),
        new GetVnetConnectionGatewayOperation(),
        new GetVnetConnectionGatewaySlotOperation(),
        new GetVnetConnectionSlotOperation(),
        new GetWebJobOperation(),
        new GetWebJobSlotOperation(),
        new GetWebSiteContainerLogsOperation(),
        new GetWebSiteContainerLogsSlotOperation(),
        new GetWorkflowOperation(),
        new InstallSiteExtensionOperation(),
        new InstallSiteExtensionSlotOperation(),
        new IsCloneableOperation(),
        new IsCloneableSlotOperation(),
        new ListOperation(),
        new ListApplicationSettingsOperation(),
        new ListApplicationSettingsSlotOperation(),
        new ListAzureStorageAccountsOperation(),
        new ListAzureStorageAccountsSlotOperation(),
        new ListBackupStatusSecretsOperation(),
        new ListBackupStatusSecretsSlotOperation(),
        new ListBackupsOperation(),
        new ListBackupsSlotOperation(),
        new ListBasicPublishingCredentialsPoliciesOperation(),
        new ListBasicPublishingCredentialsPoliciesSlotOperation(),
        new ListByResourceGroupOperation(),
        new ListConfigurationSnapshotInfoOperation(),
        new ListConfigurationSnapshotInfoSlotOperation(),
        new ListConfigurationsOperation(),
        new ListConfigurationsSlotOperation(),
        new ListConnectionStringsOperation(),
        new ListConnectionStringsSlotOperation(),
        new ListContinuousWebJobsOperation(),
        new ListContinuousWebJobsSlotOperation(),
        new ListDeploymentLogOperation(),
        new ListDeploymentLogSlotOperation(),
        new ListDeploymentsOperation(),
        new ListDeploymentsSlotOperation(),
        new ListDomainOwnershipIdentifiersOperation(),
        new ListDomainOwnershipIdentifiersSlotOperation(),
        new ListFunctionKeysOperation(),
        new ListFunctionKeysSlotOperation(),
        new ListFunctionSecretsOperation(),
        new ListFunctionSecretsSlotOperation(),
        new ListFunctionsOperation(),
        new ListHostKeysOperation(),
        new ListHostKeysSlotOperation(),
        new ListHostNameBindingsOperation(),
        new ListHostNameBindingsSlotOperation(),
        new ListHybridConnectionsOperation(),
        new ListHybridConnectionsSlotOperation(),
        new ListInstanceFunctionsSlotOperation(),
        new ListInstanceIdentifiersOperation(),
        new ListInstanceIdentifiersSlotOperation(),
        new ListInstanceProcessModulesOperation(),
        new ListInstanceProcessModulesSlotOperation(),
        new ListInstanceProcessThreadsOperation(),
        new ListInstanceProcessThreadsSlotOperation(),
        new ListInstanceProcessesOperation(),
        new ListInstanceProcessesSlotOperation(),
        new ListInstanceWorkflowsSlotOperation(),
        new ListMetadataOperation(),
        new ListMetadataSlotOperation(),
        new ListNetworkFeaturesOperation(),
        new ListNetworkFeaturesSlotOperation(),
        new ListPerfMonCountersOperation(),
        new ListPerfMonCountersSlotOperation(),
        new ListPremierAddOnsOperation(),
        new ListPremierAddOnsSlotOperation(),
        new ListProcessModulesOperation(),
        new ListProcessModulesSlotOperation(),
        new ListProcessThreadsOperation(),
        new ListProcessThreadsSlotOperation(),
        new ListProcessesOperation(),
        new ListProcessesSlotOperation(),
        new ListProductionSiteDeploymentStatusesOperation(),
        new ListPublicCertificatesOperation(),
        new ListPublicCertificatesSlotOperation(),
        new ListPublishingCredentialsOperation(),
        new ListPublishingCredentialsSlotOperation(),
        new ListPublishingProfileXmlWithSecretsOperation(),
        new ListPublishingProfileXmlWithSecretsSlotOperation(),
        new ListRelayServiceConnectionsOperation(),
        new ListRelayServiceConnectionsSlotOperation(),
        new ListSiteBackupsOperation(),
        new ListSiteBackupsSlotOperation(),
        new ListSiteExtensionsOperation(),
        new ListSiteExtensionsSlotOperation(),
        new ListSitePushSettingsOperation(),
        new ListSitePushSettingsSlotOperation(),
        new ListSlotConfigurationNamesOperation(),
        new ListSlotDifferencesFromProductionOperation(),
        new ListSlotDifferencesSlotOperation(),
        new ListSlotSiteDeploymentStatusesSlotOperation(),
        new ListSlotsOperation(),
        new ListSnapshotsOperation(),
        new ListSnapshotsFromDRSecondaryOperation(),
        new ListSnapshotsFromDRSecondarySlotOperation(),
        new ListSnapshotsSlotOperation(),
        new ListSyncFunctionTriggersOperation(),
        new ListSyncFunctionTriggersSlotOperation(),
        new ListSyncStatusOperation(),
        new ListSyncStatusSlotOperation(),
        new ListTriggeredWebJobHistoryOperation(),
        new ListTriggeredWebJobHistorySlotOperation(),
        new ListTriggeredWebJobsOperation(),
        new ListTriggeredWebJobsSlotOperation(),
        new ListUsagesOperation(),
        new ListUsagesSlotOperation(),
        new ListVnetConnectionsOperation(),
        new ListVnetConnectionsSlotOperation(),
        new ListWebJobsOperation(),
        new ListWebJobsSlotOperation(),
        new ListWorkflowsOperation(),
        new ListWorkflowsConnectionsOperation(),
        new ListWorkflowsConnectionsSlotOperation(),
        new MigrateMySqlOperation(),
        new MigrateStorageOperation(),
        new PutPrivateAccessVnetOperation(),
        new PutPrivateAccessVnetSlotOperation(),
        new RecoverSiteConfigurationSnapshotOperation(),
        new RecoverSiteConfigurationSnapshotSlotOperation(),
        new ResetProductionSlotConfigOperation(),
        new ResetSlotConfigurationSlotOperation(),
        new RestartOperation(),
        new RestartSlotOperation(),
        new RestoreOperation(),
        new RestoreFromBackupBlobOperation(),
        new RestoreFromBackupBlobSlotOperation(),
        new RestoreFromDeletedAppOperation(),
        new RestoreFromDeletedAppSlotOperation(),
        new RestoreSlotOperation(),
        new RestoreSnapshotOperation(),
        new RestoreSnapshotSlotOperation(),
        new RunTriggeredWebJobOperation(),
        new RunTriggeredWebJobSlotOperation(),
        new StartOperation(),
        new StartContinuousWebJobOperation(),
        new StartContinuousWebJobSlotOperation(),
        new StartNetworkTraceOperation(),
        new StartNetworkTraceSlotOperation(),
        new StartSlotOperation(),
        new StartWebSiteNetworkTraceOperation(),
        new StartWebSiteNetworkTraceOperationOperation(),
        new StartWebSiteNetworkTraceOperationSlotOperation(),
        new StartWebSiteNetworkTraceSlotOperation(),
        new StopOperation(),
        new StopContinuousWebJobOperation(),
        new StopContinuousWebJobSlotOperation(),
        new StopNetworkTraceOperation(),
        new StopNetworkTraceSlotOperation(),
        new StopSlotOperation(),
        new StopWebSiteNetworkTraceOperation(),
        new StopWebSiteNetworkTraceSlotOperation(),
        new SwapSlotSlotOperation(),
        new SwapSlotWithProductionOperation(),
        new SyncFunctionTriggersOperation(),
        new SyncFunctionTriggersSlotOperation(),
        new SyncFunctionsOperation(),
        new SyncFunctionsSlotOperation(),
        new SyncRepositoryOperation(),
        new SyncRepositorySlotOperation(),
        new UpdateOperation(),
        new UpdateApplicationSettingsOperation(),
        new UpdateApplicationSettingsSlotOperation(),
        new UpdateAuthSettingsOperation(),
        new UpdateAuthSettingsSlotOperation(),
        new UpdateAuthSettingsV2Operation(),
        new UpdateAuthSettingsV2SlotOperation(),
        new UpdateAzureStorageAccountsOperation(),
        new UpdateAzureStorageAccountsSlotOperation(),
        new UpdateBackupConfigurationOperation(),
        new UpdateBackupConfigurationSlotOperation(),
        new UpdateConfigurationOperation(),
        new UpdateConfigurationSlotOperation(),
        new UpdateConnectionStringsOperation(),
        new UpdateConnectionStringsSlotOperation(),
        new UpdateDiagnosticLogsConfigOperation(),
        new UpdateDiagnosticLogsConfigSlotOperation(),
        new UpdateDomainOwnershipIdentifierOperation(),
        new UpdateDomainOwnershipIdentifierSlotOperation(),
        new UpdateFtpAllowedOperation(),
        new UpdateFtpAllowedSlotOperation(),
        new UpdateHybridConnectionOperation(),
        new UpdateHybridConnectionSlotOperation(),
        new UpdateMetadataOperation(),
        new UpdateMetadataSlotOperation(),
        new UpdatePremierAddOnOperation(),
        new UpdatePremierAddOnSlotOperation(),
        new UpdateRelayServiceConnectionOperation(),
        new UpdateRelayServiceConnectionSlotOperation(),
        new UpdateScmAllowedOperation(),
        new UpdateScmAllowedSlotOperation(),
        new UpdateSitePushSettingsOperation(),
        new UpdateSitePushSettingsSlotOperation(),
        new UpdateSlotOperation(),
        new UpdateSlotConfigurationNamesOperation(),
        new UpdateSourceControlOperation(),
        new UpdateSourceControlSlotOperation(),
        new UpdateSwiftVirtualNetworkConnectionWithCheckOperation(),
        new UpdateSwiftVirtualNetworkConnectionWithCheckSlotOperation(),
        new UpdateVnetConnectionOperation(),
        new UpdateVnetConnectionGatewayOperation(),
        new UpdateVnetConnectionGatewaySlotOperation(),
        new UpdateVnetConnectionSlotOperation(),
    };
    public IEnumerable<System.Type> Constants => new List<System.Type>
    {
        typeof(AutoHealActionTypeConstant),
        typeof(AzureResourceTypeConstant),
        typeof(AzureStorageStateConstant),
        typeof(AzureStorageTypeConstant),
        typeof(BackupItemStatusConstant),
        typeof(BackupRestoreOperationTypeConstant),
        typeof(BuiltInAuthenticationProviderConstant),
        typeof(ClientCertModeConstant),
        typeof(ClientCredentialMethodConstant),
        typeof(CloneAbilityResultConstant),
        typeof(ConfigReferenceSourceConstant),
        typeof(ConnectionStringTypeConstant),
        typeof(ContinuousWebJobStatusConstant),
        typeof(CookieExpirationConventionConstant),
        typeof(CustomHostNameDnsRecordTypeConstant),
        typeof(DatabaseTypeConstant),
        typeof(DefaultActionConstant),
        typeof(DeploymentBuildStatusConstant),
        typeof(DnsVerificationTestResultConstant),
        typeof(ForwardProxyConventionConstant),
        typeof(FrequencyUnitConstant),
        typeof(FtpsStateConstant),
        typeof(HostNameTypeConstant),
        typeof(HostTypeConstant),
        typeof(IPFilterTagConstant),
        typeof(LogLevelConstant),
        typeof(MSDeployLogEntryTypeConstant),
        typeof(MSDeployProvisioningStateConstant),
        typeof(ManagedPipelineModeConstant),
        typeof(MySqlMigrationTypeConstant),
        typeof(OperationStatusConstant),
        typeof(PublicCertificateLocationConstant),
        typeof(PublishingProfileFormatConstant),
        typeof(RedundancyModeConstant),
        typeof(ResolveStatusConstant),
        typeof(RouteTypeConstant),
        typeof(ScmTypeConstant),
        typeof(SiteAvailabilityStateConstant),
        typeof(SiteExtensionTypeConstant),
        typeof(SiteLoadBalancingConstant),
        typeof(SiteRuntimeStateConstant),
        typeof(SslStateConstant),
        typeof(SupportedTlsVersionsConstant),
        typeof(TriggeredWebJobStatusConstant),
        typeof(UnauthenticatedClientActionConstant),
        typeof(UnauthenticatedClientActionV2Constant),
        typeof(UsageStateConstant),
        typeof(WebJobTypeConstant),
        typeof(WorkflowHealthStateConstant),
        typeof(WorkflowStateConstant),
    };
    public IEnumerable<System.Type> Models => new List<System.Type>
    {
        typeof(AllowedAudiencesValidationModel),
        typeof(AllowedPrincipalsModel),
        typeof(ApiDefinitionInfoModel),
        typeof(ApiKVReferenceModel),
        typeof(ApiKVReferencePropertiesModel),
        typeof(ApiManagementConfigModel),
        typeof(AppRegistrationModel),
        typeof(AppleModel),
        typeof(AppleRegistrationModel),
        typeof(ApplicationLogsConfigModel),
        typeof(ArmIdWrapperModel),
        typeof(AuthPlatformModel),
        typeof(AutoHealActionsModel),
        typeof(AutoHealCustomActionModel),
        typeof(AutoHealRulesModel),
        typeof(AutoHealTriggersModel),
        typeof(AzureActiveDirectoryModel),
        typeof(AzureActiveDirectoryLoginModel),
        typeof(AzureActiveDirectoryRegistrationModel),
        typeof(AzureActiveDirectoryValidationModel),
        typeof(AzureBlobStorageApplicationLogsConfigModel),
        typeof(AzureBlobStorageHTTPLogsConfigModel),
        typeof(AzureStaticWebAppsModel),
        typeof(AzureStaticWebAppsRegistrationModel),
        typeof(AzureStorageInfoValueModel),
        typeof(AzureStoragePropertyDictionaryResourceModel),
        typeof(AzureTableStorageApplicationLogsConfigModel),
        typeof(BackupItemModel),
        typeof(BackupItemPropertiesModel),
        typeof(BackupRequestModel),
        typeof(BackupRequestPropertiesModel),
        typeof(BackupScheduleModel),
        typeof(BlobStorageTokenStoreModel),
        typeof(ClientRegistrationModel),
        typeof(CloningInfoModel),
        typeof(ConnStringInfoModel),
        typeof(ConnStringValueTypePairModel),
        typeof(ConnectionStringDictionaryModel),
        typeof(ContainerCPUStatisticsModel),
        typeof(ContainerCPUUsageModel),
        typeof(ContainerInfoModel),
        typeof(ContainerMemoryStatisticsModel),
        typeof(ContainerNetworkInterfaceStatisticsModel),
        typeof(ContainerThrottlingDataModel),
        typeof(ContinuousWebJobModel),
        typeof(ContinuousWebJobPropertiesModel),
        typeof(CookieExpirationModel),
        typeof(CorsSettingsModel),
        typeof(CsmDeploymentStatusModel),
        typeof(CsmDeploymentStatusPropertiesModel),
        typeof(CsmPublishingCredentialsPoliciesEntityModel),
        typeof(CsmPublishingCredentialsPoliciesEntityPropertiesModel),
        typeof(CsmPublishingProfileOptionsModel),
        typeof(CsmSlotEntityModel),
        typeof(CsmUsageQuotaModel),
        typeof(CustomHostnameAnalysisResultModel),
        typeof(CustomHostnameAnalysisResultPropertiesModel),
        typeof(CustomOpenIdConnectProviderModel),
        typeof(DatabaseBackupSettingModel),
        typeof(DefaultAuthorizationPolicyModel),
        typeof(DeletedAppRestoreRequestModel),
        typeof(DeletedAppRestoreRequestPropertiesModel),
        typeof(DeploymentModel),
        typeof(DeploymentPropertiesModel),
        typeof(EnabledConfigModel),
        typeof(ErrorEntityModel),
        typeof(ExperimentsModel),
        typeof(ExtendedLocationModel),
        typeof(FacebookModel),
        typeof(FileSystemApplicationLogsConfigModel),
        typeof(FileSystemHTTPLogsConfigModel),
        typeof(FileSystemTokenStoreModel),
        typeof(ForwardProxyModel),
        typeof(FunctionEnvelopeModel),
        typeof(FunctionEnvelopePropertiesModel),
        typeof(FunctionSecretsModel),
        typeof(GitHubModel),
        typeof(GitHubActionCodeConfigurationModel),
        typeof(GitHubActionConfigurationModel),
        typeof(GitHubActionContainerConfigurationModel),
        typeof(GlobalValidationModel),
        typeof(GoogleModel),
        typeof(HTTPLogsConfigModel),
        typeof(HTTPSettingsModel),
        typeof(HTTPSettingsRoutesModel),
        typeof(HandlerMappingModel),
        typeof(HostKeysModel),
        typeof(HostNameBindingModel),
        typeof(HostNameBindingPropertiesModel),
        typeof(HostNameSslStateModel),
        typeof(HostingEnvironmentProfileModel),
        typeof(HybridConnectionModel),
        typeof(HybridConnectionPropertiesModel),
        typeof(IPSecurityRestrictionModel),
        typeof(IdentifierModel),
        typeof(IdentifierPropertiesModel),
        typeof(IdentityProvidersModel),
        typeof(JwtClaimChecksModel),
        typeof(KeyInfoModel),
        typeof(LegacyMicrosoftAccountModel),
        typeof(LocalizableStringModel),
        typeof(LoginModel),
        typeof(LoginRoutesModel),
        typeof(LoginScopesModel),
        typeof(MSDeployModel),
        typeof(MSDeployCoreModel),
        typeof(MSDeployLogModel),
        typeof(MSDeployLogEntryModel),
        typeof(MSDeployLogPropertiesModel),
        typeof(MSDeployPropertiesModel),
        typeof(MSDeployStatusModel),
        typeof(MSDeployStatusPropertiesModel),
        typeof(MigrateMySqlRequestModel),
        typeof(MigrateMySqlRequestPropertiesModel),
        typeof(MigrateMySqlStatusModel),
        typeof(MigrateMySqlStatusPropertiesModel),
        typeof(NameValuePairModel),
        typeof(NetworkFeaturesModel),
        typeof(NetworkFeaturesPropertiesModel),
        typeof(NetworkTraceModel),
        typeof(NonceModel),
        typeof(OpenIdConnectClientCredentialModel),
        typeof(OpenIdConnectConfigModel),
        typeof(OpenIdConnectLoginModel),
        typeof(OpenIdConnectRegistrationModel),
        typeof(OperationModel),
        typeof(PerfMonResponseModel),
        typeof(PerfMonSampleModel),
        typeof(PerfMonSetModel),
        typeof(PremierAddOnModel),
        typeof(PremierAddOnPatchResourceModel),
        typeof(PremierAddOnPatchResourcePropertiesModel),
        typeof(PremierAddOnPropertiesModel),
        typeof(PrivateAccessModel),
        typeof(PrivateAccessPropertiesModel),
        typeof(PrivateAccessSubnetModel),
        typeof(PrivateAccessVirtualNetworkModel),
        typeof(PrivateLinkConnectionApprovalRequestModel),
        typeof(PrivateLinkConnectionApprovalRequestResourceModel),
        typeof(PrivateLinkConnectionStateModel),
        typeof(PrivateLinkResourceModel),
        typeof(PrivateLinkResourcePropertiesModel),
        typeof(PrivateLinkResourcesWrapperModel),
        typeof(ProcessInfoModel),
        typeof(ProcessInfoPropertiesModel),
        typeof(ProcessModuleInfoModel),
        typeof(ProcessModuleInfoPropertiesModel),
        typeof(ProcessThreadInfoModel),
        typeof(ProcessThreadInfoPropertiesModel),
        typeof(PublicCertificateModel),
        typeof(PublicCertificatePropertiesModel),
        typeof(PushSettingsModel),
        typeof(PushSettingsPropertiesModel),
        typeof(RampUpRuleModel),
        typeof(RelayServiceConnectionEntityModel),
        typeof(RelayServiceConnectionEntityPropertiesModel),
        typeof(RemotePrivateEndpointConnectionARMResourceModel),
        typeof(RemotePrivateEndpointConnectionARMResourcePropertiesModel),
        typeof(RequestsBasedTriggerModel),
        typeof(RestoreRequestModel),
        typeof(RestoreRequestPropertiesModel),
        typeof(SiteModel),
        typeof(SiteAuthSettingsModel),
        typeof(SiteAuthSettingsPropertiesModel),
        typeof(SiteAuthSettingsV2Model),
        typeof(SiteAuthSettingsV2PropertiesModel),
        typeof(SiteCloneabilityModel),
        typeof(SiteCloneabilityCriterionModel),
        typeof(SiteConfigModel),
        typeof(SiteConfigResourceModel),
        typeof(SiteConfigurationSnapshotInfoModel),
        typeof(SiteConfigurationSnapshotInfoPropertiesModel),
        typeof(SiteExtensionInfoModel),
        typeof(SiteExtensionInfoPropertiesModel),
        typeof(SiteLimitsModel),
        typeof(SiteLogsConfigModel),
        typeof(SiteLogsConfigPropertiesModel),
        typeof(SiteMachineKeyModel),
        typeof(SitePatchResourceModel),
        typeof(SitePatchResourcePropertiesModel),
        typeof(SitePhpErrorLogFlagModel),
        typeof(SitePhpErrorLogFlagPropertiesModel),
        typeof(SitePropertiesModel),
        typeof(SiteSourceControlModel),
        typeof(SiteSourceControlPropertiesModel),
        typeof(SlotConfigNamesModel),
        typeof(SlotConfigNamesResourceModel),
        typeof(SlotDifferenceModel),
        typeof(SlotDifferencePropertiesModel),
        typeof(SlotSwapStatusModel),
        typeof(SlowRequestsBasedTriggerModel),
        typeof(SnapshotModel),
        typeof(SnapshotPropertiesModel),
        typeof(SnapshotRecoverySourceModel),
        typeof(SnapshotRestoreRequestModel),
        typeof(SnapshotRestoreRequestPropertiesModel),
        typeof(StatusCodesBasedTriggerModel),
        typeof(StatusCodesRangeBasedTriggerModel),
        typeof(StorageMigrationOptionsModel),
        typeof(StorageMigrationOptionsPropertiesModel),
        typeof(StorageMigrationResponseModel),
        typeof(StorageMigrationResponsePropertiesModel),
        typeof(StringDictionaryModel),
        typeof(SwiftVirtualNetworkModel),
        typeof(SwiftVirtualNetworkPropertiesModel),
        typeof(TokenStoreModel),
        typeof(TriggeredJobHistoryModel),
        typeof(TriggeredJobHistoryPropertiesModel),
        typeof(TriggeredJobRunModel),
        typeof(TriggeredWebJobModel),
        typeof(TriggeredWebJobPropertiesModel),
        typeof(TwitterModel),
        typeof(TwitterRegistrationModel),
        typeof(UserModel),
        typeof(UserPropertiesModel),
        typeof(VirtualApplicationModel),
        typeof(VirtualDirectoryModel),
        typeof(VnetGatewayModel),
        typeof(VnetGatewayPropertiesModel),
        typeof(VnetInfoModel),
        typeof(VnetInfoResourceModel),
        typeof(VnetRouteModel),
        typeof(VnetRoutePropertiesModel),
        typeof(WebJobModel),
        typeof(WebJobPropertiesModel),
        typeof(WebSiteInstanceStatusModel),
        typeof(WebSiteInstanceStatusPropertiesModel),
        typeof(WorkflowArtifactsModel),
        typeof(WorkflowEnvelopeModel),
        typeof(WorkflowEnvelopePropertiesModel),
        typeof(WorkflowHealthModel),
    };
}
