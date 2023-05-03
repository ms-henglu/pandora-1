using System.Collections.Generic;
using Pandora.Definitions.Interfaces;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.CosmosDB.v2023_04_15.CosmosDB;

internal class Definition : ResourceDefinition
{
    public string Name => "CosmosDB";
    public IEnumerable<Interfaces.ApiOperation> Operations => new List<Interfaces.ApiOperation>
    {
        new CassandraResourcesCreateUpdateCassandraKeyspaceOperation(),
        new CassandraResourcesCreateUpdateCassandraTableOperation(),
        new CassandraResourcesDeleteCassandraKeyspaceOperation(),
        new CassandraResourcesDeleteCassandraTableOperation(),
        new CassandraResourcesGetCassandraKeyspaceOperation(),
        new CassandraResourcesGetCassandraKeyspaceThroughputOperation(),
        new CassandraResourcesGetCassandraTableOperation(),
        new CassandraResourcesGetCassandraTableThroughputOperation(),
        new CassandraResourcesListCassandraKeyspacesOperation(),
        new CassandraResourcesListCassandraTablesOperation(),
        new CassandraResourcesMigrateCassandraKeyspaceToAutoscaleOperation(),
        new CassandraResourcesMigrateCassandraKeyspaceToManualThroughputOperation(),
        new CassandraResourcesMigrateCassandraTableToAutoscaleOperation(),
        new CassandraResourcesMigrateCassandraTableToManualThroughputOperation(),
        new CassandraResourcesUpdateCassandraKeyspaceThroughputOperation(),
        new CassandraResourcesUpdateCassandraTableThroughputOperation(),
        new CollectionListMetricDefinitionsOperation(),
        new CollectionListMetricsOperation(),
        new CollectionListUsagesOperation(),
        new CollectionPartitionListMetricsOperation(),
        new CollectionPartitionListUsagesOperation(),
        new CollectionPartitionRegionListMetricsOperation(),
        new CollectionRegionListMetricsOperation(),
        new DatabaseAccountRegionListMetricsOperation(),
        new DatabaseAccountsCheckNameExistsOperation(),
        new DatabaseAccountsCreateOrUpdateOperation(),
        new DatabaseAccountsDeleteOperation(),
        new DatabaseAccountsFailoverPriorityChangeOperation(),
        new DatabaseAccountsGetOperation(),
        new DatabaseAccountsGetReadOnlyKeysOperation(),
        new DatabaseAccountsListOperation(),
        new DatabaseAccountsListByResourceGroupOperation(),
        new DatabaseAccountsListConnectionStringsOperation(),
        new DatabaseAccountsListKeysOperation(),
        new DatabaseAccountsListMetricDefinitionsOperation(),
        new DatabaseAccountsListMetricsOperation(),
        new DatabaseAccountsListReadOnlyKeysOperation(),
        new DatabaseAccountsListUsagesOperation(),
        new DatabaseAccountsOfflineRegionOperation(),
        new DatabaseAccountsOnlineRegionOperation(),
        new DatabaseAccountsRegenerateKeyOperation(),
        new DatabaseAccountsUpdateOperation(),
        new DatabaseListMetricDefinitionsOperation(),
        new DatabaseListMetricsOperation(),
        new DatabaseListUsagesOperation(),
        new GremlinResourcesCreateUpdateGremlinDatabaseOperation(),
        new GremlinResourcesCreateUpdateGremlinGraphOperation(),
        new GremlinResourcesDeleteGremlinDatabaseOperation(),
        new GremlinResourcesDeleteGremlinGraphOperation(),
        new GremlinResourcesGetGremlinDatabaseOperation(),
        new GremlinResourcesGetGremlinDatabaseThroughputOperation(),
        new GremlinResourcesGetGremlinGraphOperation(),
        new GremlinResourcesGetGremlinGraphThroughputOperation(),
        new GremlinResourcesListGremlinDatabasesOperation(),
        new GremlinResourcesListGremlinGraphsOperation(),
        new GremlinResourcesMigrateGremlinDatabaseToAutoscaleOperation(),
        new GremlinResourcesMigrateGremlinDatabaseToManualThroughputOperation(),
        new GremlinResourcesMigrateGremlinGraphToAutoscaleOperation(),
        new GremlinResourcesMigrateGremlinGraphToManualThroughputOperation(),
        new GremlinResourcesUpdateGremlinDatabaseThroughputOperation(),
        new GremlinResourcesUpdateGremlinGraphThroughputOperation(),
        new LocationsGetOperation(),
        new LocationsListOperation(),
        new MongoDBResourcesCreateUpdateMongoDBCollectionOperation(),
        new MongoDBResourcesCreateUpdateMongoDBDatabaseOperation(),
        new MongoDBResourcesDeleteMongoDBCollectionOperation(),
        new MongoDBResourcesDeleteMongoDBDatabaseOperation(),
        new MongoDBResourcesGetMongoDBCollectionOperation(),
        new MongoDBResourcesGetMongoDBCollectionThroughputOperation(),
        new MongoDBResourcesGetMongoDBDatabaseOperation(),
        new MongoDBResourcesGetMongoDBDatabaseThroughputOperation(),
        new MongoDBResourcesListMongoDBCollectionsOperation(),
        new MongoDBResourcesListMongoDBDatabasesOperation(),
        new MongoDBResourcesMigrateMongoDBCollectionToAutoscaleOperation(),
        new MongoDBResourcesMigrateMongoDBCollectionToManualThroughputOperation(),
        new MongoDBResourcesMigrateMongoDBDatabaseToAutoscaleOperation(),
        new MongoDBResourcesMigrateMongoDBDatabaseToManualThroughputOperation(),
        new MongoDBResourcesUpdateMongoDBCollectionThroughputOperation(),
        new MongoDBResourcesUpdateMongoDBDatabaseThroughputOperation(),
        new PartitionKeyRangeIdListMetricsOperation(),
        new PartitionKeyRangeIdRegionListMetricsOperation(),
        new PercentileListMetricsOperation(),
        new PercentileSourceTargetListMetricsOperation(),
        new PercentileTargetListMetricsOperation(),
        new SqlResourcesCreateUpdateClientEncryptionKeyOperation(),
        new SqlResourcesCreateUpdateSqlContainerOperation(),
        new SqlResourcesCreateUpdateSqlDatabaseOperation(),
        new SqlResourcesCreateUpdateSqlStoredProcedureOperation(),
        new SqlResourcesCreateUpdateSqlTriggerOperation(),
        new SqlResourcesCreateUpdateSqlUserDefinedFunctionOperation(),
        new SqlResourcesDeleteSqlContainerOperation(),
        new SqlResourcesDeleteSqlDatabaseOperation(),
        new SqlResourcesDeleteSqlStoredProcedureOperation(),
        new SqlResourcesDeleteSqlTriggerOperation(),
        new SqlResourcesDeleteSqlUserDefinedFunctionOperation(),
        new SqlResourcesGetClientEncryptionKeyOperation(),
        new SqlResourcesGetSqlContainerOperation(),
        new SqlResourcesGetSqlContainerThroughputOperation(),
        new SqlResourcesGetSqlDatabaseOperation(),
        new SqlResourcesGetSqlDatabaseThroughputOperation(),
        new SqlResourcesGetSqlStoredProcedureOperation(),
        new SqlResourcesGetSqlTriggerOperation(),
        new SqlResourcesGetSqlUserDefinedFunctionOperation(),
        new SqlResourcesListClientEncryptionKeysOperation(),
        new SqlResourcesListSqlContainersOperation(),
        new SqlResourcesListSqlDatabasesOperation(),
        new SqlResourcesListSqlStoredProceduresOperation(),
        new SqlResourcesListSqlTriggersOperation(),
        new SqlResourcesListSqlUserDefinedFunctionsOperation(),
        new SqlResourcesMigrateSqlContainerToAutoscaleOperation(),
        new SqlResourcesMigrateSqlContainerToManualThroughputOperation(),
        new SqlResourcesMigrateSqlDatabaseToAutoscaleOperation(),
        new SqlResourcesMigrateSqlDatabaseToManualThroughputOperation(),
        new SqlResourcesUpdateSqlContainerThroughputOperation(),
        new SqlResourcesUpdateSqlDatabaseThroughputOperation(),
        new TableResourcesCreateUpdateTableOperation(),
        new TableResourcesDeleteTableOperation(),
        new TableResourcesGetTableOperation(),
        new TableResourcesGetTableThroughputOperation(),
        new TableResourcesListTablesOperation(),
        new TableResourcesMigrateTableToAutoscaleOperation(),
        new TableResourcesMigrateTableToManualThroughputOperation(),
        new TableResourcesUpdateTableThroughputOperation(),
    };
    public IEnumerable<System.Type> Constants => new List<System.Type>
    {
        typeof(AnalyticalStorageSchemaTypeConstant),
        typeof(BackupPolicyMigrationStatusConstant),
        typeof(BackupPolicyTypeConstant),
        typeof(BackupStorageRedundancyConstant),
        typeof(CompositePathSortOrderConstant),
        typeof(ConflictResolutionModeConstant),
        typeof(ConnectorOfferConstant),
        typeof(ContinuousTierConstant),
        typeof(CreateModeConstant),
        typeof(DataTypeConstant),
        typeof(DatabaseAccountKindConstant),
        typeof(DatabaseAccountOfferTypeConstant),
        typeof(DefaultConsistencyLevelConstant),
        typeof(IndexKindConstant),
        typeof(IndexingModeConstant),
        typeof(KeyKindConstant),
        typeof(KindConstant),
        typeof(MinimalTlsVersionConstant),
        typeof(NetworkAclBypassConstant),
        typeof(PartitionKindConstant),
        typeof(PrimaryAggregationTypeConstant),
        typeof(PublicNetworkAccessConstant),
        typeof(RestoreModeConstant),
        typeof(ServerVersionConstant),
        typeof(SpatialTypeConstant),
        typeof(StatusConstant),
        typeof(TriggerOperationConstant),
        typeof(TriggerTypeConstant),
        typeof(TypeConstant),
        typeof(UnitTypeConstant),
    };
    public IEnumerable<System.Type> Models => new List<System.Type>
    {
        typeof(AccountKeyMetadataModel),
        typeof(AnalyticalStorageConfigurationModel),
        typeof(ApiPropertiesModel),
        typeof(AutoScaleSettingsModel),
        typeof(AutoUpgradePolicyResourceModel),
        typeof(AutoscaleSettingsResourceModel),
        typeof(BackupPolicyModel),
        typeof(BackupPolicyMigrationStateModel),
        typeof(CapabilityModel),
        typeof(CapacityModel),
        typeof(CassandraKeyspaceCreateUpdateParametersModel),
        typeof(CassandraKeyspaceCreateUpdatePropertiesModel),
        typeof(CassandraKeyspaceGetPropertiesModel),
        typeof(CassandraKeyspaceGetPropertiesResourceModel),
        typeof(CassandraKeyspaceGetResultsModel),
        typeof(CassandraKeyspaceListResultModel),
        typeof(CassandraKeyspaceResourceModel),
        typeof(CassandraPartitionKeyModel),
        typeof(CassandraSchemaModel),
        typeof(CassandraTableCreateUpdateParametersModel),
        typeof(CassandraTableCreateUpdatePropertiesModel),
        typeof(CassandraTableGetPropertiesModel),
        typeof(CassandraTableGetPropertiesResourceModel),
        typeof(CassandraTableGetResultsModel),
        typeof(CassandraTableListResultModel),
        typeof(CassandraTableResourceModel),
        typeof(ClientEncryptionIncludedPathModel),
        typeof(ClientEncryptionKeyCreateUpdateParametersModel),
        typeof(ClientEncryptionKeyCreateUpdatePropertiesModel),
        typeof(ClientEncryptionKeyGetPropertiesModel),
        typeof(ClientEncryptionKeyGetPropertiesResourceModel),
        typeof(ClientEncryptionKeyGetResultsModel),
        typeof(ClientEncryptionKeyResourceModel),
        typeof(ClientEncryptionKeysListResultModel),
        typeof(ClientEncryptionPolicyModel),
        typeof(ClusterKeyModel),
        typeof(ColumnModel),
        typeof(CompositePathModel),
        typeof(ConflictResolutionPolicyModel),
        typeof(ConsistencyPolicyModel),
        typeof(ContainerPartitionKeyModel),
        typeof(ContinuousModeBackupPolicyModel),
        typeof(ContinuousModePropertiesModel),
        typeof(CorsPolicyModel),
        typeof(CreateUpdateOptionsModel),
        typeof(DatabaseAccountConnectionStringModel),
        typeof(DatabaseAccountCreateUpdateParametersModel),
        typeof(DatabaseAccountCreateUpdatePropertiesModel),
        typeof(DatabaseAccountGetPropertiesModel),
        typeof(DatabaseAccountGetResultsModel),
        typeof(DatabaseAccountKeysMetadataModel),
        typeof(DatabaseAccountListConnectionStringsResultModel),
        typeof(DatabaseAccountListKeysResultModel),
        typeof(DatabaseAccountListReadOnlyKeysResultModel),
        typeof(DatabaseAccountRegenerateKeyParametersModel),
        typeof(DatabaseAccountUpdateParametersModel),
        typeof(DatabaseAccountUpdatePropertiesModel),
        typeof(DatabaseAccountsListResultModel),
        typeof(DatabaseRestoreResourceModel),
        typeof(ExcludedPathModel),
        typeof(FailoverPoliciesModel),
        typeof(FailoverPolicyModel),
        typeof(GremlinDatabaseCreateUpdateParametersModel),
        typeof(GremlinDatabaseCreateUpdatePropertiesModel),
        typeof(GremlinDatabaseGetPropertiesModel),
        typeof(GremlinDatabaseGetPropertiesResourceModel),
        typeof(GremlinDatabaseGetResultsModel),
        typeof(GremlinDatabaseListResultModel),
        typeof(GremlinDatabaseResourceModel),
        typeof(GremlinDatabaseRestoreResourceModel),
        typeof(GremlinGraphCreateUpdateParametersModel),
        typeof(GremlinGraphCreateUpdatePropertiesModel),
        typeof(GremlinGraphGetPropertiesModel),
        typeof(GremlinGraphGetPropertiesResourceModel),
        typeof(GremlinGraphGetResultsModel),
        typeof(GremlinGraphListResultModel),
        typeof(GremlinGraphResourceModel),
        typeof(IPAddressOrRangeModel),
        typeof(IncludedPathModel),
        typeof(IndexesModel),
        typeof(IndexingPolicyModel),
        typeof(KeyWrapMetadataModel),
        typeof(LocationModel),
        typeof(LocationGetResultModel),
        typeof(LocationListResultModel),
        typeof(LocationPropertiesModel),
        typeof(MetricModel),
        typeof(MetricAvailabilityModel),
        typeof(MetricDefinitionModel),
        typeof(MetricDefinitionsListResultModel),
        typeof(MetricListResultModel),
        typeof(MetricNameModel),
        typeof(MetricValueModel),
        typeof(MongoDBCollectionCreateUpdateParametersModel),
        typeof(MongoDBCollectionCreateUpdatePropertiesModel),
        typeof(MongoDBCollectionGetPropertiesModel),
        typeof(MongoDBCollectionGetPropertiesResourceModel),
        typeof(MongoDBCollectionGetResultsModel),
        typeof(MongoDBCollectionListResultModel),
        typeof(MongoDBCollectionResourceModel),
        typeof(MongoDBDatabaseCreateUpdateParametersModel),
        typeof(MongoDBDatabaseCreateUpdatePropertiesModel),
        typeof(MongoDBDatabaseGetPropertiesModel),
        typeof(MongoDBDatabaseGetPropertiesResourceModel),
        typeof(MongoDBDatabaseGetResultsModel),
        typeof(MongoDBDatabaseListResultModel),
        typeof(MongoDBDatabaseResourceModel),
        typeof(MongoIndexModel),
        typeof(MongoIndexKeysModel),
        typeof(MongoIndexOptionsModel),
        typeof(OptionsResourceModel),
        typeof(PartitionMetricModel),
        typeof(PartitionMetricListResultModel),
        typeof(PartitionUsageModel),
        typeof(PartitionUsagesResultModel),
        typeof(PercentileMetricModel),
        typeof(PercentileMetricListResultModel),
        typeof(PercentileMetricValueModel),
        typeof(PeriodicModeBackupPolicyModel),
        typeof(PeriodicModePropertiesModel),
        typeof(PrivateEndpointConnectionModel),
        typeof(PrivateEndpointConnectionPropertiesModel),
        typeof(PrivateEndpointPropertyModel),
        typeof(PrivateLinkServiceConnectionStatePropertyModel),
        typeof(RegionForOnlineOfflineModel),
        typeof(RestoreParametersModel),
        typeof(SpatialSpecModel),
        typeof(SqlContainerCreateUpdateParametersModel),
        typeof(SqlContainerCreateUpdatePropertiesModel),
        typeof(SqlContainerGetPropertiesModel),
        typeof(SqlContainerGetPropertiesResourceModel),
        typeof(SqlContainerGetResultsModel),
        typeof(SqlContainerListResultModel),
        typeof(SqlContainerResourceModel),
        typeof(SqlDatabaseCreateUpdateParametersModel),
        typeof(SqlDatabaseCreateUpdatePropertiesModel),
        typeof(SqlDatabaseGetPropertiesModel),
        typeof(SqlDatabaseGetPropertiesResourceModel),
        typeof(SqlDatabaseGetResultsModel),
        typeof(SqlDatabaseListResultModel),
        typeof(SqlDatabaseResourceModel),
        typeof(SqlStoredProcedureCreateUpdateParametersModel),
        typeof(SqlStoredProcedureCreateUpdatePropertiesModel),
        typeof(SqlStoredProcedureGetPropertiesModel),
        typeof(SqlStoredProcedureGetPropertiesResourceModel),
        typeof(SqlStoredProcedureGetResultsModel),
        typeof(SqlStoredProcedureListResultModel),
        typeof(SqlStoredProcedureResourceModel),
        typeof(SqlTriggerCreateUpdateParametersModel),
        typeof(SqlTriggerCreateUpdatePropertiesModel),
        typeof(SqlTriggerGetPropertiesModel),
        typeof(SqlTriggerGetPropertiesResourceModel),
        typeof(SqlTriggerGetResultsModel),
        typeof(SqlTriggerListResultModel),
        typeof(SqlTriggerResourceModel),
        typeof(SqlUserDefinedFunctionCreateUpdateParametersModel),
        typeof(SqlUserDefinedFunctionCreateUpdatePropertiesModel),
        typeof(SqlUserDefinedFunctionGetPropertiesModel),
        typeof(SqlUserDefinedFunctionGetPropertiesResourceModel),
        typeof(SqlUserDefinedFunctionGetResultsModel),
        typeof(SqlUserDefinedFunctionListResultModel),
        typeof(SqlUserDefinedFunctionResourceModel),
        typeof(TableCreateUpdateParametersModel),
        typeof(TableCreateUpdatePropertiesModel),
        typeof(TableGetPropertiesModel),
        typeof(TableGetPropertiesResourceModel),
        typeof(TableGetResultsModel),
        typeof(TableListResultModel),
        typeof(TableResourceModel),
        typeof(ThroughputPolicyResourceModel),
        typeof(ThroughputSettingsGetPropertiesModel),
        typeof(ThroughputSettingsGetPropertiesResourceModel),
        typeof(ThroughputSettingsGetResultsModel),
        typeof(ThroughputSettingsResourceModel),
        typeof(ThroughputSettingsUpdateParametersModel),
        typeof(ThroughputSettingsUpdatePropertiesModel),
        typeof(UniqueKeyModel),
        typeof(UniqueKeyPolicyModel),
        typeof(UsageModel),
        typeof(UsagesResultModel),
        typeof(VirtualNetworkRuleModel),
    };
}
