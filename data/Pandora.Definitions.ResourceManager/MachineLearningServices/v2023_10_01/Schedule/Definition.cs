using System.Collections.Generic;
using Pandora.Definitions.Interfaces;


// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See NOTICE.txt in the project root for license information.


namespace Pandora.Definitions.ResourceManager.MachineLearningServices.v2023_10_01.Schedule;

internal class Definition : ResourceDefinition
{
    public string Name => "Schedule";
    public IEnumerable<Interfaces.ApiOperation> Operations => new List<Interfaces.ApiOperation>
    {
        new CreateOrUpdateOperation(),
        new DeleteOperation(),
        new GetOperation(),
        new ListOperation(),
    };
    public IEnumerable<System.Type> Constants => new List<System.Type>
    {
        typeof(BlockedTransformersConstant),
        typeof(CategoricalDataDriftMetricConstant),
        typeof(CategoricalDataQualityMetricConstant),
        typeof(CategoricalPredictionDriftMetricConstant),
        typeof(ClassificationModelsConstant),
        typeof(ClassificationMultilabelPrimaryMetricsConstant),
        typeof(ClassificationPrimaryMetricsConstant),
        typeof(DistributionTypeConstant),
        typeof(EarlyTerminationPolicyTypeConstant),
        typeof(FeatureAttributionMetricConstant),
        typeof(FeatureImportanceModeConstant),
        typeof(FeatureLagsConstant),
        typeof(FeaturizationModeConstant),
        typeof(ForecastHorizonModeConstant),
        typeof(ForecastingModelsConstant),
        typeof(ForecastingPrimaryMetricsConstant),
        typeof(GoalConstant),
        typeof(IdentityConfigurationTypeConstant),
        typeof(InputDeliveryModeConstant),
        typeof(InstanceSegmentationPrimaryMetricsConstant),
        typeof(JobInputTypeConstant),
        typeof(JobLimitsTypeConstant),
        typeof(JobOutputTypeConstant),
        typeof(JobStatusConstant),
        typeof(JobTierConstant),
        typeof(JobTypeConstant),
        typeof(LearningRateSchedulerConstant),
        typeof(LogVerbosityConstant),
        typeof(ModelSizeConstant),
        typeof(ModelTaskTypeConstant),
        typeof(MonitorComputeIdentityTypeConstant),
        typeof(MonitorComputeTypeConstant),
        typeof(MonitoringFeatureDataTypeConstant),
        typeof(MonitoringFeatureFilterTypeConstant),
        typeof(MonitoringInputDataTypeConstant),
        typeof(MonitoringNotificationTypeConstant),
        typeof(MonitoringSignalTypeConstant),
        typeof(NCrossValidationsModeConstant),
        typeof(NodesValueTypeConstant),
        typeof(NumericalDataDriftMetricConstant),
        typeof(NumericalDataQualityMetricConstant),
        typeof(NumericalPredictionDriftMetricConstant),
        typeof(ObjectDetectionPrimaryMetricsConstant),
        typeof(OutputDeliveryModeConstant),
        typeof(RandomSamplingAlgorithmRuleConstant),
        typeof(RecurrenceFrequencyConstant),
        typeof(RegressionModelsConstant),
        typeof(RegressionPrimaryMetricsConstant),
        typeof(SamplingAlgorithmTypeConstant),
        typeof(ScheduleActionTypeConstant),
        typeof(ScheduleListViewTypeConstant),
        typeof(ScheduleProvisioningStatusConstant),
        typeof(SeasonalityModeConstant),
        typeof(ShortSeriesHandlingConfigurationConstant),
        typeof(StackMetaLearnerTypeConstant),
        typeof(StochasticOptimizerConstant),
        typeof(TargetAggregationFunctionConstant),
        typeof(TargetLagsModeConstant),
        typeof(TargetRollingWindowSizeModeConstant),
        typeof(TaskTypeConstant),
        typeof(TriggerTypeConstant),
        typeof(UseStlConstant),
        typeof(ValidationMetricTypeConstant),
        typeof(WeekDayConstant),
    };
    public IEnumerable<System.Type> Models => new List<System.Type>
    {
        typeof(AllFeaturesModel),
        typeof(AllNodesModel),
        typeof(AmlTokenModel),
        typeof(AmlTokenComputeIdentityModel),
        typeof(AutoForecastHorizonModel),
        typeof(AutoMLJobModel),
        typeof(AutoMLVerticalModel),
        typeof(AutoNCrossValidationsModel),
        typeof(AutoSeasonalityModel),
        typeof(AutoTargetLagsModel),
        typeof(AutoTargetRollingWindowSizeModel),
        typeof(BanditPolicyModel),
        typeof(BayesianSamplingAlgorithmModel),
        typeof(CategoricalDataDriftMetricThresholdModel),
        typeof(CategoricalDataQualityMetricThresholdModel),
        typeof(CategoricalPredictionDriftMetricThresholdModel),
        typeof(ClassificationModel),
        typeof(ClassificationTrainingSettingsModel),
        typeof(ColumnTransformerModel),
        typeof(CommandJobModel),
        typeof(CommandJobLimitsModel),
        typeof(CreateMonitorActionModel),
        typeof(CronTriggerModel),
        typeof(CustomForecastHorizonModel),
        typeof(CustomMetricThresholdModel),
        typeof(CustomModelJobInputModel),
        typeof(CustomModelJobOutputModel),
        typeof(CustomMonitoringSignalModel),
        typeof(CustomNCrossValidationsModel),
        typeof(CustomSeasonalityModel),
        typeof(CustomTargetLagsModel),
        typeof(CustomTargetRollingWindowSizeModel),
        typeof(DataDriftMetricThresholdBaseModel),
        typeof(DataDriftMonitoringSignalModel),
        typeof(DataQualityMetricThresholdBaseModel),
        typeof(DataQualityMonitoringSignalModel),
        typeof(DistributionConfigurationModel),
        typeof(EarlyTerminationPolicyModel),
        typeof(EndpointScheduleActionModel),
        typeof(FeatureAttributionDriftMonitoringSignalModel),
        typeof(FeatureAttributionMetricThresholdModel),
        typeof(FeatureImportanceSettingsModel),
        typeof(FeatureSubsetModel),
        typeof(FeaturizationSettingsModel),
        typeof(FixedInputDataModel),
        typeof(ForecastHorizonModel),
        typeof(ForecastingModel),
        typeof(ForecastingSettingsModel),
        typeof(ForecastingTrainingSettingsModel),
        typeof(GridSamplingAlgorithmModel),
        typeof(IdentityConfigurationModel),
        typeof(ImageClassificationModel),
        typeof(ImageClassificationMultilabelModel),
        typeof(ImageInstanceSegmentationModel),
        typeof(ImageLimitSettingsModel),
        typeof(ImageModelDistributionSettingsClassificationModel),
        typeof(ImageModelDistributionSettingsObjectDetectionModel),
        typeof(ImageModelSettingsClassificationModel),
        typeof(ImageModelSettingsObjectDetectionModel),
        typeof(ImageObjectDetectionModel),
        typeof(ImageSweepSettingsModel),
        typeof(JobBaseModel),
        typeof(JobInputModel),
        typeof(JobLimitsModel),
        typeof(JobOutputModel),
        typeof(JobResourceConfigurationModel),
        typeof(JobScheduleActionModel),
        typeof(JobServiceModel),
        typeof(LiteralJobInputModel),
        typeof(MLFlowModelJobInputModel),
        typeof(MLFlowModelJobOutputModel),
        typeof(MLTableJobInputModel),
        typeof(MLTableJobOutputModel),
        typeof(ManagedComputeIdentityModel),
        typeof(ManagedIdentityModel),
        typeof(MedianStoppingPolicyModel),
        typeof(MonitorComputeConfigurationBaseModel),
        typeof(MonitorComputeIdentityBaseModel),
        typeof(MonitorDefinitionModel),
        typeof(MonitorEmailNotificationSettingsModel),
        typeof(MonitorNotificationSettingsModel),
        typeof(MonitorServerlessSparkComputeModel),
        typeof(MonitoringFeatureFilterBaseModel),
        typeof(MonitoringInputDataBaseModel),
        typeof(MonitoringSignalBaseModel),
        typeof(MonitoringTargetModel),
        typeof(MonitoringThresholdModel),
        typeof(MpiModel),
        typeof(NCrossValidationsModel),
        typeof(NlpVerticalLimitSettingsModel),
        typeof(NodesModel),
        typeof(NumericalDataDriftMetricThresholdModel),
        typeof(NumericalDataQualityMetricThresholdModel),
        typeof(NumericalPredictionDriftMetricThresholdModel),
        typeof(ObjectiveModel),
        typeof(PipelineJobModel),
        typeof(PredictionDriftMetricThresholdBaseModel),
        typeof(PredictionDriftMonitoringSignalModel),
        typeof(PyTorchModel),
        typeof(QueueSettingsModel),
        typeof(RandomSamplingAlgorithmModel),
        typeof(RecurrenceScheduleModel),
        typeof(RecurrenceTriggerModel),
        typeof(RegressionModel),
        typeof(RegressionTrainingSettingsModel),
        typeof(RollingInputDataModel),
        typeof(SamplingAlgorithmModel),
        typeof(ScheduleModel),
        typeof(ScheduleActionBaseModel),
        typeof(ScheduleResourceModel),
        typeof(SeasonalityModel),
        typeof(StackEnsembleSettingsModel),
        typeof(StaticInputDataModel),
        typeof(SweepJobModel),
        typeof(SweepJobLimitsModel),
        typeof(TableVerticalFeaturizationSettingsModel),
        typeof(TableVerticalLimitSettingsModel),
        typeof(TargetLagsModel),
        typeof(TargetRollingWindowSizeModel),
        typeof(TensorFlowModel),
        typeof(TextClassificationModel),
        typeof(TextClassificationMultilabelModel),
        typeof(TextNerModel),
        typeof(TopNFeaturesByAttributionModel),
        typeof(TrialComponentModel),
        typeof(TriggerBaseModel),
        typeof(TritonModelJobInputModel),
        typeof(TritonModelJobOutputModel),
        typeof(TruncationSelectionPolicyModel),
        typeof(UriFileJobInputModel),
        typeof(UriFileJobOutputModel),
        typeof(UriFolderJobInputModel),
        typeof(UriFolderJobOutputModel),
        typeof(UserIdentityModel),
    };
}
