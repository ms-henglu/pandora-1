package main

type AadUserConversationMember struct {
	displayName string
	email string
	id string
	roles interface{}
	tenantId string
	user interface{}
	userId string
	visibleHistoryStartDateTime string
}

type AadUserConversationMemberCollectionResponse struct {
	value interface{}
}

type AadUserConversationMemberResult struct {
	error interface{}
	userId string
}

type AadUserNotificationRecipient struct {
	userId string
}

type AccessPackage struct {
	assignmentPolicies interface{}
	catalog interface{}
	createdDateTime string
	description string
	displayName string
	id string
	isHidden interface{}
	modifiedDateTime string
}

type AccessPackageApprovalStage struct {
	durationBeforeAutomaticDenial string
	durationBeforeEscalation string
	escalationApprovers interface{}
	fallbackEscalationApprovers interface{}
	fallbackPrimaryApprovers interface{}
	isApproverJustificationRequired interface{}
	isEscalationEnabled interface{}
	primaryApprovers interface{}
}

type AccessPackageApprovalStageCollectionResponse struct {
	value interface{}
}

type AccessPackageAssignment struct {
	accessPackage interface{}
	assignmentPolicy interface{}
	expiredDateTime string
	id string
	schedule interface{}
	state interface{}
	status string
	target interface{}
}

type AccessPackageAssignmentApprovalSettings struct {
	isApprovalRequiredForAdd interface{}
	isApprovalRequiredForUpdate interface{}
	stages interface{}
}

type AccessPackageAssignmentCollectionResponse struct {
	value interface{}
}

type AccessPackageAssignmentPolicy struct {
	accessPackage interface{}
	allowedTargetScope interface{}
	automaticRequestSettings interface{}
	catalog interface{}
	createdDateTime string
	description string
	displayName string
	expiration interface{}
	id string
	modifiedDateTime string
	requestApprovalSettings interface{}
	requestorSettings interface{}
	reviewSettings interface{}
	specificAllowedTargets interface{}
}

type AccessPackageAssignmentPolicyCollectionResponse struct {
	value interface{}
}

type AccessPackageAssignmentRequest struct {
	accessPackage interface{}
	assignment interface{}
	completedDateTime string
	createdDateTime string
	id string
	requestType interface{}
	requestor interface{}
	schedule interface{}
	state interface{}
	status string
}

type AccessPackageAssignmentRequestCollectionResponse struct {
	value interface{}
}

type AccessPackageAssignmentRequestRequirements struct {
	allowCustomAssignmentSchedule interface{}
	isApprovalRequiredForAdd interface{}
	isApprovalRequiredForUpdate interface{}
	policyDescription string
	policyDisplayName string
	policyId string
	schedule interface{}
}

type AccessPackageAssignmentRequestorSettings struct {
	allowCustomAssignmentSchedule interface{}
	enableOnBehalfRequestorsToAddAccess interface{}
	enableOnBehalfRequestorsToRemoveAccess interface{}
	enableOnBehalfRequestorsToUpdateAccess interface{}
	enableTargetsToSelfAddAccess interface{}
	enableTargetsToSelfRemoveAccess interface{}
	enableTargetsToSelfUpdateAccess interface{}
	onBehalfRequestors interface{}
}

type AccessPackageAssignmentReviewSettings struct {
	expirationBehavior interface{}
	fallbackReviewers interface{}
	isEnabled interface{}
	isRecommendationEnabled interface{}
	isReviewerJustificationRequired interface{}
	isSelfReview interface{}
	primaryReviewers interface{}
	schedule interface{}
}

type AccessPackageAutomaticRequestSettings struct {
	gracePeriodBeforeAccessRemoval string
	removeAccessWhenTargetLeavesAllowedTargets interface{}
	requestAccessForAllowedTargets interface{}
}

type AccessPackageCatalog struct {
	accessPackages interface{}
	catalogType interface{}
	createdDateTime string
	description string
	displayName string
	id string
	isExternallyVisible interface{}
	modifiedDateTime string
	state interface{}
}

type AccessPackageCatalogCollectionResponse struct {
	value interface{}
}

type AccessPackageCollectionResponse struct {
	value interface{}
}

type AccessPackageSubject struct {
	connectedOrganization interface{}
	displayName string
	email string
	id string
	objectId string
	onPremisesSecurityIdentifier string
	principalName string
	subjectType interface{}
}

type AccessReviewApplyActionCollectionResponse struct {
	value interface{}
}

type AccessReviewHistoryDefinition struct {
	createdBy interface{}
	createdDateTime string
	decisions interface{}
	displayName string
	id string
	instances interface{}
	reviewHistoryPeriodEndDateTime string
	reviewHistoryPeriodStartDateTime string
	scheduleSettings interface{}
	scopes interface{}
	status interface{}
}

type AccessReviewHistoryDefinitionCollectionResponse struct {
	value interface{}
}

type AccessReviewHistoryInstance struct {
	downloadUri string
	expirationDateTime string
	fulfilledDateTime string
	id string
	reviewHistoryPeriodEndDateTime string
	reviewHistoryPeriodStartDateTime string
	runDateTime string
	status interface{}
}

type AccessReviewHistoryInstanceCollectionResponse struct {
	value interface{}
}

type AccessReviewHistoryScheduleSettings struct {
	recurrence interface{}
	reportRange string
}

type AccessReviewInactiveUsersQueryScope struct {
	inactiveDuration string
	query string
	queryRoot string
	queryType string
}

type AccessReviewInstance struct {
	contactedReviewers interface{}
	decisions interface{}
	endDateTime string
	fallbackReviewers interface{}
	id string
	reviewers interface{}
	scope interface{}
	stages interface{}
	startDateTime string
	status string
}

type AccessReviewInstanceCollectionResponse struct {
	value interface{}
}

type AccessReviewInstanceDecisionItem struct {
	accessReviewId string
	appliedBy interface{}
	appliedDateTime string
	applyResult string
	decision string
	id string
	justification string
	principal interface{}
	principalLink string
	recommendation string
	resource interface{}
	resourceLink string
	reviewedBy interface{}
	reviewedDateTime string
}

type AccessReviewInstanceDecisionItemAccessPackageAssignmentPolicyResource struct {
	accessPackageDisplayName string
	accessPackageId string
	displayName string
	id string
	type string
}

type AccessReviewInstanceDecisionItemAzureRoleResource struct {
	displayName string
	id string
	scope interface{}
	type string
}

type AccessReviewInstanceDecisionItemCollectionResponse struct {
	value interface{}
}

type AccessReviewInstanceDecisionItemResource struct {
	displayName string
	id string
	type string
}

type AccessReviewInstanceDecisionItemServicePrincipalResource struct {
	appId string
	displayName string
	id string
	type string
}

type AccessReviewNotificationRecipientItem struct {
	notificationRecipientScope interface{}
	notificationTemplateType string
}

type AccessReviewNotificationRecipientItemCollectionResponse struct {
	value interface{}
}

type AccessReviewNotificationRecipientQueryScope struct {
	query string
	queryRoot string
	queryType string
}

type AccessReviewQueryScope struct {
	query string
	queryRoot string
	queryType string
}

type AccessReviewReviewer struct {
	createdDateTime string
	displayName string
	id string
	userPrincipalName string
}

type AccessReviewReviewerCollectionResponse struct {
	value interface{}
}

type AccessReviewReviewerScope struct {
	query string
	queryRoot string
	queryType string
}

type AccessReviewReviewerScopeCollectionResponse struct {
	value interface{}
}

type AccessReviewScheduleDefinition struct {
	additionalNotificationRecipients interface{}
	createdBy interface{}
	createdDateTime string
	descriptionForAdmins string
	descriptionForReviewers string
	displayName string
	fallbackReviewers interface{}
	id string
	instanceEnumerationScope interface{}
	instances interface{}
	lastModifiedDateTime string
	reviewers interface{}
	scope interface{}
	settings interface{}
	stageSettings interface{}
	status string
}

type AccessReviewScheduleDefinitionCollectionResponse struct {
	value interface{}
}

type AccessReviewScheduleSettings struct {
	applyActions interface{}
	autoApplyDecisionsEnabled interface{}
	decisionHistoriesForReviewersEnabled interface{}
	defaultDecision string
	defaultDecisionEnabled interface{}
	instanceDurationInDays interface{}
	justificationRequiredOnApproval interface{}
	mailNotificationsEnabled interface{}
	recommendationsEnabled interface{}
	recurrence interface{}
	reminderNotificationsEnabled interface{}
}

type AccessReviewScopeCollectionResponse struct {
	value interface{}
}

type AccessReviewSet struct {
	definitions interface{}
	historyDefinitions interface{}
	id string
}

type AccessReviewStage struct {
	decisions interface{}
	endDateTime string
	fallbackReviewers interface{}
	id string
	reviewers interface{}
	startDateTime string
	status string
}

type AccessReviewStageCollectionResponse struct {
	value interface{}
}

type AccessReviewStageSettings struct {
	decisionsThatWillMoveToNextStage interface{}
	dependsOn interface{}
	durationInDays interface{}
	fallbackReviewers interface{}
	recommendationsEnabled interface{}
	reviewers interface{}
	stageId string
}

type AccessReviewStageSettingsCollectionResponse struct {
	value interface{}
}

type ActionResultPart struct {
	error interface{}
}

type ActivityBasedTimeoutPolicy struct {
	appliesTo interface{}
	definition interface{}
	deletedDateTime string
	description string
	displayName string
	id string
	isOrganizationDefault interface{}
}

type ActivityBasedTimeoutPolicyCollectionResponse struct {
	value interface{}
}

type ActivityHistoryItem struct {
	activeDurationSeconds interface{}
	activity interface{}
	createdDateTime string
	expirationDateTime string
	id string
	lastActiveDateTime string
	lastModifiedDateTime string
	startedDateTime string
	status interface{}
	userTimezone string
}

type ActivityHistoryItemCollectionResponse struct {
	value interface{}
}

type AddIn struct {
	id string
	properties interface{}
	type string
}

type AddInCollectionResponse struct {
	value interface{}
}

type Admin struct {
	serviceAnnouncement interface{}
}

type AdminConsentRequestPolicy struct {
	id string
	isEnabled interface{}
	notifyReviewers interface{}
	remindersEnabled interface{}
	requestDurationInDays interface{}
	reviewers interface{}
	version interface{}
}

type AdministrativeUnit struct {
	deletedDateTime string
	description string
	displayName string
	extensions interface{}
	id string
	members interface{}
	scopedRoleMembers interface{}
	visibility string
}

type AdministrativeUnitCollectionResponse struct {
	value interface{}
}

type AggregationOption struct {
	bucketDefinition interface{}
	field string
	size interface{}
}

type AggregationOptionCollectionResponse struct {
	value interface{}
}

type Agreement struct {
	acceptances interface{}
	displayName string
	file interface{}
	files interface{}
	id string
	isPerDeviceAcceptanceRequired interface{}
	isViewingBeforeAcceptanceRequired interface{}
	termsExpiration interface{}
	userReacceptRequiredFrequency string
}

type AgreementAcceptance struct {
	agreementFileId string
	agreementId string
	deviceDisplayName string
	deviceId string
	deviceOSType string
	deviceOSVersion string
	expirationDateTime string
	id string
	recordedDateTime string
	state interface{}
	userDisplayName string
	userEmail string
	userId string
	userPrincipalName string
}

type AgreementAcceptanceCollectionResponse struct {
	value interface{}
}

type AgreementCollectionResponse struct {
	value interface{}
}

type AgreementFile struct {
	createdDateTime string
	displayName string
	fileData interface{}
	fileName string
	id string
	isDefault interface{}
	isMajorVersion interface{}
	language string
	localizations interface{}
}

type AgreementFileData struct {
	data string
}

type AgreementFileLocalization struct {
	createdDateTime string
	displayName string
	fileData interface{}
	fileName string
	id string
	isDefault interface{}
	isMajorVersion interface{}
	language string
	versions interface{}
}

type AgreementFileLocalizationCollectionResponse struct {
	value interface{}
}

type AgreementFileProperties struct {
	createdDateTime string
	displayName string
	fileData interface{}
	fileName string
	id string
	isDefault interface{}
	isMajorVersion interface{}
	language string
}

type AgreementFileVersion struct {
	createdDateTime string
	displayName string
	fileData interface{}
	fileName string
	id string
	isDefault interface{}
	isMajorVersion interface{}
	language string
}

type AgreementFileVersionCollectionResponse struct {
	value interface{}
}

type Album struct {
	coverImageItemId string
}

type Alert struct {
	activityGroupName string
	alertDetections interface{}
	assignedTo string
	azureSubscriptionId string
	azureTenantId string
	category string
	closedDateTime string
	cloudAppStates interface{}
	comments interface{}
	confidence interface{}
	createdDateTime string
	description string
	detectionIds interface{}
	eventDateTime string
	feedback interface{}
	fileStates interface{}
	historyStates interface{}
	hostStates interface{}
	id string
	incidentIds interface{}
	investigationSecurityStates interface{}
	lastEventDateTime string
	lastModifiedDateTime string
	malwareStates interface{}
	messageSecurityStates interface{}
	networkConnections interface{}
	processes interface{}
	recommendedActions interface{}
	registryKeyStates interface{}
	securityResources interface{}
	severity string
	sourceMaterials interface{}
	status string
	tags interface{}
	title string
	triggers interface{}
	uriClickSecurityStates interface{}
	userStates interface{}
	vendorInformation interface{}
	vulnerabilityStates interface{}
}

type AlertCollectionResponse struct {
	value interface{}
}

type AlertDetection struct {
	detectionType string
	method string
	name string
}

type AlertDetectionCollectionResponse struct {
	value interface{}
}

type AlertHistoryState struct {
	appId string
	assignedTo string
	comments interface{}
	feedback interface{}
	status interface{}
	updatedDateTime string
	user string
}

type AlertHistoryStateCollectionResponse struct {
	value interface{}
}

type AlertTrigger struct {
	name string
	type string
	value string
}

type AlertTriggerCollectionResponse struct {
	value interface{}
}

type AlterationResponse struct {
	originalQueryString string
	queryAlteration interface{}
	queryAlterationType interface{}
}

type AlteredQueryToken struct {
	length interface{}
	offset interface{}
	suggestion string
}

type AlteredQueryTokenCollectionResponse struct {
	value interface{}
}

type AlternativeSecurityId struct {
	identityProvider string
	key string
	type interface{}
}

type AlternativeSecurityIdCollectionResponse struct {
	value interface{}
}

type AndroidCompliancePolicy struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	deviceThreatProtectionEnabled interface{}
	deviceThreatProtectionRequiredSecurityLevel string
	displayName string
	id string
	lastModifiedDateTime string
	minAndroidSecurityPatchLevel string
	osMaximumVersion string
	osMinimumVersion string
	passwordExpirationDays interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeLock interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequired interface{}
	passwordRequiredType string
	scheduledActionsForRule interface{}
	securityBlockJailbrokenDevices interface{}
	securityDisableUsbDebugging interface{}
	securityPreventInstallAppsFromUnknownSources interface{}
	securityRequireCompanyPortalAppIntegrity interface{}
	securityRequireGooglePlayServices interface{}
	securityRequireSafetyNetAttestationBasicIntegrity interface{}
	securityRequireSafetyNetAttestationCertifiedDevice interface{}
	securityRequireUpToDateSecurityProviders interface{}
	securityRequireVerifyApps interface{}
	storageRequireEncryption interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type AndroidCompliancePolicyCollectionResponse struct {
	value interface{}
}

type AndroidCustomConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	omaSettings interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type AndroidCustomConfigurationCollectionResponse struct {
	value interface{}
}

type AndroidGeneralDeviceConfiguration struct {
	appsBlockClipboardSharing interface{}
	appsBlockCopyPaste interface{}
	appsBlockYouTube interface{}
	appsHideList interface{}
	appsInstallAllowList interface{}
	appsLaunchBlockList interface{}
	assignments interface{}
	bluetoothBlocked interface{}
	cameraBlocked interface{}
	cellularBlockDataRoaming interface{}
	cellularBlockMessaging interface{}
	cellularBlockVoiceRoaming interface{}
	cellularBlockWiFiTethering interface{}
	compliantAppListType string
	compliantAppsList interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceSharingAllowed interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	diagnosticDataBlockSubmission interface{}
	displayName string
	factoryResetBlocked interface{}
	googleAccountBlockAutoSync interface{}
	googlePlayStoreBlocked interface{}
	id string
	kioskModeApps interface{}
	kioskModeBlockSleepButton interface{}
	kioskModeBlockVolumeButtons interface{}
	lastModifiedDateTime string
	locationServicesBlocked interface{}
	nfcBlocked interface{}
	passwordBlockFingerprintUnlock interface{}
	passwordBlockTrustAgents interface{}
	passwordExpirationDays interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeScreenTimeout interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequired interface{}
	passwordRequiredType string
	passwordSignInFailureCountBeforeFactoryReset interface{}
	powerOffBlocked interface{}
	screenCaptureBlocked interface{}
	securityRequireVerifyApps interface{}
	storageBlockGoogleBackup interface{}
	storageBlockRemovableStorage interface{}
	storageRequireDeviceEncryption interface{}
	storageRequireRemovableStorageEncryption interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
	voiceAssistantBlocked interface{}
	voiceDialingBlocked interface{}
	webBrowserBlockAutofill interface{}
	webBrowserBlockJavaScript interface{}
	webBrowserBlockPopups interface{}
	webBrowserBlocked interface{}
	webBrowserCookieSettings string
	wiFiBlocked interface{}
}

type AndroidGeneralDeviceConfigurationCollectionResponse struct {
	value interface{}
}

type AndroidLobApp struct {
	assignments interface{}
	categories interface{}
	committedContentVersion string
	contentVersions interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	fileName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	minimumSupportedOperatingSystem interface{}
	notes string
	owner string
	packageId string
	privacyInformationUrl string
	publisher string
	publishingState string
	size interface{}
	versionCode string
	versionName string
}

type AndroidLobAppCollectionResponse struct {
	value interface{}
}

type AndroidManagedAppProtection struct {
	allowedDataStorageLocations interface{}
	allowedInboundDataTransferSources string
	allowedOutboundClipboardSharingLevel string
	allowedOutboundDataTransferDestinations string
	apps interface{}
	assignments interface{}
	contactSyncBlocked interface{}
	createdDateTime string
	customBrowserDisplayName string
	customBrowserPackageId string
	dataBackupBlocked interface{}
	deployedAppCount interface{}
	deploymentSummary interface{}
	description string
	deviceComplianceRequired interface{}
	disableAppEncryptionIfDeviceEncryptionIsEnabled interface{}
	disableAppPinIfDevicePinIsSet interface{}
	displayName string
	encryptAppData interface{}
	fingerprintBlocked interface{}
	id string
	isAssigned interface{}
	lastModifiedDateTime string
	managedBrowser string
	managedBrowserToOpenLinksRequired interface{}
	maximumPinRetries interface{}
	minimumPinLength interface{}
	minimumRequiredAppVersion string
	minimumRequiredOsVersion string
	minimumRequiredPatchVersion string
	minimumWarningAppVersion string
	minimumWarningOsVersion string
	minimumWarningPatchVersion string
	organizationalCredentialsRequired interface{}
	periodBeforePinReset string
	periodOfflineBeforeAccessCheck string
	periodOfflineBeforeWipeIsEnforced string
	periodOnlineBeforeAccessCheck string
	pinCharacterSet string
	pinRequired interface{}
	printBlocked interface{}
	saveAsBlocked interface{}
	screenCaptureBlocked interface{}
	simplePinBlocked interface{}
	version string
}

type AndroidManagedAppProtectionCollectionResponse struct {
	value interface{}
}

type AndroidManagedAppRegistration struct {
	appIdentifier interface{}
	applicationVersion string
	appliedPolicies interface{}
	createdDateTime string
	deviceName string
	deviceTag string
	deviceType string
	flaggedReasons interface{}
	id string
	intendedPolicies interface{}
	lastSyncDateTime string
	managementSdkVersion string
	operations interface{}
	platformVersion string
	userId string
	version string
}

type AndroidManagedAppRegistrationCollectionResponse struct {
	value interface{}
}

type AndroidMinimumOperatingSystem struct {
	v10_0 interface{}
	v11_0 interface{}
	v4_0 interface{}
	v4_0_3 interface{}
	v4_1 interface{}
	v4_2 interface{}
	v4_3 interface{}
	v4_4 interface{}
	v5_0 interface{}
	v5_1 interface{}
}

type AndroidMobileAppIdentifier struct {
	packageId string
}

type AndroidStoreApp struct {
	appStoreUrl string
	assignments interface{}
	categories interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	minimumSupportedOperatingSystem interface{}
	notes string
	owner string
	packageId string
	privacyInformationUrl string
	publisher string
	publishingState string
}

type AndroidStoreAppCollectionResponse struct {
	value interface{}
}

type AndroidWorkProfileCompliancePolicy struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	deviceThreatProtectionEnabled interface{}
	deviceThreatProtectionRequiredSecurityLevel string
	displayName string
	id string
	lastModifiedDateTime string
	minAndroidSecurityPatchLevel string
	osMaximumVersion string
	osMinimumVersion string
	passwordExpirationDays interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeLock interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequired interface{}
	passwordRequiredType string
	scheduledActionsForRule interface{}
	securityBlockJailbrokenDevices interface{}
	securityDisableUsbDebugging interface{}
	securityPreventInstallAppsFromUnknownSources interface{}
	securityRequireCompanyPortalAppIntegrity interface{}
	securityRequireGooglePlayServices interface{}
	securityRequireSafetyNetAttestationBasicIntegrity interface{}
	securityRequireSafetyNetAttestationCertifiedDevice interface{}
	securityRequireUpToDateSecurityProviders interface{}
	securityRequireVerifyApps interface{}
	storageRequireEncryption interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type AndroidWorkProfileCompliancePolicyCollectionResponse struct {
	value interface{}
}

type AndroidWorkProfileCustomConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	omaSettings interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type AndroidWorkProfileCustomConfigurationCollectionResponse struct {
	value interface{}
}

type AndroidWorkProfileGeneralDeviceConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	passwordBlockFingerprintUnlock interface{}
	passwordBlockTrustAgents interface{}
	passwordExpirationDays interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeScreenTimeout interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequiredType string
	passwordSignInFailureCountBeforeFactoryReset interface{}
	securityRequireVerifyApps interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
	workProfileBlockAddingAccounts interface{}
	workProfileBlockCamera interface{}
	workProfileBlockCrossProfileCallerId interface{}
	workProfileBlockCrossProfileContactsSearch interface{}
	workProfileBlockCrossProfileCopyPaste interface{}
	workProfileBlockNotificationsWhileDeviceLocked interface{}
	workProfileBlockScreenCapture interface{}
	workProfileBluetoothEnableContactSharing interface{}
	workProfileDataSharingType string
	workProfileDefaultAppPermissionPolicy string
	workProfilePasswordBlockFingerprintUnlock interface{}
	workProfilePasswordBlockTrustAgents interface{}
	workProfilePasswordExpirationDays interface{}
	workProfilePasswordMinLetterCharacters interface{}
	workProfilePasswordMinLowerCaseCharacters interface{}
	workProfilePasswordMinNonLetterCharacters interface{}
	workProfilePasswordMinNumericCharacters interface{}
	workProfilePasswordMinSymbolCharacters interface{}
	workProfilePasswordMinUpperCaseCharacters interface{}
	workProfilePasswordMinimumLength interface{}
	workProfilePasswordMinutesOfInactivityBeforeScreenTimeout interface{}
	workProfilePasswordPreviousPasswordBlockCount interface{}
	workProfilePasswordRequiredType string
	workProfilePasswordSignInFailureCountBeforeFactoryReset interface{}
	workProfileRequirePassword interface{}
}

type AndroidWorkProfileGeneralDeviceConfigurationCollectionResponse struct {
	value interface{}
}

type ApiApplication struct {
	acceptMappedClaims interface{}
	knownClientApplications interface{}
	oauth2PermissionScopes interface{}
	preAuthorizedApplications interface{}
	requestedAccessTokenVersion interface{}
}

type AppCatalogs struct {
	id string
	teamsApps interface{}
}

type AppConfigurationSettingItem struct {
	appConfigKey string
	appConfigKeyType string
	appConfigKeyValue string
}

type AppConfigurationSettingItemCollectionResponse struct {
	value interface{}
}

type AppConsentApprovalRoute struct {
	appConsentRequests interface{}
	id string
}

type AppConsentRequest struct {
	appDisplayName string
	appId string
	id string
	pendingScopes interface{}
	userConsentRequests interface{}
}

type AppConsentRequestCollectionResponse struct {
	value interface{}
}

type AppConsentRequestScope struct {
	displayName string
}

type AppConsentRequestScopeCollectionResponse struct {
	value interface{}
}

type AppHostedMediaConfig struct {
	blob string
}

type AppIdentity struct {
	appId string
	displayName string
	servicePrincipalId string
	servicePrincipalName string
}

type AppListItem struct {
	appId string
	appStoreUrl string
	name string
	publisher string
}

type AppListItemCollectionResponse struct {
	value interface{}
}

type AppRole struct {
	allowedMemberTypes interface{}
	description string
	displayName string
	id string
	isEnabled interface{}
	origin string
	value string
}

type AppRoleAssignment struct {
	appRoleId string
	createdDateTime string
	deletedDateTime string
	id string
	principalDisplayName string
	principalId string
	principalType string
	resourceDisplayName string
	resourceId string
}

type AppRoleAssignmentCollectionResponse struct {
	value interface{}
}

type AppRoleCollectionResponse struct {
	value interface{}
}

type AppScope struct {
	displayName string
	id string
	type string
}

type AppleDeviceFeaturesConfigurationBase struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type AppleDeviceFeaturesConfigurationBaseCollectionResponse struct {
	value interface{}
}

type AppleManagedIdentityProvider struct {
	certificateData string
	developerId string
	displayName string
	id string
	keyId string
	serviceId string
}

type AppleManagedIdentityProviderCollectionResponse struct {
	value interface{}
}

type ApplePushNotificationCertificate struct {
	appleIdentifier string
	certificate string
	certificateSerialNumber string
	expirationDateTime string
	id string
	lastModifiedDateTime string
	topicIdentifier string
}

type Application struct {
	addIns interface{}
	api interface{}
	appId string
	appRoles interface{}
	applicationTemplateId string
	certification interface{}
	createdDateTime string
	createdOnBehalfOf interface{}
	deletedDateTime string
	description string
	disabledByMicrosoftStatus string
	displayName string
	extensionProperties interface{}
	federatedIdentityCredentials interface{}
	groupMembershipClaims string
	homeRealmDiscoveryPolicies interface{}
	id string
	identifierUris interface{}
	info interface{}
	isDeviceOnlyAuthSupported interface{}
	isFallbackPublicClient interface{}
	keyCredentials interface{}
	logo string
	notes string
	oauth2RequirePostResponse interface{}
	optionalClaims interface{}
	owners interface{}
	parentalControlSettings interface{}
	passwordCredentials interface{}
	publicClient interface{}
	publisherDomain string
	requiredResourceAccess interface{}
	samlMetadataUrl string
	serviceManagementReference string
	signInAudience string
	spa interface{}
	tags interface{}
	tokenEncryptionKeyId string
	tokenIssuancePolicies interface{}
	tokenLifetimePolicies interface{}
	verifiedPublisher interface{}
	web interface{}
}

type ApplicationCollectionResponse struct {
	value interface{}
}

type ApplicationEnforcedRestrictionsSessionControl struct {
	isEnabled interface{}
}

type ApplicationServicePrincipal struct {
	application interface{}
	servicePrincipal interface{}
}

type ApplicationTemplate struct {
	categories interface{}
	description string
	displayName string
	homePageUrl string
	id string
	logoUrl string
	publisher string
	supportedProvisioningTypes interface{}
	supportedSingleSignOnModes interface{}
}

type ApplicationTemplateCollectionResponse struct {
	value interface{}
}

type AppliedConditionalAccessPolicy struct {
	displayName string
	enforcedGrantControls interface{}
	enforcedSessionControls interface{}
	id string
	result interface{}
}

type AppliedConditionalAccessPolicyCollectionResponse struct {
	value interface{}
}

type Approval struct {
	id string
	stages interface{}
}

type ApprovalCollectionResponse struct {
	value interface{}
}

type ApprovalSettings struct {
	approvalMode string
	approvalStages interface{}
	isApprovalRequired interface{}
	isApprovalRequiredForExtension interface{}
	isRequestorJustificationRequired interface{}
}

type ApprovalStage struct {
	assignedToMe interface{}
	displayName string
	id string
	justification string
	reviewResult string
	reviewedBy interface{}
	reviewedDateTime string
	status string
}

type ApprovalStageCollectionResponse struct {
	value interface{}
}

type ArchivedPrintJob struct {
	acquiredByPrinter interface{}
	acquiredDateTime string
	completionDateTime string
	copiesPrinted interface{}
	createdBy interface{}
	createdDateTime string
	id string
	printerId string
	processingState string
}

type AssignedLabel struct {
	displayName string
	labelId string
}

type AssignedLabelCollectionResponse struct {
	value interface{}
}

type AssignedLicense struct {
	disabledPlans interface{}
	skuId string
}

type AssignedLicenseCollectionResponse struct {
	value interface{}
}

type AssignedPlan struct {
	assignedDateTime string
	capabilityStatus string
	service string
	servicePlanId string
}

type AssignedPlanCollectionResponse struct {
	value interface{}
}

type AssignmentOrder struct {
	order interface{}
}

type AssociatedTeamInfo struct {
	displayName string
	id string
	team interface{}
	tenantId string
}

type AssociatedTeamInfoCollectionResponse struct {
	value interface{}
}

type Attachment struct {
	contentType string
	id string
	isInline interface{}
	lastModifiedDateTime string
	name string
	size interface{}
}

type AttachmentBase struct {
	contentType string
	id string
	lastModifiedDateTime string
	name string
	size interface{}
}

type AttachmentBaseCollectionResponse struct {
	value interface{}
}

type AttachmentCollectionResponse struct {
	value interface{}
}

type AttachmentInfo struct {
	attachmentType interface{}
	contentType string
	name string
	size interface{}
}

type AttachmentItem struct {
	attachmentType interface{}
	contentId string
	contentType string
	isInline interface{}
	name string
	size interface{}
}

type AttachmentSession struct {
	content string
	expirationDateTime string
	id string
	nextExpectedRanges interface{}
}

type AttachmentSessionCollectionResponse struct {
	value interface{}
}

type AttendanceInterval struct {
	durationInSeconds interface{}
	joinDateTime string
	leaveDateTime string
}

type AttendanceIntervalCollectionResponse struct {
	value interface{}
}

type AttendanceRecord struct {
	attendanceIntervals interface{}
	emailAddress string
	id string
	identity interface{}
	role string
	totalAttendanceInSeconds interface{}
}

type AttendanceRecordCollectionResponse struct {
	value interface{}
}

type Attendee struct {
	emailAddress interface{}
	proposedNewTime interface{}
	status interface{}
	type interface{}
}

type AttendeeAvailability struct {
	attendee interface{}
	availability interface{}
}

type AttendeeAvailabilityCollectionResponse struct {
	value interface{}
}

type AttendeeBase struct {
	emailAddress interface{}
	type interface{}
}

type AttendeeCollectionResponse struct {
	value interface{}
}

type AttributeRuleMembers struct {
	description string
	membershipRule string
}

type Audio struct {
	album string
	albumArtist string
	artist string
	bitrate interface{}
	composers string
	copyright string
	disc interface{}
	discCount interface{}
	duration interface{}
	genre string
	hasDrm interface{}
	isVariableBitrate interface{}
	title string
	track interface{}
	trackCount interface{}
	year interface{}
}

type AudioConferencing struct {
	conferenceId string
	dialinUrl string
	tollFreeNumber string
	tollFreeNumbers interface{}
	tollNumber string
	tollNumbers interface{}
}

type AudioRoutingGroup struct {
	id string
	receivers interface{}
	routingMode string
	sources interface{}
}

type AudioRoutingGroupCollectionResponse struct {
	value interface{}
}

type AuditActivityInitiator struct {
	app interface{}
	user interface{}
}

type AuditLogRoot struct {
	directoryAudits interface{}
	id string
	provisioning interface{}
	restrictedSignIns interface{}
	signIns interface{}
}

type Authentication struct {
	emailMethods interface{}
	fido2Methods interface{}
	id string
	methods interface{}
	microsoftAuthenticatorMethods interface{}
	operations interface{}
	passwordMethods interface{}
	phoneMethods interface{}
	softwareOathMethods interface{}
	temporaryAccessPassMethods interface{}
	windowsHelloForBusinessMethods interface{}
}

type AuthenticationFlowsPolicy struct {
	description string
	displayName string
	id string
	selfServiceSignUp interface{}
}

type AuthenticationMethod struct {
	id string
}

type AuthenticationMethodCollectionResponse struct {
	value interface{}
}

type AuthenticationMethodConfiguration struct {
	id string
	state interface{}
}

type AuthenticationMethodConfigurationCollectionResponse struct {
	value interface{}
}

type AuthenticationMethodTarget struct {
	id string
	isRegistrationRequired interface{}
	targetType string
}

type AuthenticationMethodTargetCollectionResponse struct {
	value interface{}
}

type AuthenticationMethodsPolicy struct {
	authenticationMethodConfigurations interface{}
	description string
	displayName string
	id string
	lastModifiedDateTime string
	policyVersion string
	reconfirmationInDays interface{}
	registrationEnforcement interface{}
}

type AuthenticationMethodsRegistrationCampaign struct {
	excludeTargets interface{}
	includeTargets interface{}
	snoozeDurationInDays interface{}
	state string
}

type AuthenticationMethodsRegistrationCampaignIncludeTarget struct {
	id string
	targetType string
	targetedAuthenticationMethod string
}

type AuthenticationMethodsRegistrationCampaignIncludeTargetCollectionResponse struct {
	value interface{}
}

type AuthoredNote struct {
	author interface{}
	content interface{}
	createdDateTime string
	id string
}

type AuthoredNoteCollectionResponse struct {
	value interface{}
}

type AuthorizationPolicy struct {
	allowEmailVerifiedUsersToJoinOrganization interface{}
	allowInvitesFrom interface{}
	allowedToSignUpEmailBasedSubscriptions interface{}
	allowedToUseSSPR interface{}
	blockMsolPowerShell interface{}
	defaultUserRolePermissions interface{}
	deletedDateTime string
	description string
	displayName string
	guestUserRoleId string
	id string
}

type AuthorizationPolicyCollectionResponse struct {
	value interface{}
}

type AutomaticRepliesMailTips struct {
	message string
	messageLanguage interface{}
	scheduledEndTime interface{}
	scheduledStartTime interface{}
}

type AutomaticRepliesSetting struct {
	externalAudience interface{}
	externalReplyMessage string
	internalReplyMessage string
	scheduledEndDateTime interface{}
	scheduledStartDateTime interface{}
	status interface{}
}

type AvailabilityItem struct {
	endDateTime interface{}
	serviceId string
	startDateTime interface{}
	status interface{}
}

type AvailabilityItemCollectionResponse struct {
	value interface{}
}

type AverageComparativeScore struct {
	averageScore interface{}
	basis string
}

type AverageComparativeScoreCollectionResponse struct {
	value interface{}
}

type AzureActiveDirectoryTenant struct {
	displayName string
	tenantId string
}

type B2xIdentityUserFlow struct {
	apiConnectorConfiguration interface{}
	id string
	identityProviders interface{}
	languages interface{}
	userAttributeAssignments interface{}
	userFlowIdentityProviders interface{}
	userFlowType string
	userFlowTypeVersion interface{}
}

type B2xIdentityUserFlowCollectionResponse struct {
	value interface{}
}

type BaseItem struct {
	createdBy interface{}
	createdByUser interface{}
	createdDateTime string
	description string
	eTag string
	id string
	lastModifiedBy interface{}
	lastModifiedByUser interface{}
	lastModifiedDateTime string
	name string
	parentReference interface{}
	webUrl string
}

type BaseItemCollectionResponse struct {
	value interface{}
}

type BaseItemVersion struct {
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	publication interface{}
}

type BasicAuthentication struct {
	password string
	username string
}

type BitLockerRemovableDrivePolicy struct {
	blockCrossOrganizationWriteAccess interface{}
	encryptionMethod interface{}
	requireEncryptionForWriteAccess interface{}
}

type Bitlocker struct {
	id string
	recoveryKeys interface{}
}

type BitlockerRecoveryKey struct {
	createdDateTime string
	deviceId string
	id string
	key string
	volumeType interface{}
}

type BitlockerRecoveryKeyCollectionResponse struct {
	value interface{}
}

type BookingAppointment struct {
	additionalInformation string
	customerTimeZone string
	customers interface{}
	duration string
	endDateTime interface{}
	filledAttendeesCount interface{}
	id string
	isLocationOnline interface{}
	joinWebUrl string
	maximumAttendeesCount interface{}
	optOutOfCustomerEmail interface{}
	postBuffer string
	preBuffer string
	price interface{}
	priceType string
	reminders interface{}
	selfServiceAppointmentId string
	serviceId string
	serviceLocation interface{}
	serviceName string
	serviceNotes string
	smsNotificationsEnabled interface{}
	staffMemberIds interface{}
	startDateTime interface{}
}

type BookingAppointmentCollectionResponse struct {
	value interface{}
}

type BookingBusiness struct {
	address interface{}
	appointments interface{}
	businessHours interface{}
	businessType string
	calendarView interface{}
	customQuestions interface{}
	customers interface{}
	defaultCurrencyIso string
	displayName string
	email string
	id string
	isPublished interface{}
	phone string
	publicUrl string
	schedulingPolicy interface{}
	services interface{}
	staffMembers interface{}
	webSiteUrl string
}

type BookingBusinessCollectionResponse struct {
	value interface{}
}

type BookingCurrency struct {
	id string
	symbol string
}

type BookingCurrencyCollectionResponse struct {
	value interface{}
}

type BookingCustomQuestion struct {
	answerInputType interface{}
	answerOptions interface{}
	displayName string
	id string
}

type BookingCustomQuestionCollectionResponse struct {
	value interface{}
}

type BookingCustomer struct {
	addresses interface{}
	displayName string
	emailAddress string
	id string
	phones interface{}
}

type BookingCustomerBase struct {
	id string
}

type BookingCustomerBaseCollectionResponse struct {
	value interface{}
}

type BookingCustomerCollectionResponse struct {
	value interface{}
}

type BookingCustomerInformation struct {
	customQuestionAnswers interface{}
	customerId string
	emailAddress string
	location interface{}
	name string
	notes string
	phone string
	timeZone string
}

type BookingCustomerInformationBaseCollectionResponse struct {
	value interface{}
}

type BookingQuestionAnswer struct {
	answer string
	answerInputType interface{}
	answerOptions interface{}
	isRequired interface{}
	question string
	questionId string
	selectedOptions interface{}
}

type BookingQuestionAnswerCollectionResponse struct {
	value interface{}
}

type BookingQuestionAssignment struct {
	isRequired interface{}
	questionId string
}

type BookingQuestionAssignmentCollectionResponse struct {
	value interface{}
}

type BookingReminder struct {
	message string
	offset string
	recipients string
}

type BookingReminderCollectionResponse struct {
	value interface{}
}

type BookingSchedulingPolicy struct {
	allowStaffSelection interface{}
	maximumAdvance string
	minimumLeadTime string
	sendConfirmationsToOwner interface{}
	timeSlotInterval string
}

type BookingService struct {
	additionalInformation string
	customQuestions interface{}
	defaultDuration string
	defaultLocation interface{}
	defaultPrice interface{}
	defaultPriceType string
	defaultReminders interface{}
	description string
	displayName string
	id string
	isHiddenFromCustomers interface{}
	isLocationOnline interface{}
	maximumAttendeesCount interface{}
	notes string
	postBuffer string
	preBuffer string
	schedulingPolicy interface{}
	smsNotificationsEnabled interface{}
	staffMemberIds interface{}
	webUrl string
}

type BookingServiceCollectionResponse struct {
	value interface{}
}

type BookingStaffMember struct {
	availabilityIsAffectedByPersonalCalendar interface{}
	displayName string
	emailAddress string
	id string
	role string
	timeZone string
	useBusinessHours interface{}
	workingHours interface{}
}

type BookingStaffMemberBase struct {
	id string
}

type BookingStaffMemberBaseCollectionResponse struct {
	value interface{}
}

type BookingStaffMemberCollectionResponse struct {
	value interface{}
}

type BookingWorkHours struct {
	day string
	timeSlots interface{}
}

type BookingWorkHoursCollectionResponse struct {
	value interface{}
}

type BookingWorkTimeSlot struct {
	endTime string
	startTime string
}

type BookingWorkTimeSlotCollectionResponse struct {
	value interface{}
}

type BroadcastMeetingSettings struct {
	allowedAudience interface{}
	isAttendeeReportEnabled interface{}
	isQuestionAndAnswerEnabled interface{}
	isRecordingEnabled interface{}
	isVideoOnDemandEnabled interface{}
}

type BucketAggregationDefinition struct {
	isDescending interface{}
	minimumCount interface{}
	prefixFilter string
	ranges interface{}
	sortBy string
}

type BucketAggregationRange struct {
	from string
	to string
}

type BucketAggregationRangeCollectionResponse struct {
	value interface{}
}

type BuiltInIdentityProvider struct {
	displayName string
	id string
	identityProviderType string
}

type BuiltInIdentityProviderCollectionResponse struct {
	value interface{}
}

type Bundle struct {
	album interface{}
	childCount interface{}
}

type CalculatedColumn struct {
	format string
	formula string
	outputType string
}

type Calendar struct {
	allowedOnlineMeetingProviders interface{}
	calendarPermissions interface{}
	calendarView interface{}
	canEdit interface{}
	canShare interface{}
	canViewPrivateItems interface{}
	changeKey string
	color interface{}
	defaultOnlineMeetingProvider interface{}
	events interface{}
	hexColor string
	id string
	isDefaultCalendar interface{}
	isRemovable interface{}
	isTallyingResponses interface{}
	multiValueExtendedProperties interface{}
	name string
	owner interface{}
	singleValueExtendedProperties interface{}
}

type CalendarCollectionResponse struct {
	value interface{}
}

type CalendarGroup struct {
	calendars interface{}
	changeKey string
	classId string
	id string
	name string
}

type CalendarGroupCollectionResponse struct {
	value interface{}
}

type CalendarPermission struct {
	allowedRoles interface{}
	emailAddress interface{}
	id string
	isInsideOrganization interface{}
	isRemovable interface{}
	role interface{}
}

type CalendarPermissionCollectionResponse struct {
	value interface{}
}

type CalendarSharingMessage struct {
	attachments interface{}
	bccRecipients interface{}
	body interface{}
	bodyPreview string
	canAccept interface{}
	categories interface{}
	ccRecipients interface{}
	changeKey string
	conversationId string
	conversationIndex string
	createdDateTime string
	extensions interface{}
	flag interface{}
	from interface{}
	hasAttachments interface{}
	id string
	importance interface{}
	inferenceClassification interface{}
	internetMessageHeaders interface{}
	internetMessageId string
	isDeliveryReceiptRequested interface{}
	isDraft interface{}
	isRead interface{}
	isReadReceiptRequested interface{}
	lastModifiedDateTime string
	multiValueExtendedProperties interface{}
	parentFolderId string
	receivedDateTime string
	replyTo interface{}
	sender interface{}
	sentDateTime string
	sharingMessageAction interface{}
	sharingMessageActions interface{}
	singleValueExtendedProperties interface{}
	subject string
	suggestedCalendarName string
	toRecipients interface{}
	uniqueBody interface{}
	webLink string
}

type CalendarSharingMessageAction struct {
	action interface{}
	actionType interface{}
	importance interface{}
}

type CalendarSharingMessageActionCollectionResponse struct {
	value interface{}
}

type CalendarSharingMessageCollectionResponse struct {
	value interface{}
}

type Call struct {
	audioRoutingGroups interface{}
	callChainId string
	callOptions interface{}
	callRoutes interface{}
	callbackUri string
	chatInfo interface{}
	direction interface{}
	id string
	incomingContext interface{}
	mediaConfig interface{}
	mediaState interface{}
	meetingInfo interface{}
	myParticipantId string
	operations interface{}
	participants interface{}
	requestedModalities interface{}
	resultInfo interface{}
	source interface{}
	state interface{}
	subject string
	targets interface{}
	tenantId string
	toneInfo interface{}
	transcription interface{}
}

type CallCollectionResponse struct {
	value interface{}
}

type CallEndedEventMessageDetail struct {
	callDuration string
	callEventType interface{}
	callId string
	callParticipants interface{}
	initiator interface{}
}

type CallMediaState struct {
	audio interface{}
}

type CallOptions struct {
	hideBotAfterEscalation interface{}
}

type CallParticipantInfo struct {
	participant interface{}
}

type CallParticipantInfoCollectionResponse struct {
	value interface{}
}

type CallRecordingEventMessageDetail struct {
	callId string
	callRecordingDisplayName string
	callRecordingDuration string
	callRecordingStatus interface{}
	callRecordingUrl string
	initiator interface{}
	meetingOrganizer interface{}
}

type CallRecordsCallRecord struct {
	endDateTime string
	id string
	joinWebUrl string
	lastModifiedDateTime string
	modalities interface{}
	organizer interface{}
	participants interface{}
	sessions interface{}
	startDateTime string
	type string
	version interface{}
}

type CallRecordsCallRecordCollectionResponse struct {
	value interface{}
}

type CallRecordsClientUserAgent struct {
	applicationVersion string
	headerValue string
	platform string
	productFamily string
}

type CallRecordsDeviceInfo struct {
	captureDeviceDriver string
	captureDeviceName string
	captureNotFunctioningEventRatio interface{}
	cpuInsufficentEventRatio interface{}
	deviceClippingEventRatio interface{}
	deviceGlitchEventRatio interface{}
	howlingEventCount interface{}
	initialSignalLevelRootMeanSquare interface{}
	lowSpeechLevelEventRatio interface{}
	lowSpeechToNoiseEventRatio interface{}
	micGlitchRate interface{}
	receivedNoiseLevel interface{}
	receivedSignalLevel interface{}
	renderDeviceDriver string
	renderDeviceName string
	renderMuteEventRatio interface{}
	renderNotFunctioningEventRatio interface{}
	renderZeroVolumeEventRatio interface{}
	sentNoiseLevel interface{}
	sentSignalLevel interface{}
	speakerGlitchRate interface{}
}

type CallRecordsDirectRoutingLogRow struct {
	callEndSubReason interface{}
	callType string
	calleeNumber string
	callerNumber string
	correlationId string
	duration interface{}
	endDateTime string
	failureDateTime string
	finalSipCode interface{}
	finalSipCodePhrase string
	id string
	inviteDateTime string
	mediaBypassEnabled interface{}
	mediaPathLocation string
	signalingLocation string
	startDateTime string
	successfulCall interface{}
	trunkFullyQualifiedDomainName string
	userDisplayName string
	userId string
	userPrincipalName string
}

type CallRecordsEndpoint struct {
	userAgent interface{}
}

type CallRecordsFailureInfo struct {
	reason string
	stage string
}

type CallRecordsMedia struct {
	calleeDevice interface{}
	calleeNetwork interface{}
	callerDevice interface{}
	callerNetwork interface{}
	label string
	streams interface{}
}

type CallRecordsMediaCollectionResponse struct {
	value interface{}
}

type CallRecordsMediaStream struct {
	audioCodec interface{}
	averageAudioDegradation interface{}
	averageAudioNetworkJitter string
	averageBandwidthEstimate interface{}
	averageJitter string
	averagePacketLossRate interface{}
	averageRatioOfConcealedSamples interface{}
	averageReceivedFrameRate interface{}
	averageRoundTripTime string
	averageVideoFrameLossPercentage interface{}
	averageVideoFrameRate interface{}
	averageVideoPacketLossRate interface{}
	endDateTime string
	lowFrameRateRatio interface{}
	lowVideoProcessingCapabilityRatio interface{}
	maxAudioNetworkJitter string
	maxJitter string
	maxPacketLossRate interface{}
	maxRatioOfConcealedSamples interface{}
	maxRoundTripTime string
	packetUtilization interface{}
	postForwardErrorCorrectionPacketLossRate interface{}
	startDateTime string
	streamDirection string
	streamId string
	videoCodec interface{}
	wasMediaBypassed interface{}
}

type CallRecordsMediaStreamCollectionResponse struct {
	value interface{}
}

type CallRecordsNetworkInfo struct {
	bandwidthLowEventRatio interface{}
	basicServiceSetIdentifier string
	connectionType string
	delayEventRatio interface{}
	dnsSuffix string
	ipAddress string
	linkSpeed interface{}
	macAddress string
	networkTransportProtocol string
	port interface{}
	receivedQualityEventRatio interface{}
	reflexiveIPAddress string
	relayIPAddress string
	relayPort interface{}
	sentQualityEventRatio interface{}
	subnet string
	traceRouteHops interface{}
	wifiBand string
	wifiBatteryCharge interface{}
	wifiChannel interface{}
	wifiMicrosoftDriver string
	wifiMicrosoftDriverVersion string
	wifiRadioType string
	wifiSignalStrength interface{}
	wifiVendorDriver string
	wifiVendorDriverVersion string
}

type CallRecordsParticipantEndpoint struct {
	feedback interface{}
	identity interface{}
	userAgent interface{}
}

type CallRecordsPstnCallLogRow struct {
	callDurationSource interface{}
	callId string
	callType string
	calleeNumber string
	callerNumber string
	charge interface{}
	conferenceId string
	connectionCharge interface{}
	currency string
	destinationContext string
	destinationName string
	duration interface{}
	endDateTime string
	id string
	inventoryType string
	licenseCapability string
	operator string
	startDateTime string
	tenantCountryCode string
	usageCountryCode string
	userDisplayName string
	userId string
	userPrincipalName string
}

type CallRecordsSegment struct {
	callee interface{}
	caller interface{}
	endDateTime string
	failureInfo interface{}
	id string
	media interface{}
	startDateTime string
}

type CallRecordsSegmentCollectionResponse struct {
	value interface{}
}

type CallRecordsServiceEndpoint struct {
	userAgent interface{}
}

type CallRecordsServiceUserAgent struct {
	applicationVersion string
	headerValue string
	role string
}

type CallRecordsSession struct {
	callee interface{}
	caller interface{}
	endDateTime string
	failureInfo interface{}
	id string
	modalities interface{}
	segments interface{}
	startDateTime string
}

type CallRecordsSessionCollectionResponse struct {
	value interface{}
}

type CallRecordsTraceRouteHop struct {
	hopCount interface{}
	ipAddress string
	roundTripTime string
}

type CallRecordsTraceRouteHopCollectionResponse struct {
	value interface{}
}

type CallRecordsUserAgent struct {
	applicationVersion string
	headerValue string
}

type CallRecordsUserFeedback struct {
	rating string
	text string
	tokens interface{}
}

type CallRoute struct {
	final interface{}
	original interface{}
	routingType string
}

type CallRouteCollectionResponse struct {
	value interface{}
}

type CallStartedEventMessageDetail struct {
	callEventType interface{}
	callId string
	initiator interface{}
}

type CallTranscriptEventMessageDetail struct {
	callId string
	callTranscriptICalUid string
	meetingOrganizer interface{}
}

type CallTranscriptionInfo struct {
	lastModifiedDateTime string
	state string
}

type CancelMediaProcessingOperation struct {
	clientContext string
	id string
	resultInfo interface{}
	status string
}

type CancelMediaProcessingOperationCollectionResponse struct {
	value interface{}
}

type CasesRoot struct {
	ediscoveryCases interface{}
	id string
}

type CertificateAuthority struct {
	certificate string
	certificateRevocationListUrl string
	deltaCertificateRevocationListUrl string
	isRootAuthority interface{}
	issuer string
	issuerSki string
}

type CertificateAuthorityCollectionResponse struct {
	value interface{}
}

type CertificateBasedAuthConfiguration struct {
	certificateAuthorities interface{}
	id string
}

type CertificateBasedAuthConfigurationCollectionResponse struct {
	value interface{}
}

type Certification struct {
	certificationDetailsUrl string
	certificationExpirationDateTime string
	isCertifiedByMicrosoft interface{}
	isPublisherAttested interface{}
	lastCertificationDateTime string
}

type CertificationControl struct {
	name string
	url string
}

type CertificationControlCollectionResponse struct {
	value interface{}
}

type ChangeNotification struct {
	changeType string
	clientState string
	encryptedContent interface{}
	id string
	lifecycleEvent interface{}
	resource string
	resourceData interface{}
	subscriptionExpirationDateTime string
	subscriptionId string
	tenantId string
}

type ChangeNotificationCollection struct {
	validationTokens interface{}
	value interface{}
}

type ChangeNotificationCollectionResponse struct {
	value interface{}
}

type ChangeNotificationEncryptedContent struct {
	data string
	dataKey string
	dataSignature string
	encryptionCertificateId string
	encryptionCertificateThumbprint string
}

type ChangeTrackedEntity struct {
	createdDateTime string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type Channel struct {
	createdDateTime string
	description string
	displayName string
	email string
	filesFolder interface{}
	id string
	isFavoriteByDefault interface{}
	members interface{}
	membershipType interface{}
	messages interface{}
	sharedWithTeams interface{}
	tabs interface{}
	tenantId string
	webUrl string
}

type ChannelAddedEventMessageDetail struct {
	channelDisplayName string
	channelId string
	initiator interface{}
}

type ChannelCollectionResponse struct {
	value interface{}
}

type ChannelDeletedEventMessageDetail struct {
	channelDisplayName string
	channelId string
	initiator interface{}
}

type ChannelDescriptionUpdatedEventMessageDetail struct {
	channelDescription string
	channelId string
	initiator interface{}
}

type ChannelIdentity struct {
	channelId string
	teamId string
}

type ChannelRenamedEventMessageDetail struct {
	channelDisplayName string
	channelId string
	initiator interface{}
}

type ChannelSetAsFavoriteByDefaultEventMessageDetail struct {
	channelId string
	initiator interface{}
}

type ChannelUnsetAsFavoriteByDefaultEventMessageDetail struct {
	channelId string
	initiator interface{}
}

type Chat struct {
	chatType string
	createdDateTime string
	id string
	installedApps interface{}
	lastUpdatedDateTime string
	members interface{}
	messages interface{}
	onlineMeetingInfo interface{}
	tabs interface{}
	tenantId string
	topic string
	webUrl string
}

type ChatCollectionResponse struct {
	value interface{}
}

type ChatInfo struct {
	messageId string
	replyChainMessageId string
	threadId string
}

type ChatMessage struct {
	attachments interface{}
	body interface{}
	channelIdentity interface{}
	chatId string
	createdDateTime string
	deletedDateTime string
	etag string
	eventDetail interface{}
	from interface{}
	hostedContents interface{}
	id string
	importance string
	lastEditedDateTime string
	lastModifiedDateTime string
	locale string
	mentions interface{}
	messageType string
	policyViolation interface{}
	reactions interface{}
	replies interface{}
	replyToId string
	subject string
	summary string
	webUrl string
}

type ChatMessageAttachment struct {
	content string
	contentType string
	contentUrl string
	id string
	name string
	thumbnailUrl string
}

type ChatMessageAttachmentCollectionResponse struct {
	value interface{}
}

type ChatMessageCollectionResponse struct {
	value interface{}
}

type ChatMessageFromIdentitySet struct {
	application interface{}
	device interface{}
	user interface{}
}

type ChatMessageHostedContent struct {
	contentBytes string
	contentType string
	id string
}

type ChatMessageHostedContentCollectionResponse struct {
	value interface{}
}

type ChatMessageMention struct {
	id interface{}
	mentionText string
	mentioned interface{}
}

type ChatMessageMentionCollectionResponse struct {
	value interface{}
}

type ChatMessageMentionedIdentitySet struct {
	application interface{}
	conversation interface{}
	device interface{}
	user interface{}
}

type ChatMessagePolicyViolation struct {
	dlpAction interface{}
	justificationText string
	policyTip interface{}
	userAction interface{}
	verdictDetails interface{}
}

type ChatMessagePolicyViolationPolicyTip struct {
	complianceUrl string
	generalText string
	matchedConditionDescriptions interface{}
}

type ChatMessageReaction struct {
	createdDateTime string
	reactionType string
	user interface{}
}

type ChatMessageReactionCollectionResponse struct {
	value interface{}
}

type ChatMessageReactionIdentitySet struct {
	application interface{}
	device interface{}
	user interface{}
}

type ChatRenamedEventMessageDetail struct {
	chatDisplayName string
	chatId string
	initiator interface{}
}

type ChecklistItem struct {
	checkedDateTime string
	createdDateTime string
	displayName string
	id string
	isChecked interface{}
}

type ChecklistItemCollectionResponse struct {
	value interface{}
}

type ChoiceColumn struct {
	allowTextEntry interface{}
	choices interface{}
	displayAs string
}

type ClaimsMappingPolicy struct {
	appliesTo interface{}
	definition interface{}
	deletedDateTime string
	description string
	displayName string
	id string
	isOrganizationDefault interface{}
}

type ClaimsMappingPolicyCollectionResponse struct {
	value interface{}
}

type ClientCertificateAuthentication struct {
	certificateList interface{}
}

type CloudAppSecuritySessionControl struct {
	cloudAppSecurityType interface{}
	isEnabled interface{}
}

type CloudAppSecurityState struct {
	destinationServiceIp string
	destinationServiceName string
	riskScore string
}

type CloudAppSecurityStateCollectionResponse struct {
	value interface{}
}

type CloudCommunications struct {
	callRecords interface{}
	calls interface{}
	id string
	onlineMeetings interface{}
	presences interface{}
}

type ColumnDefinition struct {
	boolean interface{}
	calculated interface{}
	choice interface{}
	columnGroup string
	contentApprovalStatus interface{}
	currency interface{}
	dateTime interface{}
	defaultValue interface{}
	description string
	displayName string
	enforceUniqueValues interface{}
	geolocation interface{}
	hidden interface{}
	hyperlinkOrPicture interface{}
	id string
	indexed interface{}
	isDeletable interface{}
	isReorderable interface{}
	isSealed interface{}
	lookup interface{}
	name string
	number interface{}
	personOrGroup interface{}
	propagateChanges interface{}
	readOnly interface{}
	required interface{}
	sourceColumn interface{}
	sourceContentType interface{}
	term interface{}
	text interface{}
	thumbnail interface{}
	type interface{}
	validation interface{}
}

type ColumnDefinitionCollectionResponse struct {
	value interface{}
}

type ColumnLink struct {
	id string
	name string
}

type ColumnLinkCollectionResponse struct {
	value interface{}
}

type ColumnValidation struct {
	defaultLanguage string
	descriptions interface{}
	formula string
}

type CommsNotification struct {
	changeType string
	resourceUrl string
}

type CommsNotificationCollectionResponse struct {
	value interface{}
}

type CommsNotifications struct {
	value interface{}
}

type CommsOperation struct {
	clientContext string
	id string
	resultInfo interface{}
	status string
}

type CommsOperationCollectionResponse struct {
	value interface{}
}

type ComplianceInformation struct {
	certificationControls interface{}
	certificationName string
}

type ComplianceInformationCollectionResponse struct {
	value interface{}
}

type ComplianceManagementPartner struct {
	androidEnrollmentAssignments interface{}
	androidOnboarded interface{}
	displayName string
	id string
	iosEnrollmentAssignments interface{}
	iosOnboarded interface{}
	lastHeartbeatDateTime string
	macOsEnrollmentAssignments interface{}
	macOsOnboarded interface{}
	partnerState string
}

type ComplianceManagementPartnerAssignment struct {
	target interface{}
}

type ComplianceManagementPartnerAssignmentCollectionResponse struct {
	value interface{}
}

type ComplianceManagementPartnerCollectionResponse struct {
	value interface{}
}

type ConditionalAccessApplications struct {
	excludeApplications interface{}
	includeApplications interface{}
	includeAuthenticationContextClassReferences interface{}
	includeUserActions interface{}
}

type ConditionalAccessClientApplications struct {
	excludeServicePrincipals interface{}
	includeServicePrincipals interface{}
}

type ConditionalAccessConditionSet struct {
	applications interface{}
	clientAppTypes interface{}
	clientApplications interface{}
	devices interface{}
	locations interface{}
	platforms interface{}
	servicePrincipalRiskLevels interface{}
	signInRiskLevels interface{}
	userRiskLevels interface{}
	users interface{}
}

type ConditionalAccessDevices struct {
	deviceFilter interface{}
}

type ConditionalAccessFilter struct {
	mode string
	rule string
}

type ConditionalAccessGrantControls struct {
	builtInControls interface{}
	customAuthenticationFactors interface{}
	operator string
	termsOfUse interface{}
}

type ConditionalAccessLocations struct {
	excludeLocations interface{}
	includeLocations interface{}
}

type ConditionalAccessPlatforms struct {
	excludePlatforms interface{}
	includePlatforms interface{}
}

type ConditionalAccessPolicy struct {
	conditions interface{}
	createdDateTime string
	description string
	displayName string
	grantControls interface{}
	id string
	modifiedDateTime string
	sessionControls interface{}
	state string
}

type ConditionalAccessPolicyCollectionResponse struct {
	value interface{}
}

type ConditionalAccessRoot struct {
	id string
	namedLocations interface{}
	policies interface{}
}

type ConditionalAccessSessionControl struct {
	isEnabled interface{}
}

type ConditionalAccessSessionControls struct {
	applicationEnforcedRestrictions interface{}
	cloudAppSecurity interface{}
	disableResilienceDefaults interface{}
	persistentBrowser interface{}
	signInFrequency interface{}
}

type ConditionalAccessUsers struct {
	excludeGroups interface{}
	excludeRoles interface{}
	excludeUsers interface{}
	includeGroups interface{}
	includeRoles interface{}
	includeUsers interface{}
}

type Configuration struct {
	authorizedAppIds interface{}
}

type ConfigurationManagerClientEnabledFeatures struct {
	compliancePolicy interface{}
	deviceConfiguration interface{}
	inventory interface{}
	modernApps interface{}
	resourceAccess interface{}
	windowsUpdateForBusiness interface{}
}

type ConfigurationManagerCollectionAssignmentTarget struct {
	collectionId string
}

type ConnectedOrganization struct {
	createdDateTime string
	description string
	displayName string
	externalSponsors interface{}
	id string
	identitySources interface{}
	internalSponsors interface{}
	modifiedDateTime string
	state interface{}
}

type ConnectedOrganizationCollectionResponse struct {
	value interface{}
}

type ConnectedOrganizationMembers struct {
	connectedOrganizationId string
	description string
}

type ConnectionInfo struct {
	url string
}

type Contact struct {
	assistantName string
	birthday string
	businessAddress interface{}
	businessHomePage string
	businessPhones interface{}
	categories interface{}
	changeKey string
	children interface{}
	companyName string
	createdDateTime string
	department string
	displayName string
	emailAddresses interface{}
	extensions interface{}
	fileAs string
	generation string
	givenName string
	homeAddress interface{}
	homePhones interface{}
	id string
	imAddresses interface{}
	initials string
	jobTitle string
	lastModifiedDateTime string
	manager string
	middleName string
	mobilePhone string
	multiValueExtendedProperties interface{}
	nickName string
	officeLocation string
	otherAddress interface{}
	parentFolderId string
	personalNotes string
	photo interface{}
	profession string
	singleValueExtendedProperties interface{}
	spouseName string
	surname string
	title string
	yomiCompanyName string
	yomiGivenName string
	yomiSurname string
}

type ContactCollectionResponse struct {
	value interface{}
}

type ContactFolder struct {
	childFolders interface{}
	contacts interface{}
	displayName string
	id string
	multiValueExtendedProperties interface{}
	parentFolderId string
	singleValueExtendedProperties interface{}
}

type ContactFolderCollectionResponse struct {
	value interface{}
}

type ContentType struct {
	associatedHubsUrls interface{}
	base interface{}
	baseTypes interface{}
	columnLinks interface{}
	columnPositions interface{}
	columns interface{}
	description string
	documentSet interface{}
	documentTemplate interface{}
	group string
	hidden interface{}
	id string
	inheritedFrom interface{}
	isBuiltIn interface{}
	name string
	order interface{}
	parentId string
	propagateChanges interface{}
	readOnly interface{}
	sealed interface{}
}

type ContentTypeCollectionResponse struct {
	value interface{}
}

type ContentTypeInfo struct {
	id string
	name string
}

type ContentTypeInfoCollectionResponse struct {
	value interface{}
}

type ContentTypeOrder struct {
	default interface{}
	position interface{}
}

type Contract struct {
	contractType string
	customerId string
	defaultDomainName string
	deletedDateTime string
	displayName string
	id string
}

type ContractCollectionResponse struct {
	value interface{}
}

type ControlScore struct {
	controlCategory string
	controlName string
	description string
	score interface{}
}

type ControlScoreCollectionResponse struct {
	value interface{}
}

type Conversation struct {
	hasAttachments interface{}
	id string
	lastDeliveredDateTime string
	preview string
	threads interface{}
	topic string
	uniqueSenders interface{}
}

type ConversationCollectionResponse struct {
	value interface{}
}

type ConversationMember struct {
	displayName string
	id string
	roles interface{}
	visibleHistoryStartDateTime string
}

type ConversationMemberCollectionResponse struct {
	value interface{}
}

type ConversationMemberRoleUpdatedEventMessageDetail struct {
	conversationMemberRoles interface{}
	conversationMemberUser interface{}
	initiator interface{}
}

type ConversationThread struct {
	ccRecipients interface{}
	hasAttachments interface{}
	id string
	isLocked interface{}
	lastDeliveredDateTime string
	posts interface{}
	preview string
	toRecipients interface{}
	topic string
	uniqueSenders interface{}
}

type ConversationThreadCollectionResponse struct {
	value interface{}
}

type ConvertIdResult struct {
	errorDetails interface{}
	sourceId string
	targetId string
}

type CopyNotebookModel struct {
	createdBy string
	createdByIdentity interface{}
	createdTime string
	id string
	isDefault interface{}
	isShared interface{}
	lastModifiedBy string
	lastModifiedByIdentity interface{}
	lastModifiedTime string
	links interface{}
	name string
	sectionGroupsUrl string
	sectionsUrl string
	self string
	userRole interface{}
}

type CountryNamedLocation struct {
	countriesAndRegions interface{}
	countryLookupMethod interface{}
	createdDateTime string
	displayName string
	id string
	includeUnknownCountriesAndRegions interface{}
	modifiedDateTime string
}

type CountryNamedLocationCollectionResponse struct {
	value interface{}
}

type CrossTenantAccessPolicy struct {
	default interface{}
	deletedDateTime string
	description string
	displayName string
	id string
	partners interface{}
}

type CrossTenantAccessPolicyB2BSetting struct {
	applications interface{}
	usersAndGroups interface{}
}

type CrossTenantAccessPolicyCollectionResponse struct {
	value interface{}
}

type CrossTenantAccessPolicyConfigurationDefault struct {
	b2bCollaborationInbound interface{}
	b2bCollaborationOutbound interface{}
	b2bDirectConnectInbound interface{}
	b2bDirectConnectOutbound interface{}
	id string
	inboundTrust interface{}
	isServiceDefault interface{}
}

type CrossTenantAccessPolicyConfigurationPartner struct {
	b2bCollaborationInbound interface{}
	b2bCollaborationOutbound interface{}
	b2bDirectConnectInbound interface{}
	b2bDirectConnectOutbound interface{}
	inboundTrust interface{}
	isServiceProvider interface{}
	tenantId string
}

type CrossTenantAccessPolicyConfigurationPartnerCollectionResponse struct {
	value interface{}
}

type CrossTenantAccessPolicyInboundTrust struct {
	isCompliantDeviceAccepted interface{}
	isHybridAzureADJoinedDeviceAccepted interface{}
	isMfaAccepted interface{}
}

type CrossTenantAccessPolicyTarget struct {
	target string
	targetType interface{}
}

type CrossTenantAccessPolicyTargetCollectionResponse struct {
	value interface{}
}

type CrossTenantAccessPolicyTargetConfiguration struct {
	accessType interface{}
	targets interface{}
}

type CurrencyColumn struct {
	locale string
}

type CustomTimeZone struct {
	bias interface{}
	daylightOffset interface{}
	name string
	standardOffset interface{}
}

type DataPolicyOperation struct {
	completedDateTime string
	id string
	progress interface{}
	status interface{}
	storageLocation string
	submittedDateTime string
	userId string
}

type DataPolicyOperationCollectionResponse struct {
	value interface{}
}

type DataSource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	holdStatus interface{}
	id string
}

type DataSubject struct {
	email string
	firstName string
	lastName string
	residency string
}

type DateTimeColumn struct {
	displayAs string
	format string
}

type DateTimeTimeZone struct {
	dateTime string
	timeZone string
}

type DaylightTimeZoneOffset struct {
	dayOccurrence interface{}
	dayOfWeek interface{}
	daylightBias interface{}
	month interface{}
	time string
	year interface{}
}

type DefaultColumnValue struct {
	formula string
	value string
}

type DefaultManagedAppProtection struct {
	allowedDataStorageLocations interface{}
	allowedInboundDataTransferSources string
	allowedOutboundClipboardSharingLevel string
	allowedOutboundDataTransferDestinations string
	appDataEncryptionType string
	apps interface{}
	contactSyncBlocked interface{}
	createdDateTime string
	customSettings interface{}
	dataBackupBlocked interface{}
	deployedAppCount interface{}
	deploymentSummary interface{}
	description string
	deviceComplianceRequired interface{}
	disableAppEncryptionIfDeviceEncryptionIsEnabled interface{}
	disableAppPinIfDevicePinIsSet interface{}
	displayName string
	encryptAppData interface{}
	faceIdBlocked interface{}
	fingerprintBlocked interface{}
	id string
	lastModifiedDateTime string
	managedBrowser string
	managedBrowserToOpenLinksRequired interface{}
	maximumPinRetries interface{}
	minimumPinLength interface{}
	minimumRequiredAppVersion string
	minimumRequiredOsVersion string
	minimumRequiredPatchVersion string
	minimumRequiredSdkVersion string
	minimumWarningAppVersion string
	minimumWarningOsVersion string
	minimumWarningPatchVersion string
	organizationalCredentialsRequired interface{}
	periodBeforePinReset string
	periodOfflineBeforeAccessCheck string
	periodOfflineBeforeWipeIsEnforced string
	periodOnlineBeforeAccessCheck string
	pinCharacterSet string
	pinRequired interface{}
	printBlocked interface{}
	saveAsBlocked interface{}
	screenCaptureBlocked interface{}
	simplePinBlocked interface{}
	version string
}

type DefaultManagedAppProtectionCollectionResponse struct {
	value interface{}
}

type DefaultUserRolePermissions struct {
	allowedToCreateApps interface{}
	allowedToCreateSecurityGroups interface{}
	allowedToReadOtherUsers interface{}
	permissionGrantPoliciesAssigned interface{}
}

type DefenderDetectedMalwareActions struct {
	highSeverity string
	lowSeverity string
	moderateSeverity string
	severeSeverity string
}

type DelegatedPermissionClassification struct {
	classification interface{}
	id string
	permissionId string
	permissionName string
}

type DelegatedPermissionClassificationCollectionResponse struct {
	value interface{}
}

type DeleteUserFromSharedAppleDeviceActionResult struct {
	actionName string
	actionState string
	lastUpdatedDateTime string
	startDateTime string
	userPrincipalName string
}

type Deleted struct {
	state string
}

type DetectedApp struct {
	deviceCount interface{}
	displayName string
	id string
	managedDevices interface{}
	sizeInByte interface{}
	version string
}

type DetectedAppCollectionResponse struct {
	value interface{}
}

type Device struct {
	accountEnabled interface{}
	alternativeSecurityIds interface{}
	approximateLastSignInDateTime string
	complianceExpirationDateTime string
	deletedDateTime string
	deviceId string
	deviceMetadata string
	deviceVersion interface{}
	displayName string
	extensions interface{}
	id string
	isCompliant interface{}
	isManaged interface{}
	mdmAppId string
	memberOf interface{}
	onPremisesLastSyncDateTime string
	onPremisesSyncEnabled interface{}
	operatingSystem string
	operatingSystemVersion string
	physicalIds interface{}
	profileType string
	registeredOwners interface{}
	registeredUsers interface{}
	systemLabels interface{}
	transitiveMemberOf interface{}
	trustType string
}

type DeviceActionResult struct {
	actionName string
	actionState string
	lastUpdatedDateTime string
	startDateTime string
}

type DeviceActionResultCollectionResponse struct {
	value interface{}
}

type DeviceAndAppManagementRoleAssignment struct {
	description string
	displayName string
	id string
	members interface{}
	resourceScopes interface{}
	roleDefinition interface{}
}

type DeviceAndAppManagementRoleAssignmentCollectionResponse struct {
	value interface{}
}

type DeviceAndAppManagementRoleDefinition struct {
	description string
	displayName string
	id string
	isBuiltIn interface{}
	roleAssignments interface{}
	rolePermissions interface{}
}

type DeviceAndAppManagementRoleDefinitionCollectionResponse struct {
	value interface{}
}

type DeviceAppManagement struct {
	androidManagedAppProtections interface{}
	defaultManagedAppProtections interface{}
	id string
	iosManagedAppProtections interface{}
	isEnabledForMicrosoftStoreForBusiness interface{}
	managedAppPolicies interface{}
	managedAppRegistrations interface{}
	managedAppStatuses interface{}
	managedEBooks interface{}
	mdmWindowsInformationProtectionPolicies interface{}
	microsoftStoreForBusinessLanguage string
	microsoftStoreForBusinessLastCompletedApplicationSyncTime string
	microsoftStoreForBusinessLastSuccessfulSyncDateTime string
	mobileAppCategories interface{}
	mobileAppConfigurations interface{}
	mobileApps interface{}
	targetedManagedAppConfigurations interface{}
	vppTokens interface{}
	windowsInformationProtectionPolicies interface{}
}

type DeviceCategory struct {
	description string
	displayName string
	id string
}

type DeviceCategoryCollectionResponse struct {
	value interface{}
}

type DeviceCollectionResponse struct {
	value interface{}
}

type DeviceComplianceActionItem struct {
	actionType string
	gracePeriodHours interface{}
	id string
	notificationMessageCCList interface{}
	notificationTemplateId string
}

type DeviceComplianceActionItemCollectionResponse struct {
	value interface{}
}

type DeviceComplianceDeviceOverview struct {
	configurationVersion interface{}
	errorCount interface{}
	failedCount interface{}
	id string
	lastUpdateDateTime string
	notApplicableCount interface{}
	pendingCount interface{}
	successCount interface{}
}

type DeviceComplianceDeviceStatus struct {
	complianceGracePeriodExpirationDateTime string
	deviceDisplayName string
	deviceModel string
	id string
	lastReportedDateTime string
	status string
	userName string
	userPrincipalName string
}

type DeviceComplianceDeviceStatusCollectionResponse struct {
	value interface{}
}

type DeviceCompliancePolicy struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	scheduledActionsForRule interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type DeviceCompliancePolicyAssignment struct {
	id string
	target interface{}
}

type DeviceCompliancePolicyAssignmentCollectionResponse struct {
	value interface{}
}

type DeviceCompliancePolicyCollectionResponse struct {
	value interface{}
}

type DeviceCompliancePolicyDeviceStateSummary struct {
	compliantDeviceCount interface{}
	configManagerCount interface{}
	conflictDeviceCount interface{}
	errorDeviceCount interface{}
	id string
	inGracePeriodCount interface{}
	nonCompliantDeviceCount interface{}
	notApplicableDeviceCount interface{}
	remediatedDeviceCount interface{}
	unknownDeviceCount interface{}
}

type DeviceCompliancePolicySettingState struct {
	currentValue string
	errorCode interface{}
	errorDescription string
	instanceDisplayName string
	setting string
	settingName string
	sources interface{}
	state string
	userEmail string
	userId string
	userName string
	userPrincipalName string
}

type DeviceCompliancePolicySettingStateCollectionResponse struct {
	value interface{}
}

type DeviceCompliancePolicySettingStateSummary struct {
	compliantDeviceCount interface{}
	conflictDeviceCount interface{}
	deviceComplianceSettingStates interface{}
	errorDeviceCount interface{}
	id string
	nonCompliantDeviceCount interface{}
	notApplicableDeviceCount interface{}
	platformType string
	remediatedDeviceCount interface{}
	setting string
	settingName string
	unknownDeviceCount interface{}
}

type DeviceCompliancePolicySettingStateSummaryCollectionResponse struct {
	value interface{}
}

type DeviceCompliancePolicyState struct {
	displayName string
	id string
	platformType string
	settingCount interface{}
	settingStates interface{}
	state string
	version interface{}
}

type DeviceCompliancePolicyStateCollectionResponse struct {
	value interface{}
}

type DeviceComplianceScheduledActionForRule struct {
	id string
	ruleName string
	scheduledActionConfigurations interface{}
}

type DeviceComplianceScheduledActionForRuleCollectionResponse struct {
	value interface{}
}

type DeviceComplianceSettingState struct {
	complianceGracePeriodExpirationDateTime string
	deviceId string
	deviceModel string
	deviceName string
	id string
	setting string
	settingName string
	state string
	userEmail string
	userId string
	userName string
	userPrincipalName string
}

type DeviceComplianceSettingStateCollectionResponse struct {
	value interface{}
}

type DeviceComplianceUserOverview struct {
	configurationVersion interface{}
	errorCount interface{}
	failedCount interface{}
	id string
	lastUpdateDateTime string
	notApplicableCount interface{}
	pendingCount interface{}
	successCount interface{}
}

type DeviceComplianceUserStatus struct {
	devicesCount interface{}
	id string
	lastReportedDateTime string
	status string
	userDisplayName string
	userPrincipalName string
}

type DeviceComplianceUserStatusCollectionResponse struct {
	value interface{}
}

type DeviceConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type DeviceConfigurationAssignment struct {
	id string
	target interface{}
}

type DeviceConfigurationAssignmentCollectionResponse struct {
	value interface{}
}

type DeviceConfigurationCollectionResponse struct {
	value interface{}
}

type DeviceConfigurationDeviceOverview struct {
	configurationVersion interface{}
	errorCount interface{}
	failedCount interface{}
	id string
	lastUpdateDateTime string
	notApplicableCount interface{}
	pendingCount interface{}
	successCount interface{}
}

type DeviceConfigurationDeviceStateSummary struct {
	compliantDeviceCount interface{}
	conflictDeviceCount interface{}
	errorDeviceCount interface{}
	id string
	nonCompliantDeviceCount interface{}
	notApplicableDeviceCount interface{}
	remediatedDeviceCount interface{}
	unknownDeviceCount interface{}
}

type DeviceConfigurationDeviceStatus struct {
	complianceGracePeriodExpirationDateTime string
	deviceDisplayName string
	deviceModel string
	id string
	lastReportedDateTime string
	status string
	userName string
	userPrincipalName string
}

type DeviceConfigurationDeviceStatusCollectionResponse struct {
	value interface{}
}

type DeviceConfigurationSettingState struct {
	currentValue string
	errorCode interface{}
	errorDescription string
	instanceDisplayName string
	setting string
	settingName string
	sources interface{}
	state string
	userEmail string
	userId string
	userName string
	userPrincipalName string
}

type DeviceConfigurationSettingStateCollectionResponse struct {
	value interface{}
}

type DeviceConfigurationState struct {
	displayName string
	id string
	platformType string
	settingCount interface{}
	settingStates interface{}
	state string
	version interface{}
}

type DeviceConfigurationStateCollectionResponse struct {
	value interface{}
}

type DeviceConfigurationUserOverview struct {
	configurationVersion interface{}
	errorCount interface{}
	failedCount interface{}
	id string
	lastUpdateDateTime string
	notApplicableCount interface{}
	pendingCount interface{}
	successCount interface{}
}

type DeviceConfigurationUserStatus struct {
	devicesCount interface{}
	id string
	lastReportedDateTime string
	status string
	userDisplayName string
	userPrincipalName string
}

type DeviceConfigurationUserStatusCollectionResponse struct {
	value interface{}
}

type DeviceDetail struct {
	browser string
	deviceId string
	displayName string
	isCompliant interface{}
	isManaged interface{}
	operatingSystem string
	trustType string
}

type DeviceEnrollmentConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	displayName string
	id string
	lastModifiedDateTime string
	priority interface{}
	version interface{}
}

type DeviceEnrollmentConfigurationCollectionResponse struct {
	value interface{}
}

type DeviceEnrollmentLimitConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	displayName string
	id string
	lastModifiedDateTime string
	limit interface{}
	priority interface{}
	version interface{}
}

type DeviceEnrollmentLimitConfigurationCollectionResponse struct {
	value interface{}
}

type DeviceEnrollmentPlatformRestriction struct {
	osMaximumVersion string
	osMinimumVersion string
	personalDeviceEnrollmentBlocked interface{}
	platformBlocked interface{}
}

type DeviceEnrollmentPlatformRestrictionsConfiguration struct {
	androidRestriction interface{}
	assignments interface{}
	createdDateTime string
	description string
	displayName string
	id string
	iosRestriction interface{}
	lastModifiedDateTime string
	macOSRestriction interface{}
	priority interface{}
	version interface{}
	windowsMobileRestriction interface{}
	windowsRestriction interface{}
}

type DeviceEnrollmentPlatformRestrictionsConfigurationCollectionResponse struct {
	value interface{}
}

type DeviceEnrollmentWindowsHelloForBusinessConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	displayName string
	enhancedBiometricsState string
	id string
	lastModifiedDateTime string
	pinExpirationInDays interface{}
	pinLowercaseCharactersUsage string
	pinMaximumLength interface{}
	pinMinimumLength interface{}
	pinPreviousBlockCount interface{}
	pinSpecialCharactersUsage string
	pinUppercaseCharactersUsage string
	priority interface{}
	remotePassportEnabled interface{}
	securityDeviceRequired interface{}
	state string
	unlockWithBiometricsEnabled interface{}
	version interface{}
}

type DeviceEnrollmentWindowsHelloForBusinessConfigurationCollectionResponse struct {
	value interface{}
}

type DeviceExchangeAccessStateSummary struct {
	allowedDeviceCount interface{}
	blockedDeviceCount interface{}
	quarantinedDeviceCount interface{}
	unavailableDeviceCount interface{}
	unknownDeviceCount interface{}
}

type DeviceGeoLocation struct {
	altitude interface{}
	heading interface{}
	horizontalAccuracy interface{}
	lastCollectedDateTime string
	latitude interface{}
	longitude interface{}
	speed interface{}
	verticalAccuracy interface{}
}

type DeviceHealthAttestationState struct {
	attestationIdentityKey string
	bitLockerStatus string
	bootAppSecurityVersion string
	bootDebugging string
	bootManagerSecurityVersion string
	bootManagerVersion string
	bootRevisionListInfo string
	codeIntegrity string
	codeIntegrityCheckVersion string
	codeIntegrityPolicy string
	contentNamespaceUrl string
	contentVersion string
	dataExcutionPolicy string
	deviceHealthAttestationStatus string
	earlyLaunchAntiMalwareDriverProtection string
	healthAttestationSupportedStatus string
	healthStatusMismatchInfo string
	issuedDateTime string
	lastUpdateDateTime string
	operatingSystemKernelDebugging string
	operatingSystemRevListInfo string
	pcr0 string
	pcrHashAlgorithm string
	resetCount interface{}
	restartCount interface{}
	safeMode string
	secureBoot string
	secureBootConfigurationPolicyFingerPrint string
	testSigning string
	tpmVersion string
	virtualSecureMode string
	windowsPE string
}

type DeviceInfo struct {
	captureDeviceDriver string
	captureDeviceName string
	captureNotFunctioningEventRatio interface{}
	cpuInsufficentEventRatio interface{}
	deviceClippingEventRatio interface{}
	deviceGlitchEventRatio interface{}
	howlingEventCount interface{}
	initialSignalLevelRootMeanSquare interface{}
	lowSpeechLevelEventRatio interface{}
	lowSpeechToNoiseEventRatio interface{}
	micGlitchRate interface{}
	receivedNoiseLevel interface{}
	receivedSignalLevel interface{}
	renderDeviceDriver string
	renderDeviceName string
	renderMuteEventRatio interface{}
	renderNotFunctioningEventRatio interface{}
	renderZeroVolumeEventRatio interface{}
	sentNoiseLevel interface{}
	sentSignalLevel interface{}
	speakerGlitchRate interface{}
}

type DeviceInstallState struct {
	deviceId string
	deviceName string
	errorCode string
	id string
	installState string
	lastSyncDateTime string
	osDescription string
	osVersion string
	userName string
}

type DeviceInstallStateCollectionResponse struct {
	value interface{}
}

type DeviceManagement struct {
	applePushNotificationCertificate interface{}
	complianceManagementPartners interface{}
	conditionalAccessSettings interface{}
	detectedApps interface{}
	deviceCategories interface{}
	deviceCompliancePolicies interface{}
	deviceCompliancePolicyDeviceStateSummary interface{}
	deviceCompliancePolicySettingStateSummaries interface{}
	deviceConfigurationDeviceStateSummaries interface{}
	deviceConfigurations interface{}
	deviceEnrollmentConfigurations interface{}
	deviceManagementPartners interface{}
	exchangeConnectors interface{}
	id string
	importedWindowsAutopilotDeviceIdentities interface{}
	intuneAccountId string
	intuneBrand interface{}
	iosUpdateStatuses interface{}
	managedDeviceOverview interface{}
	managedDevices interface{}
	mobileThreatDefenseConnectors interface{}
	notificationMessageTemplates interface{}
	remoteAssistancePartners interface{}
	reports interface{}
	resourceOperations interface{}
	roleAssignments interface{}
	roleDefinitions interface{}
	settings interface{}
	softwareUpdateStatusSummary interface{}
	subscriptionState string
	telecomExpenseManagementPartners interface{}
	termsAndConditions interface{}
	troubleshootingEvents interface{}
	windowsAutopilotDeviceIdentities interface{}
	windowsInformationProtectionAppLearningSummaries interface{}
	windowsInformationProtectionNetworkLearningSummaries interface{}
}

type DeviceManagementExchangeConnector struct {
	connectorServerName string
	exchangeAlias string
	exchangeConnectorType string
	exchangeOrganization string
	id string
	lastSyncDateTime string
	primarySmtpAddress string
	serverName string
	status string
	version string
}

type DeviceManagementExchangeConnectorCollectionResponse struct {
	value interface{}
}

type DeviceManagementExportJob struct {
	expirationDateTime string
	filter string
	format string
	id string
	localizationType string
	reportName string
	requestDateTime string
	select interface{}
	snapshotId string
	status string
	url string
}

type DeviceManagementExportJobCollectionResponse struct {
	value interface{}
}

type DeviceManagementPartner struct {
	displayName string
	id string
	isConfigured interface{}
	lastHeartbeatDateTime string
	partnerAppType string
	partnerState string
	singleTenantAppId string
	whenPartnerDevicesWillBeMarkedAsNonCompliantDateTime string
	whenPartnerDevicesWillBeRemovedDateTime string
}

type DeviceManagementPartnerCollectionResponse struct {
	value interface{}
}

type DeviceManagementReports struct {
	exportJobs interface{}
	id string
}

type DeviceManagementSettings struct {
	deviceComplianceCheckinThresholdDays interface{}
	isScheduledActionEnabled interface{}
	secureByDefault interface{}
}

type DeviceManagementTroubleshootingEvent struct {
	correlationId string
	eventDateTime string
	id string
}

type DeviceManagementTroubleshootingEventCollectionResponse struct {
	value interface{}
}

type DeviceOperatingSystemSummary struct {
	androidCount interface{}
	iosCount interface{}
	macOSCount interface{}
	unknownCount interface{}
	windowsCount interface{}
	windowsMobileCount interface{}
}

type Diagnostic struct {
	message string
	url string
}

type Directory struct {
	administrativeUnits interface{}
	deletedItems interface{}
	federationConfigurations interface{}
	id string
}

type DirectoryAudit struct {
	activityDateTime string
	activityDisplayName string
	additionalDetails interface{}
	category string
	correlationId string
	id string
	initiatedBy interface{}
	loggedByService string
	operationType string
	result interface{}
	resultReason string
	targetResources interface{}
}

type DirectoryAuditCollectionResponse struct {
	value interface{}
}

type DirectoryObject struct {
	deletedDateTime string
	id string
}

type DirectoryObjectCollectionResponse struct {
	value interface{}
}

type DirectoryObjectPartnerReference struct {
	deletedDateTime string
	description string
	displayName string
	externalPartnerTenantId string
	id string
	objectType string
}

type DirectoryObjectPartnerReferenceCollectionResponse struct {
	value interface{}
}

type DirectoryRole struct {
	deletedDateTime string
	description string
	displayName string
	id string
	members interface{}
	roleTemplateId string
	scopedMembers interface{}
}

type DirectoryRoleCollectionResponse struct {
	value interface{}
}

type DirectoryRoleTemplate struct {
	deletedDateTime string
	description string
	displayName string
	id string
}

type DirectoryRoleTemplateCollectionResponse struct {
	value interface{}
}

type DisplayNameLocalization struct {
	displayName string
	languageTag string
}

type DisplayNameLocalizationCollectionResponse struct {
	value interface{}
}

type DocumentSet struct {
	allowedContentTypes interface{}
	defaultContents interface{}
	propagateWelcomePageChanges interface{}
	sharedColumns interface{}
	shouldPrefixNameToFile interface{}
	welcomePageColumns interface{}
	welcomePageUrl string
}

type DocumentSetContent struct {
	contentType interface{}
	fileName string
	folderName string
}

type DocumentSetContentCollectionResponse struct {
	value interface{}
}

type DocumentSetVersion struct {
	comment string
	createdBy interface{}
	createdDateTime string
	fields interface{}
	id string
	items interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	publication interface{}
	shouldCaptureMinorVersion interface{}
}

type DocumentSetVersionCollectionResponse struct {
	value interface{}
}

type DocumentSetVersionItem struct {
	itemId string
	title string
	versionId string
}

type DocumentSetVersionItemCollectionResponse struct {
	value interface{}
}

type Domain struct {
	authenticationType string
	availabilityStatus string
	domainNameReferences interface{}
	federationConfiguration interface{}
	id string
	isAdminManaged interface{}
	isDefault interface{}
	isInitial interface{}
	isRoot interface{}
	isVerified interface{}
	manufacturer string
	model string
	passwordNotificationWindowInDays interface{}
	passwordValidityPeriodInDays interface{}
	serviceConfigurationRecords interface{}
	state interface{}
	supportedServices interface{}
	verificationDnsRecords interface{}
}

type DomainCollectionResponse struct {
	value interface{}
}

type DomainDnsCnameRecord struct {
	canonicalName string
	id string
	isOptional interface{}
	label string
	recordType string
	supportedService string
	ttl interface{}
}

type DomainDnsCnameRecordCollectionResponse struct {
	value interface{}
}

type DomainDnsMxRecord struct {
	id string
	isOptional interface{}
	label string
	mailExchange string
	preference interface{}
	recordType string
	supportedService string
	ttl interface{}
}

type DomainDnsMxRecordCollectionResponse struct {
	value interface{}
}

type DomainDnsRecord struct {
	id string
	isOptional interface{}
	label string
	recordType string
	supportedService string
	ttl interface{}
}

type DomainDnsRecordCollectionResponse struct {
	value interface{}
}

type DomainDnsSrvRecord struct {
	id string
	isOptional interface{}
	label string
	nameTarget string
	port interface{}
	priority interface{}
	protocol string
	recordType string
	service string
	supportedService string
	ttl interface{}
	weight interface{}
}

type DomainDnsSrvRecordCollectionResponse struct {
	value interface{}
}

type DomainDnsTxtRecord struct {
	id string
	isOptional interface{}
	label string
	recordType string
	supportedService string
	text string
	ttl interface{}
}

type DomainDnsTxtRecordCollectionResponse struct {
	value interface{}
}

type DomainDnsUnavailableRecord struct {
	description string
	id string
	isOptional interface{}
	label string
	recordType string
	supportedService string
	ttl interface{}
}

type DomainDnsUnavailableRecordCollectionResponse struct {
	value interface{}
}

type DomainIdentitySource struct {
	displayName string
	domainName string
}

type DomainState struct {
	lastActionDateTime string
	operation string
	status string
}

type Drive struct {
	bundles interface{}
	createdBy interface{}
	createdByUser interface{}
	createdDateTime string
	description string
	driveType string
	eTag string
	following interface{}
	id string
	items interface{}
	lastModifiedBy interface{}
	lastModifiedByUser interface{}
	lastModifiedDateTime string
	list interface{}
	name string
	owner interface{}
	parentReference interface{}
	quota interface{}
	root interface{}
	sharePointIds interface{}
	special interface{}
	system interface{}
	webUrl string
}

type DriveCollectionResponse struct {
	value interface{}
}

type DriveItem struct {
	analytics interface{}
	audio interface{}
	bundle interface{}
	cTag string
	children interface{}
	content string
	createdBy interface{}
	createdByUser interface{}
	createdDateTime string
	deleted interface{}
	description string
	eTag string
	file interface{}
	fileSystemInfo interface{}
	folder interface{}
	id string
	image interface{}
	lastModifiedBy interface{}
	lastModifiedByUser interface{}
	lastModifiedDateTime string
	listItem interface{}
	location interface{}
	malware interface{}
	name string
	package interface{}
	parentReference interface{}
	pendingOperations interface{}
	permissions interface{}
	photo interface{}
	publication interface{}
	remoteItem interface{}
	root interface{}
	searchResult interface{}
	shared interface{}
	sharepointIds interface{}
	size interface{}
	specialFolder interface{}
	subscriptions interface{}
	thumbnails interface{}
	versions interface{}
	video interface{}
	webDavUrl string
	webUrl string
	workbook interface{}
}

type DriveItemCollectionResponse struct {
	value interface{}
}

type DriveItemUploadableProperties struct {
	description string
	fileSize interface{}
	fileSystemInfo interface{}
	name string
}

type DriveItemVersion struct {
	content string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	publication interface{}
	size interface{}
}

type DriveItemVersionCollectionResponse struct {
	value interface{}
}

type DriveRecipient struct {
	alias string
	email string
	objectId string
}

type EBookInstallSummary struct {
	failedDeviceCount interface{}
	failedUserCount interface{}
	id string
	installedDeviceCount interface{}
	installedUserCount interface{}
	notInstalledDeviceCount interface{}
	notInstalledUserCount interface{}
}

type EdgeSearchEngine struct {
	edgeSearchEngineType string
}

type EdgeSearchEngineCustom struct {
	edgeSearchEngineOpenSearchXmlUrl string
}

type EdiscoveryAddToReviewSetOperation struct {
	action interface{}
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	id string
	percentProgress interface{}
	resultInfo interface{}
	reviewSet interface{}
	search interface{}
	status interface{}
}

type EdiscoveryCaseSettings struct {
	id string
	ocr interface{}
	redundancyDetection interface{}
	topicModeling interface{}
}

type EdiscoveryEstimateOperation struct {
	action interface{}
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	id string
	indexedItemCount interface{}
	indexedItemsSize interface{}
	mailboxCount interface{}
	percentProgress interface{}
	resultInfo interface{}
	search interface{}
	siteCount interface{}
	status interface{}
	unindexedItemCount interface{}
	unindexedItemsSize interface{}
}

type EdiscoveryIndexOperation struct {
	action interface{}
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	id string
	percentProgress interface{}
	resultInfo interface{}
	status interface{}
}

type EdiscoveryReviewSet struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	id string
	queries interface{}
}

type EdiscoveryReviewTag struct {
	childSelectability interface{}
	childTags interface{}
	createdBy interface{}
	description string
	displayName string
	id string
	lastModifiedDateTime string
	parent interface{}
}

type EdiscoverySearch struct {
	addToReviewSetOperation interface{}
	additionalSources interface{}
	contentQuery string
	createdBy interface{}
	createdDateTime string
	custodianSources interface{}
	dataSourceScopes interface{}
	description string
	displayName string
	id string
	lastEstimateStatisticsOperation interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	noncustodialSources interface{}
}

type EditionUpgradeConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	license string
	licenseType string
	productKey string
	targetEdition string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type EditionUpgradeConfigurationCollectionResponse struct {
	value interface{}
}

type EducationAssignment struct {
	addToCalendarAction interface{}
	addedStudentAction interface{}
	allowLateSubmissions interface{}
	allowStudentsToAddResourcesToSubmission interface{}
	assignDateTime string
	assignTo interface{}
	assignedDateTime string
	categories interface{}
	classId string
	closeDateTime string
	createdBy interface{}
	createdDateTime string
	displayName string
	dueDateTime string
	grading interface{}
	id string
	instructions interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	notificationChannelUrl string
	resources interface{}
	resourcesFolderUrl string
	rubric interface{}
	status interface{}
	submissions interface{}
	webUrl string
}

type EducationAssignmentCollectionResponse struct {
	value interface{}
}

type EducationAssignmentDefaults struct {
	addToCalendarAction interface{}
	addedStudentAction interface{}
	dueTime string
	id string
	notificationChannelUrl string
}

type EducationAssignmentGrade struct {
	gradedBy interface{}
	gradedDateTime string
}

type EducationAssignmentIndividualRecipient struct {
	recipients interface{}
}

type EducationAssignmentPointsGrade struct {
	gradedBy interface{}
	gradedDateTime string
	points interface{}
}

type EducationAssignmentPointsGradeType struct {
	maxPoints interface{}
}

type EducationAssignmentResource struct {
	distributeForStudentWork interface{}
	id string
	resource interface{}
}

type EducationAssignmentResourceCollectionResponse struct {
	value interface{}
}

type EducationAssignmentSettings struct {
	id string
	submissionAnimationDisabled interface{}
}

type EducationCategory struct {
	displayName string
	id string
}

type EducationCategoryCollectionResponse struct {
	value interface{}
}

type EducationClass struct {
	assignmentCategories interface{}
	assignmentDefaults interface{}
	assignmentSettings interface{}
	assignments interface{}
	classCode string
	course interface{}
	createdBy interface{}
	description string
	displayName string
	externalId string
	externalName string
	externalSource interface{}
	externalSourceDetail string
	grade string
	group interface{}
	id string
	mailNickname string
	members interface{}
	schools interface{}
	teachers interface{}
	term interface{}
}

type EducationClassCollectionResponse struct {
	value interface{}
}

type EducationCourse struct {
	courseNumber string
	description string
	displayName string
	externalId string
	subject string
}

type EducationExcelResource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	fileUrl string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type EducationExternalResource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	webUrl string
}

type EducationFeedback struct {
	feedbackBy interface{}
	feedbackDateTime string
	text interface{}
}

type EducationFeedbackOutcome struct {
	feedback interface{}
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	publishedFeedback interface{}
}

type EducationFeedbackOutcomeCollectionResponse struct {
	value interface{}
}

type EducationFileResource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	fileUrl string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type EducationItemBody struct {
	content string
	contentType interface{}
}

type EducationLinkResource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	link string
}

type EducationMediaResource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	fileUrl string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type EducationOnPremisesInfo struct {
	immutableId string
}

type EducationOrganization struct {
	description string
	displayName string
	externalSource interface{}
	externalSourceDetail string
	id string
}

type EducationOutcome struct {
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type EducationOutcomeCollectionResponse struct {
	value interface{}
}

type EducationPointsOutcome struct {
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	points interface{}
	publishedPoints interface{}
}

type EducationPointsOutcomeCollectionResponse struct {
	value interface{}
}

type EducationPowerPointResource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	fileUrl string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type EducationResource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type EducationRoot struct {
	classes interface{}
	me interface{}
	schools interface{}
	users interface{}
}

type EducationRubric struct {
	createdBy interface{}
	createdDateTime string
	description interface{}
	displayName string
	grading interface{}
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	levels interface{}
	qualities interface{}
}

type EducationRubricCollectionResponse struct {
	value interface{}
}

type EducationRubricOutcome struct {
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	publishedRubricQualityFeedback interface{}
	publishedRubricQualitySelectedLevels interface{}
	rubricQualityFeedback interface{}
	rubricQualitySelectedLevels interface{}
}

type EducationRubricOutcomeCollectionResponse struct {
	value interface{}
}

type EducationSchool struct {
	address interface{}
	administrativeUnit interface{}
	classes interface{}
	createdBy interface{}
	description string
	displayName string
	externalId string
	externalPrincipalId string
	externalSource interface{}
	externalSourceDetail string
	fax string
	highestGrade string
	id string
	lowestGrade string
	phone string
	principalEmail string
	principalName string
	schoolNumber string
	users interface{}
}

type EducationSchoolCollectionResponse struct {
	value interface{}
}

type EducationStudent struct {
	birthDate string
	externalId string
	gender interface{}
	grade string
	graduationYear string
	studentNumber string
}

type EducationSubmission struct {
	id string
	outcomes interface{}
	reassignedBy interface{}
	reassignedDateTime string
	recipient interface{}
	resources interface{}
	resourcesFolderUrl string
	returnedBy interface{}
	returnedDateTime string
	status interface{}
	submittedBy interface{}
	submittedDateTime string
	submittedResources interface{}
	unsubmittedBy interface{}
	unsubmittedDateTime string
}

type EducationSubmissionCollectionResponse struct {
	value interface{}
}

type EducationSubmissionIndividualRecipient struct {
	userId string
}

type EducationSubmissionResource struct {
	assignmentResourceUrl string
	id string
	resource interface{}
}

type EducationSubmissionResourceCollectionResponse struct {
	value interface{}
}

type EducationTeacher struct {
	externalId string
	teacherNumber string
}

type EducationTeamsAppResource struct {
	appIconWebUrl string
	appId string
	createdBy interface{}
	createdDateTime string
	displayName string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	teamsEmbeddedContentUrl string
	webUrl string
}

type EducationTerm struct {
	displayName string
	endDate string
	externalId string
	startDate string
}

type EducationUser struct {
	accountEnabled interface{}
	assignedLicenses interface{}
	assignedPlans interface{}
	assignments interface{}
	businessPhones interface{}
	classes interface{}
	createdBy interface{}
	department string
	displayName string
	externalSource interface{}
	externalSourceDetail string
	givenName string
	id string
	mail string
	mailNickname string
	mailingAddress interface{}
	middleName string
	mobilePhone string
	officeLocation string
	onPremisesInfo interface{}
	passwordPolicies string
	passwordProfile interface{}
	preferredLanguage string
	primaryRole string
	provisionedPlans interface{}
	refreshTokensValidFromDateTime string
	relatedContacts interface{}
	residenceAddress interface{}
	rubrics interface{}
	schools interface{}
	showInAddressList interface{}
	student interface{}
	surname string
	taughtClasses interface{}
	teacher interface{}
	usageLocation string
	user interface{}
	userPrincipalName string
	userType string
}

type EducationUserCollectionResponse struct {
	value interface{}
}

type EducationWordResource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	fileUrl string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type EmailAddress struct {
	address string
	name string
}

type EmailAddressCollectionResponse struct {
	value interface{}
}

type EmailAuthenticationMethod struct {
	emailAddress string
	id string
}

type EmailAuthenticationMethodCollectionResponse struct {
	value interface{}
}

type EmailAuthenticationMethodConfiguration struct {
	allowExternalIdToUseEmailOtp interface{}
	id string
	includeTargets interface{}
	state interface{}
}

type EmailAuthenticationMethodConfigurationCollectionResponse struct {
	value interface{}
}

type EmailFileAssessmentRequest struct {
	category string
	contentData string
	contentType interface{}
	createdBy interface{}
	createdDateTime string
	destinationRoutingReason interface{}
	expectedAssessment string
	id string
	recipientEmail string
	requestSource interface{}
	results interface{}
	status interface{}
}

type EmailFileAssessmentRequestCollectionResponse struct {
	value interface{}
}

type EmployeeOrgData struct {
	costCenter string
	division string
}

type Endpoint struct {
	userAgent interface{}
}

type EndpointCollectionResponse struct {
	value interface{}
}

type EnrollmentConfigurationAssignment struct {
	id string
	target interface{}
}

type EnrollmentConfigurationAssignmentCollectionResponse struct {
	value interface{}
}

type EnrollmentTroubleshootingEvent struct {
	correlationId string
	deviceId string
	enrollmentType string
	eventDateTime string
	failureCategory string
	failureReason string
	id string
	managedDeviceIdentifier string
	operatingSystem string
	osVersion string
	userId string
}

type EnrollmentTroubleshootingEventCollectionResponse struct {
	value interface{}
}

type EntitlementManagement struct {
	accessPackageAssignmentApprovals interface{}
	accessPackages interface{}
	assignmentPolicies interface{}
	assignmentRequests interface{}
	assignments interface{}
	catalogs interface{}
	connectedOrganizations interface{}
	id string
	settings interface{}
}

type EntitlementManagementSchedule struct {
	expiration interface{}
	recurrence interface{}
	startDateTime string
}

type EntitlementManagementSettings struct {
	durationUntilExternalUserDeletedAfterBlocked string
	externalUserLifecycleAction interface{}
	id string
}

type Entity struct {
	id string
}

type Event struct {
	allowNewTimeProposals interface{}
	attachments interface{}
	attendees interface{}
	body interface{}
	bodyPreview string
	calendar interface{}
	categories interface{}
	changeKey string
	createdDateTime string
	end interface{}
	extensions interface{}
	hasAttachments interface{}
	hideAttendees interface{}
	iCalUId string
	id string
	importance interface{}
	instances interface{}
	isAllDay interface{}
	isCancelled interface{}
	isDraft interface{}
	isOnlineMeeting interface{}
	isOrganizer interface{}
	isReminderOn interface{}
	lastModifiedDateTime string
	location interface{}
	locations interface{}
	multiValueExtendedProperties interface{}
	onlineMeeting interface{}
	onlineMeetingProvider interface{}
	onlineMeetingUrl string
	organizer interface{}
	originalEndTimeZone string
	originalStart string
	originalStartTimeZone string
	recurrence interface{}
	reminderMinutesBeforeStart interface{}
	responseRequested interface{}
	responseStatus interface{}
	sensitivity interface{}
	seriesMasterId string
	showAs interface{}
	singleValueExtendedProperties interface{}
	start interface{}
	subject string
	transactionId string
	type interface{}
	webLink string
}

type EventCollectionResponse struct {
	value interface{}
}

type EventMessage struct {
	attachments interface{}
	bccRecipients interface{}
	body interface{}
	bodyPreview string
	categories interface{}
	ccRecipients interface{}
	changeKey string
	conversationId string
	conversationIndex string
	createdDateTime string
	endDateTime interface{}
	event interface{}
	extensions interface{}
	flag interface{}
	from interface{}
	hasAttachments interface{}
	id string
	importance interface{}
	inferenceClassification interface{}
	internetMessageHeaders interface{}
	internetMessageId string
	isAllDay interface{}
	isDelegated interface{}
	isDeliveryReceiptRequested interface{}
	isDraft interface{}
	isOutOfDate interface{}
	isRead interface{}
	isReadReceiptRequested interface{}
	lastModifiedDateTime string
	location interface{}
	meetingMessageType interface{}
	multiValueExtendedProperties interface{}
	parentFolderId string
	receivedDateTime string
	recurrence interface{}
	replyTo interface{}
	sender interface{}
	sentDateTime string
	singleValueExtendedProperties interface{}
	startDateTime interface{}
	subject string
	toRecipients interface{}
	type interface{}
	uniqueBody interface{}
	webLink string
}

type EventMessageCollectionResponse struct {
	value interface{}
}

type EventMessageRequest struct {
	allowNewTimeProposals interface{}
	attachments interface{}
	bccRecipients interface{}
	body interface{}
	bodyPreview string
	categories interface{}
	ccRecipients interface{}
	changeKey string
	conversationId string
	conversationIndex string
	createdDateTime string
	endDateTime interface{}
	event interface{}
	extensions interface{}
	flag interface{}
	from interface{}
	hasAttachments interface{}
	id string
	importance interface{}
	inferenceClassification interface{}
	internetMessageHeaders interface{}
	internetMessageId string
	isAllDay interface{}
	isDelegated interface{}
	isDeliveryReceiptRequested interface{}
	isDraft interface{}
	isOutOfDate interface{}
	isRead interface{}
	isReadReceiptRequested interface{}
	lastModifiedDateTime string
	location interface{}
	meetingMessageType interface{}
	meetingRequestType interface{}
	multiValueExtendedProperties interface{}
	parentFolderId string
	previousEndDateTime interface{}
	previousLocation interface{}
	previousStartDateTime interface{}
	receivedDateTime string
	recurrence interface{}
	replyTo interface{}
	responseRequested interface{}
	sender interface{}
	sentDateTime string
	singleValueExtendedProperties interface{}
	startDateTime interface{}
	subject string
	toRecipients interface{}
	type interface{}
	uniqueBody interface{}
	webLink string
}

type EventMessageRequestCollectionResponse struct {
	value interface{}
}

type EventMessageResponse struct {
	attachments interface{}
	bccRecipients interface{}
	body interface{}
	bodyPreview string
	categories interface{}
	ccRecipients interface{}
	changeKey string
	conversationId string
	conversationIndex string
	createdDateTime string
	endDateTime interface{}
	event interface{}
	extensions interface{}
	flag interface{}
	from interface{}
	hasAttachments interface{}
	id string
	importance interface{}
	inferenceClassification interface{}
	internetMessageHeaders interface{}
	internetMessageId string
	isAllDay interface{}
	isDelegated interface{}
	isDeliveryReceiptRequested interface{}
	isDraft interface{}
	isOutOfDate interface{}
	isRead interface{}
	isReadReceiptRequested interface{}
	lastModifiedDateTime string
	location interface{}
	meetingMessageType interface{}
	multiValueExtendedProperties interface{}
	parentFolderId string
	proposedNewTime interface{}
	receivedDateTime string
	recurrence interface{}
	replyTo interface{}
	responseType interface{}
	sender interface{}
	sentDateTime string
	singleValueExtendedProperties interface{}
	startDateTime interface{}
	subject string
	toRecipients interface{}
	type interface{}
	uniqueBody interface{}
	webLink string
}

type EventMessageResponseCollectionResponse struct {
	value interface{}
}

type ExcludeTarget struct {
	id string
	targetType string
}

type ExcludeTargetCollectionResponse struct {
	value interface{}
}

type ExclusionGroupAssignmentTarget struct {
	groupId string
}

type ExpirationPattern struct {
	duration string
	endDateTime string
	type interface{}
}

type Extension struct {
	id string
}

type ExtensionCollectionResponse struct {
	value interface{}
}

type ExtensionProperty struct {
	appDisplayName string
	dataType string
	deletedDateTime string
	id string
	isSyncedFromOnPremises interface{}
	name string
	targetObjects interface{}
}

type ExtensionPropertyCollectionResponse struct {
	value interface{}
}

type ExtensionSchemaProperty struct {
	name string
	type string
}

type ExtensionSchemaPropertyCollectionResponse struct {
	value interface{}
}

type ExternalConnectorsAcl struct {
	accessType string
	type string
	value string
}

type ExternalConnectorsAclCollectionResponse struct {
	value interface{}
}

type ExternalConnectorsConfiguration struct {
	authorizedAppIds interface{}
}

type ExternalConnectorsConnectionOperation struct {
	error interface{}
	id string
	status interface{}
}

type ExternalConnectorsConnectionOperationCollectionResponse struct {
	value interface{}
}

type ExternalConnectorsExternal struct {
	connections interface{}
}

type ExternalConnectorsExternalConnection struct {
	configuration interface{}
	description string
	groups interface{}
	id string
	items interface{}
	name string
	operations interface{}
	schema interface{}
	state interface{}
}

type ExternalConnectorsExternalConnectionCollectionResponse struct {
	value interface{}
}

type ExternalConnectorsExternalGroup struct {
	description string
	displayName string
	id string
	members interface{}
}

type ExternalConnectorsExternalGroupCollectionResponse struct {
	value interface{}
}

type ExternalConnectorsExternalItem struct {
	acl interface{}
	content interface{}
	id string
	properties interface{}
}

type ExternalConnectorsExternalItemCollectionResponse struct {
	value interface{}
}

type ExternalConnectorsExternalItemContent struct {
	type string
	value string
}

type ExternalConnectorsIdentity struct {
	id string
	type interface{}
}

type ExternalConnectorsIdentityCollectionResponse struct {
	value interface{}
}

type ExternalConnectorsProperty struct {
	aliases interface{}
	isQueryable interface{}
	isRefinable interface{}
	isRetrievable interface{}
	isSearchable interface{}
	labels interface{}
	name string
	type string
}

type ExternalConnectorsPropertyCollectionResponse struct {
	value interface{}
}

type ExternalConnectorsSchema struct {
	baseType string
	id string
	properties interface{}
}

type ExternalDomainFederation struct {
	displayName string
	domainName string
	issuerUri string
}

type ExternalDomainName struct {
	id string
}

type ExternalDomainNameCollectionResponse struct {
	value interface{}
}

type ExternalItemContent struct {
	type string
	value string
}

type ExternalLink struct {
	href string
}

type FailureInfo struct {
	reason string
	stage string
}

type FeatureRolloutPolicy struct {
	appliesTo interface{}
	description string
	displayName string
	feature string
	id string
	isAppliedToOrganization interface{}
	isEnabled interface{}
}

type FeatureRolloutPolicyCollectionResponse struct {
	value interface{}
}

type FederatedIdentityCredential struct {
	audiences interface{}
	description string
	id string
	issuer string
	name string
	subject string
}

type FederatedIdentityCredentialCollectionResponse struct {
	value interface{}
}

type Fido2AuthenticationMethod struct {
	aaGuid string
	attestationCertificates interface{}
	attestationLevel interface{}
	createdDateTime string
	displayName string
	id string
	model string
}

type Fido2AuthenticationMethodCollectionResponse struct {
	value interface{}
}

type Fido2AuthenticationMethodConfiguration struct {
	id string
	includeTargets interface{}
	isAttestationEnforced interface{}
	isSelfServiceRegistrationAllowed interface{}
	keyRestrictions interface{}
	state interface{}
}

type Fido2AuthenticationMethodConfigurationCollectionResponse struct {
	value interface{}
}

type Fido2KeyRestrictions struct {
	aaGuids interface{}
	enforcementType interface{}
	isEnforced interface{}
}

type FieldValueSet struct {
	id string
}

type File struct {
	hashes interface{}
	mimeType string
	processingMetadata interface{}
}

type FileAssessmentRequest struct {
	category string
	contentData string
	contentType interface{}
	createdBy interface{}
	createdDateTime string
	expectedAssessment string
	fileName string
	id string
	requestSource interface{}
	results interface{}
	status interface{}
}

type FileAssessmentRequestCollectionResponse struct {
	value interface{}
}

type FileAttachment struct {
	contentBytes string
	contentId string
	contentLocation string
	contentType string
	id string
	isInline interface{}
	lastModifiedDateTime string
	name string
	size interface{}
}

type FileAttachmentCollectionResponse struct {
	value interface{}
}

type FileEncryptionInfo struct {
	encryptionKey string
	fileDigest string
	fileDigestAlgorithm string
	initializationVector string
	mac string
	macKey string
	profileIdentifier string
}

type FileHash struct {
	hashType interface{}
	hashValue string
}

type FileSecurityState struct {
	fileHash interface{}
	name string
	path string
	riskScore string
}

type FileSecurityStateCollectionResponse struct {
	value interface{}
}

type FileSystemInfo struct {
	createdDateTime string
	lastAccessedDateTime string
	lastModifiedDateTime string
}

type Folder struct {
	childCount interface{}
	view interface{}
}

type FolderView struct {
	sortBy string
	sortOrder string
	viewType string
}

type FollowupFlag struct {
	completedDateTime interface{}
	dueDateTime interface{}
	flagStatus interface{}
	startDateTime interface{}
}

type FreeBusyError struct {
	message string
	responseCode string
}

type GenericError struct {
	code string
	message string
}

type GeoCoordinates struct {
	altitude interface{}
	latitude interface{}
	longitude interface{}
}

type Group struct {
	acceptedSenders interface{}
	allowExternalSenders interface{}
	appRoleAssignments interface{}
	assignedLabels interface{}
	assignedLicenses interface{}
	autoSubscribeNewMembers interface{}
	calendar interface{}
	calendarView interface{}
	classification string
	conversations interface{}
	createdDateTime string
	createdOnBehalfOf interface{}
	deletedDateTime string
	description string
	displayName string
	drive interface{}
	drives interface{}
	events interface{}
	expirationDateTime string
	extensions interface{}
	groupLifecyclePolicies interface{}
	groupTypes interface{}
	hasMembersWithLicenseErrors interface{}
	hideFromAddressLists interface{}
	hideFromOutlookClients interface{}
	id string
	isArchived interface{}
	isAssignableToRole interface{}
	isSubscribedByMail interface{}
	licenseProcessingState interface{}
	mail string
	mailEnabled interface{}
	mailNickname string
	memberOf interface{}
	members interface{}
	membersWithLicenseErrors interface{}
	membershipRule string
	membershipRuleProcessingState string
	onPremisesDomainName string
	onPremisesLastSyncDateTime string
	onPremisesNetBiosName string
	onPremisesProvisioningErrors interface{}
	onPremisesSamAccountName string
	onPremisesSecurityIdentifier string
	onPremisesSyncEnabled interface{}
	onenote interface{}
	owners interface{}
	permissionGrants interface{}
	photo interface{}
	photos interface{}
	planner interface{}
	preferredDataLocation string
	preferredLanguage string
	proxyAddresses interface{}
	rejectedSenders interface{}
	renewedDateTime string
	securityEnabled interface{}
	securityIdentifier string
	settings interface{}
	sites interface{}
	team interface{}
	theme string
	threads interface{}
	transitiveMemberOf interface{}
	transitiveMembers interface{}
	unseenCount interface{}
	visibility string
}

type GroupAssignmentTarget struct {
	groupId string
}

type GroupCollectionResponse struct {
	value interface{}
}

type GroupLifecyclePolicy struct {
	alternateNotificationEmails string
	groupLifetimeInDays interface{}
	id string
	managedGroupTypes string
}

type GroupLifecyclePolicyCollectionResponse struct {
	value interface{}
}

type GroupMembers struct {
	description string
	groupId string
}

type GroupSetting struct {
	displayName string
	id string
	templateId string
	values interface{}
}

type GroupSettingCollectionResponse struct {
	value interface{}
}

type GroupSettingTemplate struct {
	deletedDateTime string
	description string
	displayName string
	id string
	values interface{}
}

type GroupSettingTemplateCollectionResponse struct {
	value interface{}
}

type Hashes struct {
	crc32Hash string
	quickXorHash string
	sha1Hash string
	sha256Hash string
}

type HomeRealmDiscoveryPolicy struct {
	appliesTo interface{}
	definition interface{}
	deletedDateTime string
	description string
	displayName string
	id string
	isOrganizationDefault interface{}
}

type HomeRealmDiscoveryPolicyCollectionResponse struct {
	value interface{}
}

type HostSecurityState struct {
	fqdn string
	isAzureAdJoined interface{}
	isAzureAdRegistered interface{}
	isHybridAzureDomainJoined interface{}
	netBiosName string
	os string
	privateIpAddress string
	publicIpAddress string
	riskScore string
}

type HostSecurityStateCollectionResponse struct {
	value interface{}
}

type HyperlinkOrPictureColumn struct {
	isPicture interface{}
}

type IPv4CidrRange struct {
	cidrAddress string
}

type IPv4Range struct {
	lowerAddress string
	upperAddress string
}

type IPv6CidrRange struct {
	cidrAddress string
}

type IPv6Range struct {
	lowerAddress string
	upperAddress string
}

type Identity struct {
	displayName string
	id string
}

type IdentityApiConnector struct {
	authenticationConfiguration interface{}
	displayName string
	id string
	targetUrl string
}

type IdentityApiConnectorCollectionResponse struct {
	value interface{}
}

type IdentityBuiltInUserFlowAttribute struct {
	dataType string
	description string
	displayName string
	id string
	userFlowAttributeType string
}

type IdentityBuiltInUserFlowAttributeCollectionResponse struct {
	value interface{}
}

type IdentityContainer struct {
	apiConnectors interface{}
	b2xUserFlows interface{}
	conditionalAccess interface{}
	id string
	identityProviders interface{}
	userFlowAttributes interface{}
}

type IdentityCustomUserFlowAttribute struct {
	dataType string
	description string
	displayName string
	id string
	userFlowAttributeType string
}

type IdentityCustomUserFlowAttributeCollectionResponse struct {
	value interface{}
}

type IdentityGovernance struct {
	accessReviews interface{}
	appConsent interface{}
	entitlementManagement interface{}
	termsOfUse interface{}
}

type IdentityProtectionRoot struct {
	riskDetections interface{}
	riskyUsers interface{}
}

type IdentityProvider struct {
	clientId string
	clientSecret string
	id string
	name string
	type string
}

type IdentityProviderBase struct {
	displayName string
	id string
}

type IdentityProviderBaseCollectionResponse struct {
	value interface{}
}

type IdentityProviderCollectionResponse struct {
	value interface{}
}

type IdentitySecurityDefaultsEnforcementPolicy struct {
	deletedDateTime string
	description string
	displayName string
	id string
	isEnabled interface{}
}

type IdentitySecurityDefaultsEnforcementPolicyCollectionResponse struct {
	value interface{}
}

type IdentitySet struct {
	application interface{}
	device interface{}
	user interface{}
}

type IdentitySetCollectionResponse struct {
	value interface{}
}

type IdentitySourceCollectionResponse struct {
	value interface{}
}

type IdentityUserFlow struct {
	id string
	userFlowType string
	userFlowTypeVersion interface{}
}

type IdentityUserFlowAttribute struct {
	dataType string
	description string
	displayName string
	id string
	userFlowAttributeType string
}

type IdentityUserFlowAttributeAssignment struct {
	displayName string
	id string
	isOptional interface{}
	requiresVerification interface{}
	userAttribute interface{}
	userAttributeValues interface{}
	userInputType string
}

type IdentityUserFlowAttributeAssignmentCollectionResponse struct {
	value interface{}
}

type IdentityUserFlowAttributeCollectionResponse struct {
	value interface{}
}

type Image struct {
	height interface{}
	width interface{}
}

type ImageInfo struct {
	addImageQuery interface{}
	alternateText string
	alternativeText string
	iconUrl string
}

type ImplicitGrantSettings struct {
	enableAccessTokenIssuance interface{}
	enableIdTokenIssuance interface{}
}

type ImportedWindowsAutopilotDeviceIdentity struct {
	assignedUserPrincipalName string
	groupTag string
	hardwareIdentifier string
	id string
	importId string
	productKey string
	serialNumber string
	state interface{}
}

type ImportedWindowsAutopilotDeviceIdentityCollectionResponse struct {
	value interface{}
}

type ImportedWindowsAutopilotDeviceIdentityState struct {
	deviceErrorCode interface{}
	deviceErrorName string
	deviceImportStatus string
	deviceRegistrationId string
}

type ImportedWindowsAutopilotDeviceIdentityUpload struct {
	createdDateTimeUtc string
	deviceIdentities interface{}
	id string
	status string
}

type IncomingCallOptions struct {
	hideBotAfterEscalation interface{}
}

type IncomingContext struct {
	observedParticipantId string
	onBehalfOf interface{}
	sourceParticipantId string
	transferor interface{}
}

type IncompleteData struct {
	missingDataBeforeDateTime string
	wasThrottled interface{}
}

type InferenceClassification struct {
	id string
	overrides interface{}
}

type InferenceClassificationOverride struct {
	classifyAs interface{}
	id string
	senderEmailAddress interface{}
}

type InferenceClassificationOverrideCollectionResponse struct {
	value interface{}
}

type InformationProtection struct {
	bitlocker interface{}
	id string
	threatAssessmentRequests interface{}
}

type InformationalUrl struct {
	logoUrl string
	marketingUrl string
	privacyStatementUrl string
	supportUrl string
	termsOfServiceUrl string
}

type Initiator struct {
	displayName string
	id string
	initiatorType interface{}
}

type InnerError struct {
	Date string
	client-request-id string
	request-id string
}

type InsightIdentity struct {
	address string
	displayName string
	id string
}

type InstanceResourceAccess struct {
	permissions interface{}
	resourceAppId string
}

type IntegerRange struct {
	end interface{}
	start interface{}
}

type IntegerRangeCollectionResponse struct {
	value interface{}
}

type InternalDomainFederation struct {
	activeSignInUri string
	displayName string
	federatedIdpMfaBehavior interface{}
	id string
	isSignedAuthenticationRequestRequired interface{}
	issuerUri string
	metadataExchangeUri string
	nextSigningCertificate string
	passiveSignInUri string
	preferredAuthenticationProtocol interface{}
	promptLoginBehavior interface{}
	signOutUri string
	signingCertificate string
	signingCertificateUpdateStatus interface{}
}

type InternalDomainFederationCollectionResponse struct {
	value interface{}
}

type InternetMessageHeader struct {
	name string
	value string
}

type InternetMessageHeaderCollectionResponse struct {
	value interface{}
}

type IntuneBrand struct {
	contactITEmailAddress string
	contactITName string
	contactITNotes string
	contactITPhoneNumber string
	darkBackgroundLogo interface{}
	displayName string
	lightBackgroundLogo interface{}
	onlineSupportSiteName string
	onlineSupportSiteUrl string
	privacyUrl string
	showDisplayNameNextToLogo interface{}
	showLogo interface{}
	showNameNextToLogo interface{}
	themeColor interface{}
}

type InvestigationSecurityState struct {
	name string
	status string
}

type InvestigationSecurityStateCollectionResponse struct {
	value interface{}
}

type Invitation struct {
	id string
	inviteRedeemUrl string
	inviteRedirectUrl string
	invitedUser interface{}
	invitedUserDisplayName string
	invitedUserEmailAddress string
	invitedUserMessageInfo interface{}
	invitedUserType string
	sendInvitationMessage interface{}
	status string
}

type InvitationCollectionResponse struct {
	value interface{}
}

type InvitationParticipantInfo struct {
	hidden interface{}
	identity interface{}
	participantId string
	removeFromDefaultAudioRoutingGroup interface{}
	replacesCallId string
}

type InvitationParticipantInfoCollectionResponse struct {
	value interface{}
}

type InviteNewBotResponse struct {
	inviteUri string
}

type InviteParticipantsOperation struct {
	clientContext string
	id string
	participants interface{}
	resultInfo interface{}
	status string
}

type InviteParticipantsOperationCollectionResponse struct {
	value interface{}
}

type InvitedUserMessageInfo struct {
	ccRecipients interface{}
	customizedMessageBody string
	messageLanguage string
}

type IosCertificateProfile struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type IosCertificateProfileCollectionResponse struct {
	value interface{}
}

type IosCompliancePolicy struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	deviceThreatProtectionEnabled interface{}
	deviceThreatProtectionRequiredSecurityLevel string
	displayName string
	id string
	lastModifiedDateTime string
	managedEmailProfileRequired interface{}
	osMaximumVersion string
	osMinimumVersion string
	passcodeBlockSimple interface{}
	passcodeExpirationDays interface{}
	passcodeMinimumCharacterSetCount interface{}
	passcodeMinimumLength interface{}
	passcodeMinutesOfInactivityBeforeLock interface{}
	passcodePreviousPasscodeBlockCount interface{}
	passcodeRequired interface{}
	passcodeRequiredType string
	scheduledActionsForRule interface{}
	securityBlockJailbrokenDevices interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type IosCompliancePolicyCollectionResponse struct {
	value interface{}
}

type IosCustomConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	payload string
	payloadFileName string
	payloadName string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type IosCustomConfigurationCollectionResponse struct {
	value interface{}
}

type IosDeviceFeaturesConfiguration struct {
	assetTagTemplate string
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	homeScreenDockIcons interface{}
	homeScreenPages interface{}
	id string
	lastModifiedDateTime string
	lockScreenFootnote string
	notificationSettings interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type IosDeviceFeaturesConfigurationCollectionResponse struct {
	value interface{}
}

type IosDeviceType struct {
	iPad interface{}
	iPhoneAndIPod interface{}
}

type IosGeneralDeviceConfiguration struct {
	accountBlockModification interface{}
	activationLockAllowWhenSupervised interface{}
	airDropBlocked interface{}
	airDropForceUnmanagedDropTarget interface{}
	airPlayForcePairingPasswordForOutgoingRequests interface{}
	appStoreBlockAutomaticDownloads interface{}
	appStoreBlockInAppPurchases interface{}
	appStoreBlockUIAppInstallation interface{}
	appStoreBlocked interface{}
	appStoreRequirePassword interface{}
	appleNewsBlocked interface{}
	appleWatchBlockPairing interface{}
	appleWatchForceWristDetection interface{}
	appsSingleAppModeList interface{}
	appsVisibilityList interface{}
	appsVisibilityListType string
	assignments interface{}
	bluetoothBlockModification interface{}
	cameraBlocked interface{}
	cellularBlockDataRoaming interface{}
	cellularBlockGlobalBackgroundFetchWhileRoaming interface{}
	cellularBlockPerAppDataModification interface{}
	cellularBlockPersonalHotspot interface{}
	cellularBlockVoiceRoaming interface{}
	certificatesBlockUntrustedTlsCertificates interface{}
	classroomAppBlockRemoteScreenObservation interface{}
	classroomAppForceUnpromptedScreenObservation interface{}
	compliantAppListType string
	compliantAppsList interface{}
	configurationProfileBlockChanges interface{}
	createdDateTime string
	definitionLookupBlocked interface{}
	description string
	deviceBlockEnableRestrictions interface{}
	deviceBlockEraseContentAndSettings interface{}
	deviceBlockNameModification interface{}
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	diagnosticDataBlockSubmission interface{}
	diagnosticDataBlockSubmissionModification interface{}
	displayName string
	documentsBlockManagedDocumentsInUnmanagedApps interface{}
	documentsBlockUnmanagedDocumentsInManagedApps interface{}
	emailInDomainSuffixes interface{}
	enterpriseAppBlockTrust interface{}
	enterpriseAppBlockTrustModification interface{}
	faceTimeBlocked interface{}
	findMyFriendsBlocked interface{}
	gameCenterBlocked interface{}
	gamingBlockGameCenterFriends interface{}
	gamingBlockMultiplayer interface{}
	hostPairingBlocked interface{}
	iBooksStoreBlockErotica interface{}
	iBooksStoreBlocked interface{}
	iCloudBlockActivityContinuation interface{}
	iCloudBlockBackup interface{}
	iCloudBlockDocumentSync interface{}
	iCloudBlockManagedAppsSync interface{}
	iCloudBlockPhotoLibrary interface{}
	iCloudBlockPhotoStreamSync interface{}
	iCloudBlockSharedPhotoStream interface{}
	iCloudRequireEncryptedBackup interface{}
	iTunesBlockExplicitContent interface{}
	iTunesBlockMusicService interface{}
	iTunesBlockRadio interface{}
	id string
	keyboardBlockAutoCorrect interface{}
	keyboardBlockDictation interface{}
	keyboardBlockPredictive interface{}
	keyboardBlockShortcuts interface{}
	keyboardBlockSpellCheck interface{}
	kioskModeAllowAssistiveSpeak interface{}
	kioskModeAllowAssistiveTouchSettings interface{}
	kioskModeAllowAutoLock interface{}
	kioskModeAllowColorInversionSettings interface{}
	kioskModeAllowRingerSwitch interface{}
	kioskModeAllowScreenRotation interface{}
	kioskModeAllowSleepButton interface{}
	kioskModeAllowTouchscreen interface{}
	kioskModeAllowVoiceOverSettings interface{}
	kioskModeAllowVolumeButtons interface{}
	kioskModeAllowZoomSettings interface{}
	kioskModeAppStoreUrl string
	kioskModeBuiltInAppId string
	kioskModeManagedAppId string
	kioskModeRequireAssistiveTouch interface{}
	kioskModeRequireColorInversion interface{}
	kioskModeRequireMonoAudio interface{}
	kioskModeRequireVoiceOver interface{}
	kioskModeRequireZoom interface{}
	lastModifiedDateTime string
	lockScreenBlockControlCenter interface{}
	lockScreenBlockNotificationView interface{}
	lockScreenBlockPassbook interface{}
	lockScreenBlockTodayView interface{}
	mediaContentRatingApps string
	mediaContentRatingAustralia interface{}
	mediaContentRatingCanada interface{}
	mediaContentRatingFrance interface{}
	mediaContentRatingGermany interface{}
	mediaContentRatingIreland interface{}
	mediaContentRatingJapan interface{}
	mediaContentRatingNewZealand interface{}
	mediaContentRatingUnitedKingdom interface{}
	mediaContentRatingUnitedStates interface{}
	messagesBlocked interface{}
	networkUsageRules interface{}
	notificationsBlockSettingsModification interface{}
	passcodeBlockFingerprintModification interface{}
	passcodeBlockFingerprintUnlock interface{}
	passcodeBlockModification interface{}
	passcodeBlockSimple interface{}
	passcodeExpirationDays interface{}
	passcodeMinimumCharacterSetCount interface{}
	passcodeMinimumLength interface{}
	passcodeMinutesOfInactivityBeforeLock interface{}
	passcodeMinutesOfInactivityBeforeScreenTimeout interface{}
	passcodePreviousPasscodeBlockCount interface{}
	passcodeRequired interface{}
	passcodeRequiredType string
	passcodeSignInFailureCountBeforeWipe interface{}
	podcastsBlocked interface{}
	safariBlockAutofill interface{}
	safariBlockJavaScript interface{}
	safariBlockPopups interface{}
	safariBlocked interface{}
	safariCookieSettings string
	safariManagedDomains interface{}
	safariPasswordAutoFillDomains interface{}
	safariRequireFraudWarning interface{}
	screenCaptureBlocked interface{}
	siriBlockUserGeneratedContent interface{}
	siriBlocked interface{}
	siriBlockedWhenLocked interface{}
	siriRequireProfanityFilter interface{}
	spotlightBlockInternetResults interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
	voiceDialingBlocked interface{}
	wallpaperBlockModification interface{}
	wiFiConnectOnlyToConfiguredNetworks interface{}
}

type IosGeneralDeviceConfigurationCollectionResponse struct {
	value interface{}
}

type IosHomeScreenApp struct {
	bundleID string
	displayName string
}

type IosHomeScreenAppCollectionResponse struct {
	value interface{}
}

type IosHomeScreenFolder struct {
	displayName string
	pages interface{}
}

type IosHomeScreenFolderPage struct {
	apps interface{}
	displayName string
}

type IosHomeScreenFolderPageCollectionResponse struct {
	value interface{}
}

type IosHomeScreenItem struct {
	displayName string
}

type IosHomeScreenItemCollectionResponse struct {
	value interface{}
}

type IosHomeScreenPage struct {
	displayName string
	icons interface{}
}

type IosHomeScreenPageCollectionResponse struct {
	value interface{}
}

type IosLobApp struct {
	applicableDeviceType interface{}
	assignments interface{}
	buildNumber string
	bundleId string
	categories interface{}
	committedContentVersion string
	contentVersions interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	expirationDateTime string
	fileName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	minimumSupportedOperatingSystem interface{}
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
	size interface{}
	versionNumber string
}

type IosLobAppAssignmentSettings struct {
	vpnConfigurationId string
}

type IosLobAppCollectionResponse struct {
	value interface{}
}

type IosManagedAppProtection struct {
	allowedDataStorageLocations interface{}
	allowedInboundDataTransferSources string
	allowedOutboundClipboardSharingLevel string
	allowedOutboundDataTransferDestinations string
	appDataEncryptionType string
	apps interface{}
	assignments interface{}
	contactSyncBlocked interface{}
	createdDateTime string
	customBrowserProtocol string
	dataBackupBlocked interface{}
	deployedAppCount interface{}
	deploymentSummary interface{}
	description string
	deviceComplianceRequired interface{}
	disableAppPinIfDevicePinIsSet interface{}
	displayName string
	faceIdBlocked interface{}
	fingerprintBlocked interface{}
	id string
	isAssigned interface{}
	lastModifiedDateTime string
	managedBrowser string
	managedBrowserToOpenLinksRequired interface{}
	maximumPinRetries interface{}
	minimumPinLength interface{}
	minimumRequiredAppVersion string
	minimumRequiredOsVersion string
	minimumRequiredSdkVersion string
	minimumWarningAppVersion string
	minimumWarningOsVersion string
	organizationalCredentialsRequired interface{}
	periodBeforePinReset string
	periodOfflineBeforeAccessCheck string
	periodOfflineBeforeWipeIsEnforced string
	periodOnlineBeforeAccessCheck string
	pinCharacterSet string
	pinRequired interface{}
	printBlocked interface{}
	saveAsBlocked interface{}
	simplePinBlocked interface{}
	version string
}

type IosManagedAppProtectionCollectionResponse struct {
	value interface{}
}

type IosManagedAppRegistration struct {
	appIdentifier interface{}
	applicationVersion string
	appliedPolicies interface{}
	createdDateTime string
	deviceName string
	deviceTag string
	deviceType string
	flaggedReasons interface{}
	id string
	intendedPolicies interface{}
	lastSyncDateTime string
	managementSdkVersion string
	operations interface{}
	platformVersion string
	userId string
	version string
}

type IosManagedAppRegistrationCollectionResponse struct {
	value interface{}
}

type IosMinimumOperatingSystem struct {
	v10_0 interface{}
	v11_0 interface{}
	v12_0 interface{}
	v13_0 interface{}
	v14_0 interface{}
	v8_0 interface{}
	v9_0 interface{}
}

type IosMobileAppConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceStatusSummary interface{}
	deviceStatuses interface{}
	displayName string
	encodedSettingXml string
	id string
	lastModifiedDateTime string
	settings interface{}
	targetedMobileApps interface{}
	userStatusSummary interface{}
	userStatuses interface{}
	version interface{}
}

type IosMobileAppConfigurationCollectionResponse struct {
	value interface{}
}

type IosMobileAppIdentifier struct {
	bundleId string
}

type IosNetworkUsageRule struct {
	cellularDataBlockWhenRoaming interface{}
	cellularDataBlocked interface{}
	managedApps interface{}
}

type IosNetworkUsageRuleCollectionResponse struct {
	value interface{}
}

type IosNotificationSettings struct {
	alertType string
	appName string
	badgesEnabled interface{}
	bundleID string
	enabled interface{}
	publisher string
	showInNotificationCenter interface{}
	showOnLockScreen interface{}
	soundsEnabled interface{}
}

type IosNotificationSettingsCollectionResponse struct {
	value interface{}
}

type IosStoreApp struct {
	appStoreUrl string
	applicableDeviceType interface{}
	assignments interface{}
	bundleId string
	categories interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	minimumSupportedOperatingSystem interface{}
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
}

type IosStoreAppAssignmentSettings struct {
	vpnConfigurationId string
}

type IosStoreAppCollectionResponse struct {
	value interface{}
}

type IosUpdateConfiguration struct {
	activeHoursEnd string
	activeHoursStart string
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	scheduledInstallDays interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	utcTimeOffsetInMinutes interface{}
	version interface{}
}

type IosUpdateConfigurationCollectionResponse struct {
	value interface{}
}

type IosUpdateDeviceStatus struct {
	complianceGracePeriodExpirationDateTime string
	deviceDisplayName string
	deviceId string
	deviceModel string
	id string
	installStatus string
	lastReportedDateTime string
	osVersion string
	status string
	userId string
	userName string
	userPrincipalName string
}

type IosUpdateDeviceStatusCollectionResponse struct {
	value interface{}
}

type IosVppApp struct {
	appStoreUrl string
	applicableDeviceType interface{}
	assignments interface{}
	bundleId string
	categories interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	licensingType interface{}
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
	releaseDateTime string
	totalLicenseCount interface{}
	usedLicenseCount interface{}
	vppTokenAccountType string
	vppTokenAppleId string
	vppTokenOrganizationName string
}

type IosVppAppAssignmentSettings struct {
	useDeviceLicensing interface{}
	vpnConfigurationId string
}

type IosVppAppCollectionResponse struct {
	value interface{}
}

type IosVppEBook struct {
	appleId string
	assignments interface{}
	createdDateTime string
	description string
	deviceStates interface{}
	displayName string
	genres interface{}
	id string
	informationUrl string
	installSummary interface{}
	language string
	largeCover interface{}
	lastModifiedDateTime string
	privacyInformationUrl string
	publishedDateTime string
	publisher string
	seller string
	totalLicenseCount interface{}
	usedLicenseCount interface{}
	userStateSummary interface{}
	vppOrganizationName string
	vppTokenId string
}

type IosVppEBookAssignment struct {
	id string
	installIntent string
	target interface{}
}

type IosVppEBookAssignmentCollectionResponse struct {
	value interface{}
}

type IosVppEBookCollectionResponse struct {
	value interface{}
}

type IpNamedLocation struct {
	createdDateTime string
	displayName string
	id string
	ipRanges interface{}
	isTrusted interface{}
	modifiedDateTime string
}

type IpNamedLocationCollectionResponse struct {
	value interface{}
}

type IpRangeCollectionResponse struct {
	value interface{}
}

type ItemActionStat struct {
	actionCount interface{}
	actorCount interface{}
}

type ItemActivity struct {
	access interface{}
	activityDateTime string
	actor interface{}
	driveItem interface{}
	id string
}

type ItemActivityCollectionResponse struct {
	value interface{}
}

type ItemActivityStat struct {
	access interface{}
	activities interface{}
	create interface{}
	delete interface{}
	edit interface{}
	endDateTime string
	id string
	incompleteData interface{}
	isTrending interface{}
	move interface{}
	startDateTime string
}

type ItemActivityStatCollectionResponse struct {
	value interface{}
}

type ItemAnalytics struct {
	allTime interface{}
	id string
	itemActivityStats interface{}
	lastSevenDays interface{}
}

type ItemAttachment struct {
	contentType string
	id string
	isInline interface{}
	item interface{}
	lastModifiedDateTime string
	name string
	size interface{}
}

type ItemAttachmentCollectionResponse struct {
	value interface{}
}

type ItemBody struct {
	content string
	contentType interface{}
}

type ItemPreviewInfo struct {
	getUrl string
	postParameters string
	postUrl string
}

type ItemReference struct {
	driveId string
	driveType string
	id string
	name string
	path string
	shareId string
	sharepointIds interface{}
	siteId string
}

type KeyCredential struct {
	customKeyIdentifier string
	displayName string
	endDateTime string
	key string
	keyId string
	startDateTime string
	type string
	usage string
}

type KeyCredentialCollectionResponse struct {
	value interface{}
}

type KeyValue struct {
	key string
	value string
}

type KeyValueCollectionResponse struct {
	value interface{}
}

type KeyValuePair struct {
	name string
	value string
}

type KeyValuePairCollectionResponse struct {
	value interface{}
}

type LicenseAssignmentState struct {
	assignedByGroup string
	disabledPlans interface{}
	error string
	lastUpdatedDateTime string
	skuId string
	state string
}

type LicenseAssignmentStateCollectionResponse struct {
	value interface{}
}

type LicenseDetails struct {
	id string
	servicePlans interface{}
	skuId string
	skuPartNumber string
}

type LicenseDetailsCollectionResponse struct {
	value interface{}
}

type LicenseProcessingState struct {
	state string
}

type LicenseUnitsDetail struct {
	enabled interface{}
	suspended interface{}
	warning interface{}
}

type LinkedResource struct {
	applicationName string
	displayName string
	externalId string
	id string
	webUrl string
}

type LinkedResourceCollectionResponse struct {
	value interface{}
}

type List struct {
	columns interface{}
	contentTypes interface{}
	createdBy interface{}
	createdByUser interface{}
	createdDateTime string
	description string
	displayName string
	drive interface{}
	eTag string
	id string
	items interface{}
	lastModifiedBy interface{}
	lastModifiedByUser interface{}
	lastModifiedDateTime string
	list interface{}
	name string
	operations interface{}
	parentReference interface{}
	sharepointIds interface{}
	subscriptions interface{}
	system interface{}
	webUrl string
}

type ListCollectionResponse struct {
	value interface{}
}

type ListInfo struct {
	contentTypesEnabled interface{}
	hidden interface{}
	template string
}

type ListItem struct {
	analytics interface{}
	contentType interface{}
	createdBy interface{}
	createdByUser interface{}
	createdDateTime string
	description string
	documentSetVersions interface{}
	driveItem interface{}
	eTag string
	fields interface{}
	id string
	lastModifiedBy interface{}
	lastModifiedByUser interface{}
	lastModifiedDateTime string
	name string
	parentReference interface{}
	sharepointIds interface{}
	versions interface{}
	webUrl string
}

type ListItemCollectionResponse struct {
	value interface{}
}

type ListItemVersion struct {
	fields interface{}
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	publication interface{}
}

type ListItemVersionCollectionResponse struct {
	value interface{}
}

type LobbyBypassSettings struct {
	isDialInBypassEnabled interface{}
	scope interface{}
}

type LocaleInfo struct {
	displayName string
	locale string
}

type LocalizedNotificationMessage struct {
	id string
	isDefault interface{}
	lastModifiedDateTime string
	locale string
	messageTemplate string
	subject string
}

type LocalizedNotificationMessageCollectionResponse struct {
	value interface{}
}

type LocateDeviceActionResult struct {
	actionName string
	actionState string
	deviceLocation interface{}
	lastUpdatedDateTime string
	startDateTime string
}

type Location struct {
	address interface{}
	coordinates interface{}
	displayName string
	locationEmailAddress string
	locationType interface{}
	locationUri string
	uniqueId string
	uniqueIdType interface{}
}

type LocationCollectionResponse struct {
	value interface{}
}

type LocationConstraint struct {
	isRequired interface{}
	locations interface{}
	suggestLocation interface{}
}

type LocationConstraintItem struct {
	address interface{}
	coordinates interface{}
	displayName string
	locationEmailAddress string
	locationType interface{}
	locationUri string
	resolveAvailability interface{}
	uniqueId string
	uniqueIdType interface{}
}

type LocationConstraintItemCollectionResponse struct {
	value interface{}
}

type LongRunningOperation struct {
	createdDateTime string
	id string
	lastActionDateTime string
	resourceLocation string
	status interface{}
	statusDetail string
}

type LongRunningOperationCollectionResponse struct {
	value interface{}
}

type LookupColumn struct {
	allowMultipleValues interface{}
	allowUnlimitedLength interface{}
	columnName string
	listId string
	primaryLookupColumnId string
}

type MacOSCompliancePolicy struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	deviceThreatProtectionEnabled interface{}
	deviceThreatProtectionRequiredSecurityLevel string
	displayName string
	firewallBlockAllIncoming interface{}
	firewallEnableStealthMode interface{}
	firewallEnabled interface{}
	id string
	lastModifiedDateTime string
	osMaximumVersion string
	osMinimumVersion string
	passwordBlockSimple interface{}
	passwordExpirationDays interface{}
	passwordMinimumCharacterSetCount interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeLock interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequired interface{}
	passwordRequiredType string
	scheduledActionsForRule interface{}
	storageRequireEncryption interface{}
	systemIntegrityProtectionEnabled interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type MacOSCompliancePolicyCollectionResponse struct {
	value interface{}
}

type MacOSCustomConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	payload string
	payloadFileName string
	payloadName string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type MacOSCustomConfigurationCollectionResponse struct {
	value interface{}
}

type MacOSDeviceFeaturesConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type MacOSDeviceFeaturesConfigurationCollectionResponse struct {
	value interface{}
}

type MacOSGeneralDeviceConfiguration struct {
	assignments interface{}
	compliantAppListType string
	compliantAppsList interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	emailInDomainSuffixes interface{}
	id string
	lastModifiedDateTime string
	passwordBlockSimple interface{}
	passwordExpirationDays interface{}
	passwordMinimumCharacterSetCount interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeLock interface{}
	passwordMinutesOfInactivityBeforeScreenTimeout interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequired interface{}
	passwordRequiredType string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type MacOSGeneralDeviceConfigurationCollectionResponse struct {
	value interface{}
}

type MacOSOfficeSuiteApp struct {
	assignments interface{}
	categories interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
}

type MacOSOfficeSuiteAppCollectionResponse struct {
	value interface{}
}

type MailAssessmentRequest struct {
	category string
	contentType interface{}
	createdBy interface{}
	createdDateTime string
	destinationRoutingReason interface{}
	expectedAssessment string
	id string
	messageUri string
	recipientEmail string
	requestSource interface{}
	results interface{}
	status interface{}
}

type MailAssessmentRequestCollectionResponse struct {
	value interface{}
}

type MailFolder struct {
	childFolderCount interface{}
	childFolders interface{}
	displayName string
	id string
	isHidden interface{}
	messageRules interface{}
	messages interface{}
	multiValueExtendedProperties interface{}
	parentFolderId string
	singleValueExtendedProperties interface{}
	totalItemCount interface{}
	unreadItemCount interface{}
}

type MailFolderCollectionResponse struct {
	value interface{}
}

type MailSearchFolder struct {
	childFolderCount interface{}
	childFolders interface{}
	displayName string
	filterQuery string
	id string
	includeNestedFolders interface{}
	isHidden interface{}
	isSupported interface{}
	messageRules interface{}
	messages interface{}
	multiValueExtendedProperties interface{}
	parentFolderId string
	singleValueExtendedProperties interface{}
	sourceFolderIds interface{}
	totalItemCount interface{}
	unreadItemCount interface{}
}

type MailSearchFolderCollectionResponse struct {
	value interface{}
}

type MailTips struct {
	automaticReplies interface{}
	customMailTip string
	deliveryRestricted interface{}
	emailAddress interface{}
	error interface{}
	externalMemberCount interface{}
	isModerated interface{}
	mailboxFull interface{}
	maxMessageSize interface{}
	recipientScope interface{}
	recipientSuggestions interface{}
	totalMemberCount interface{}
}

type MailTipsError struct {
	code string
	message string
}

type MailboxSettings struct {
	archiveFolder string
	automaticRepliesSetting interface{}
	dateFormat string
	delegateMeetingMessageDeliveryOptions interface{}
	language interface{}
	timeFormat string
	timeZone string
	userPurpose interface{}
	workingHours interface{}
}

type Malware struct {
	description string
}

type MalwareState struct {
	category string
	family string
	name string
	severity string
	wasRunning interface{}
}

type MalwareStateCollectionResponse struct {
	value interface{}
}

type ManagedAndroidLobApp struct {
	appAvailability string
	assignments interface{}
	categories interface{}
	committedContentVersion string
	contentVersions interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	fileName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	minimumSupportedOperatingSystem interface{}
	notes string
	owner string
	packageId string
	privacyInformationUrl string
	publisher string
	publishingState string
	size interface{}
	version string
	versionCode string
	versionName string
}

type ManagedAndroidLobAppCollectionResponse struct {
	value interface{}
}

type ManagedAndroidStoreApp struct {
	appAvailability string
	appStoreUrl string
	assignments interface{}
	categories interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	minimumSupportedOperatingSystem interface{}
	notes string
	owner string
	packageId string
	privacyInformationUrl string
	publisher string
	publishingState string
	version string
}

type ManagedAndroidStoreAppCollectionResponse struct {
	value interface{}
}

type ManagedApp struct {
	appAvailability string
	assignments interface{}
	categories interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
	version string
}

type ManagedAppCollectionResponse struct {
	value interface{}
}

type ManagedAppConfiguration struct {
	createdDateTime string
	customSettings interface{}
	description string
	displayName string
	id string
	lastModifiedDateTime string
	version string
}

type ManagedAppConfigurationCollectionResponse struct {
	value interface{}
}

type ManagedAppDiagnosticStatus struct {
	mitigationInstruction string
	state string
	validationName string
}

type ManagedAppOperation struct {
	displayName string
	id string
	lastModifiedDateTime string
	state string
	version string
}

type ManagedAppOperationCollectionResponse struct {
	value interface{}
}

type ManagedAppPolicy struct {
	createdDateTime string
	description string
	displayName string
	id string
	lastModifiedDateTime string
	version string
}

type ManagedAppPolicyCollectionResponse struct {
	value interface{}
}

type ManagedAppPolicyDeploymentSummary struct {
	configurationDeployedUserCount interface{}
	configurationDeploymentSummaryPerApp interface{}
	displayName string
	id string
	lastRefreshTime string
	version string
}

type ManagedAppPolicyDeploymentSummaryPerApp struct {
	configurationAppliedUserCount interface{}
	mobileAppIdentifier interface{}
}

type ManagedAppPolicyDeploymentSummaryPerAppCollectionResponse struct {
	value interface{}
}

type ManagedAppProtection struct {
	allowedDataStorageLocations interface{}
	allowedInboundDataTransferSources string
	allowedOutboundClipboardSharingLevel string
	allowedOutboundDataTransferDestinations string
	contactSyncBlocked interface{}
	createdDateTime string
	dataBackupBlocked interface{}
	description string
	deviceComplianceRequired interface{}
	disableAppPinIfDevicePinIsSet interface{}
	displayName string
	fingerprintBlocked interface{}
	id string
	lastModifiedDateTime string
	managedBrowser string
	managedBrowserToOpenLinksRequired interface{}
	maximumPinRetries interface{}
	minimumPinLength interface{}
	minimumRequiredAppVersion string
	minimumRequiredOsVersion string
	minimumWarningAppVersion string
	minimumWarningOsVersion string
	organizationalCredentialsRequired interface{}
	periodBeforePinReset string
	periodOfflineBeforeAccessCheck string
	periodOfflineBeforeWipeIsEnforced string
	periodOnlineBeforeAccessCheck string
	pinCharacterSet string
	pinRequired interface{}
	printBlocked interface{}
	saveAsBlocked interface{}
	simplePinBlocked interface{}
	version string
}

type ManagedAppProtectionCollectionResponse struct {
	value interface{}
}

type ManagedAppRegistration struct {
	appIdentifier interface{}
	applicationVersion string
	appliedPolicies interface{}
	createdDateTime string
	deviceName string
	deviceTag string
	deviceType string
	flaggedReasons interface{}
	id string
	intendedPolicies interface{}
	lastSyncDateTime string
	managementSdkVersion string
	operations interface{}
	platformVersion string
	userId string
	version string
}

type ManagedAppRegistrationCollectionResponse struct {
	value interface{}
}

type ManagedAppStatus struct {
	displayName string
	id string
	version string
}

type ManagedAppStatusCollectionResponse struct {
	value interface{}
}

type ManagedAppStatusRaw struct {
	content interface{}
	displayName string
	id string
	version string
}

type ManagedAppStatusRawCollectionResponse struct {
	value interface{}
}

type ManagedDevice struct {
	activationLockBypassCode string
	androidSecurityPatchLevel string
	azureADDeviceId string
	azureADRegistered interface{}
	complianceGracePeriodExpirationDateTime string
	complianceState string
	configurationManagerClientEnabledFeatures interface{}
	deviceActionResults interface{}
	deviceCategory interface{}
	deviceCategoryDisplayName string
	deviceCompliancePolicyStates interface{}
	deviceConfigurationStates interface{}
	deviceEnrollmentType string
	deviceHealthAttestationState interface{}
	deviceName string
	deviceRegistrationState string
	easActivated interface{}
	easActivationDateTime string
	easDeviceId string
	emailAddress string
	enrolledDateTime string
	ethernetMacAddress string
	exchangeAccessState string
	exchangeAccessStateReason string
	exchangeLastSuccessfulSyncDateTime string
	freeStorageSpaceInBytes interface{}
	iccid string
	id string
	imei string
	isEncrypted interface{}
	isSupervised interface{}
	jailBroken string
	lastSyncDateTime string
	managedDeviceName string
	managedDeviceOwnerType string
	managementAgent string
	manufacturer string
	meid string
	model string
	notes string
	operatingSystem string
	osVersion string
	partnerReportedThreatState string
	phoneNumber string
	physicalMemoryInBytes interface{}
	remoteAssistanceSessionErrorDetails string
	remoteAssistanceSessionUrl string
	serialNumber string
	subscriberCarrier string
	totalStorageSpaceInBytes interface{}
	udid string
	userDisplayName string
	userId string
	userPrincipalName string
	wiFiMacAddress string
}

type ManagedDeviceCollectionResponse struct {
	value interface{}
}

type ManagedDeviceMobileAppConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceStatusSummary interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	targetedMobileApps interface{}
	userStatusSummary interface{}
	userStatuses interface{}
	version interface{}
}

type ManagedDeviceMobileAppConfigurationAssignment struct {
	id string
	target interface{}
}

type ManagedDeviceMobileAppConfigurationAssignmentCollectionResponse struct {
	value interface{}
}

type ManagedDeviceMobileAppConfigurationCollectionResponse struct {
	value interface{}
}

type ManagedDeviceMobileAppConfigurationDeviceStatus struct {
	complianceGracePeriodExpirationDateTime string
	deviceDisplayName string
	deviceModel string
	id string
	lastReportedDateTime string
	status string
	userName string
	userPrincipalName string
}

type ManagedDeviceMobileAppConfigurationDeviceStatusCollectionResponse struct {
	value interface{}
}

type ManagedDeviceMobileAppConfigurationDeviceSummary struct {
	configurationVersion interface{}
	errorCount interface{}
	failedCount interface{}
	id string
	lastUpdateDateTime string
	notApplicableCount interface{}
	pendingCount interface{}
	successCount interface{}
}

type ManagedDeviceMobileAppConfigurationUserStatus struct {
	devicesCount interface{}
	id string
	lastReportedDateTime string
	status string
	userDisplayName string
	userPrincipalName string
}

type ManagedDeviceMobileAppConfigurationUserStatusCollectionResponse struct {
	value interface{}
}

type ManagedDeviceMobileAppConfigurationUserSummary struct {
	configurationVersion interface{}
	errorCount interface{}
	failedCount interface{}
	id string
	lastUpdateDateTime string
	notApplicableCount interface{}
	pendingCount interface{}
	successCount interface{}
}

type ManagedDeviceOverview struct {
	deviceExchangeAccessStateSummary interface{}
	deviceOperatingSystemSummary interface{}
	dualEnrolledDeviceCount interface{}
	enrolledDeviceCount interface{}
	id string
	mdmEnrolledCount interface{}
}

type ManagedEBook struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceStates interface{}
	displayName string
	id string
	informationUrl string
	installSummary interface{}
	largeCover interface{}
	lastModifiedDateTime string
	privacyInformationUrl string
	publishedDateTime string
	publisher string
	userStateSummary interface{}
}

type ManagedEBookAssignment struct {
	id string
	installIntent string
	target interface{}
}

type ManagedEBookAssignmentCollectionResponse struct {
	value interface{}
}

type ManagedEBookCollectionResponse struct {
	value interface{}
}

type ManagedIOSLobApp struct {
	appAvailability string
	applicableDeviceType interface{}
	assignments interface{}
	buildNumber string
	bundleId string
	categories interface{}
	committedContentVersion string
	contentVersions interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	expirationDateTime string
	fileName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	minimumSupportedOperatingSystem interface{}
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
	size interface{}
	version string
	versionNumber string
}

type ManagedIOSLobAppCollectionResponse struct {
	value interface{}
}

type ManagedIOSStoreApp struct {
	appAvailability string
	appStoreUrl string
	applicableDeviceType interface{}
	assignments interface{}
	bundleId string
	categories interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	minimumSupportedOperatingSystem interface{}
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
	version string
}

type ManagedIOSStoreAppCollectionResponse struct {
	value interface{}
}

type ManagedMobileApp struct {
	id string
	mobileAppIdentifier interface{}
	version string
}

type ManagedMobileAppCollectionResponse struct {
	value interface{}
}

type ManagedMobileLobApp struct {
	appAvailability string
	assignments interface{}
	categories interface{}
	committedContentVersion string
	contentVersions interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	fileName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
	size interface{}
	version string
}

type ManagedMobileLobAppCollectionResponse struct {
	value interface{}
}

type MdmWindowsInformationProtectionPolicy struct {
	assignments interface{}
	azureRightsManagementServicesAllowed interface{}
	createdDateTime string
	dataRecoveryCertificate interface{}
	description string
	displayName string
	enforcementLevel string
	enterpriseDomain string
	enterpriseIPRanges interface{}
	enterpriseIPRangesAreAuthoritative interface{}
	enterpriseInternalProxyServers interface{}
	enterpriseNetworkDomainNames interface{}
	enterpriseProtectedDomainNames interface{}
	enterpriseProxiedDomains interface{}
	enterpriseProxyServers interface{}
	enterpriseProxyServersAreAuthoritative interface{}
	exemptAppLockerFiles interface{}
	exemptApps interface{}
	iconsVisible interface{}
	id string
	indexingEncryptedStoresOrItemsBlocked interface{}
	isAssigned interface{}
	lastModifiedDateTime string
	neutralDomainResources interface{}
	protectedAppLockerFiles interface{}
	protectedApps interface{}
	protectionUnderLockConfigRequired interface{}
	revokeOnUnenrollDisabled interface{}
	rightsManagementServicesTemplateId string
	smbAutoEncryptedFileExtensions interface{}
	version string
}

type MdmWindowsInformationProtectionPolicyCollectionResponse struct {
	value interface{}
}

type MediaContentRatingAustralia struct {
	movieRating string
	tvRating string
}

type MediaContentRatingCanada struct {
	movieRating string
	tvRating string
}

type MediaContentRatingFrance struct {
	movieRating string
	tvRating string
}

type MediaContentRatingGermany struct {
	movieRating string
	tvRating string
}

type MediaContentRatingIreland struct {
	movieRating string
	tvRating string
}

type MediaContentRatingJapan struct {
	movieRating string
	tvRating string
}

type MediaContentRatingNewZealand struct {
	movieRating string
	tvRating string
}

type MediaContentRatingUnitedKingdom struct {
	movieRating string
	tvRating string
}

type MediaContentRatingUnitedStates struct {
	movieRating string
	tvRating string
}

type MediaInfo struct {
	resourceId string
	uri string
}

type MediaInfoCollectionResponse struct {
	value interface{}
}

type MediaPrompt struct {
	mediaInfo interface{}
}

type MediaStream struct {
	direction string
	label string
	mediaType string
	serverMuted interface{}
	sourceId string
}

type MediaStreamCollectionResponse struct {
	value interface{}
}

type MeetingAttendanceReport struct {
	attendanceRecords interface{}
	id string
	meetingEndDateTime string
	meetingStartDateTime string
	totalParticipantCount interface{}
}

type MeetingAttendanceReportCollectionResponse struct {
	value interface{}
}

type MeetingParticipantInfo struct {
	identity interface{}
	role interface{}
	upn string
}

type MeetingParticipantInfoCollectionResponse struct {
	value interface{}
}

type MeetingParticipants struct {
	attendees interface{}
	organizer interface{}
}

type MeetingPolicyUpdatedEventMessageDetail struct {
	initiator interface{}
	meetingChatEnabled interface{}
	meetingChatId string
}

type MeetingTimeSuggestion struct {
	attendeeAvailability interface{}
	confidence interface{}
	locations interface{}
	meetingTimeSlot interface{}
	order interface{}
	organizerAvailability interface{}
	suggestionReason string
}

type MeetingTimeSuggestionCollectionResponse struct {
	value interface{}
}

type MeetingTimeSuggestionsResult struct {
	emptySuggestionsReason string
	meetingTimeSuggestions interface{}
}

type MembersAddedEventMessageDetail struct {
	initiator interface{}
	members interface{}
	visibleHistoryStartDateTime string
}

type MembersDeletedEventMessageDetail struct {
	initiator interface{}
	members interface{}
}

type MembersJoinedEventMessageDetail struct {
	initiator interface{}
	members interface{}
}

type MembersLeftEventMessageDetail struct {
	initiator interface{}
	members interface{}
}

type Message struct {
	attachments interface{}
	bccRecipients interface{}
	body interface{}
	bodyPreview string
	categories interface{}
	ccRecipients interface{}
	changeKey string
	conversationId string
	conversationIndex string
	createdDateTime string
	extensions interface{}
	flag interface{}
	from interface{}
	hasAttachments interface{}
	id string
	importance interface{}
	inferenceClassification interface{}
	internetMessageHeaders interface{}
	internetMessageId string
	isDeliveryReceiptRequested interface{}
	isDraft interface{}
	isRead interface{}
	isReadReceiptRequested interface{}
	lastModifiedDateTime string
	multiValueExtendedProperties interface{}
	parentFolderId string
	receivedDateTime string
	replyTo interface{}
	sender interface{}
	sentDateTime string
	singleValueExtendedProperties interface{}
	subject string
	toRecipients interface{}
	uniqueBody interface{}
	webLink string
}

type MessageCollectionResponse struct {
	value interface{}
}

type MessageRule struct {
	actions interface{}
	conditions interface{}
	displayName string
	exceptions interface{}
	hasError interface{}
	id string
	isEnabled interface{}
	isReadOnly interface{}
	sequence interface{}
}

type MessageRuleActions struct {
	assignCategories interface{}
	copyToFolder string
	delete interface{}
	forwardAsAttachmentTo interface{}
	forwardTo interface{}
	markAsRead interface{}
	markImportance interface{}
	moveToFolder string
	permanentDelete interface{}
	redirectTo interface{}
	stopProcessingRules interface{}
}

type MessageRuleCollectionResponse struct {
	value interface{}
}

type MessageRulePredicates struct {
	bodyContains interface{}
	bodyOrSubjectContains interface{}
	categories interface{}
	fromAddresses interface{}
	hasAttachments interface{}
	headerContains interface{}
	importance interface{}
	isApprovalRequest interface{}
	isAutomaticForward interface{}
	isAutomaticReply interface{}
	isEncrypted interface{}
	isMeetingRequest interface{}
	isMeetingResponse interface{}
	isNonDeliveryReport interface{}
	isPermissionControlled interface{}
	isReadReceipt interface{}
	isSigned interface{}
	isVoicemail interface{}
	messageActionFlag interface{}
	notSentToMe interface{}
	recipientContains interface{}
	senderContains interface{}
	sensitivity interface{}
	sentCcMe interface{}
	sentOnlyToMe interface{}
	sentToAddresses interface{}
	sentToMe interface{}
	sentToOrCcMe interface{}
	subjectContains interface{}
	withinSizeRange interface{}
}

type MessageSecurityState struct {
	connectingIP string
	deliveryAction string
	deliveryLocation string
	directionality string
	internetMessageId string
	messageFingerprint string
	messageReceivedDateTime string
	messageSubject string
	networkMessageId string
}

type MessageSecurityStateCollectionResponse struct {
	value interface{}
}

type MicrosoftAuthenticatorAuthenticationMethod struct {
	createdDateTime string
	device interface{}
	deviceTag string
	displayName string
	id string
	phoneAppVersion string
}

type MicrosoftAuthenticatorAuthenticationMethodCollectionResponse struct {
	value interface{}
}

type MicrosoftAuthenticatorAuthenticationMethodConfiguration struct {
	id string
	includeTargets interface{}
	state interface{}
}

type MicrosoftAuthenticatorAuthenticationMethodConfigurationCollectionResponse struct {
	value interface{}
}

type MicrosoftAuthenticatorAuthenticationMethodTarget struct {
	authenticationMode string
	id string
	isRegistrationRequired interface{}
	targetType string
}

type MicrosoftAuthenticatorAuthenticationMethodTargetCollectionResponse struct {
	value interface{}
}

type MicrosoftStoreForBusinessApp struct {
	assignments interface{}
	categories interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	licenseType string
	notes string
	owner string
	packageIdentityName string
	privacyInformationUrl string
	productKey string
	publisher string
	publishingState string
	totalLicenseCount interface{}
	usedLicenseCount interface{}
}

type MicrosoftStoreForBusinessAppAssignmentSettings struct {
	useDeviceContext interface{}
}

type MicrosoftStoreForBusinessAppCollectionResponse struct {
	value interface{}
}

type MimeContent struct {
	type string
	value string
}

type MobileApp struct {
	assignments interface{}
	categories interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
}

type MobileAppAssignment struct {
	id string
	intent string
	settings interface{}
	target interface{}
}

type MobileAppAssignmentCollectionResponse struct {
	value interface{}
}

type MobileAppCategory struct {
	displayName string
	id string
	lastModifiedDateTime string
}

type MobileAppCategoryCollectionResponse struct {
	value interface{}
}

type MobileAppCollectionResponse struct {
	value interface{}
}

type MobileAppContent struct {
	files interface{}
	id string
}

type MobileAppContentCollectionResponse struct {
	value interface{}
}

type MobileAppContentFile struct {
	azureStorageUri string
	azureStorageUriExpirationDateTime string
	createdDateTime string
	id string
	isCommitted interface{}
	manifest string
	name string
	size interface{}
	sizeEncrypted interface{}
	uploadState string
}

type MobileAppContentFileCollectionResponse struct {
	value interface{}
}

type MobileAppInstallTimeSettings struct {
	deadlineDateTime string
	startDateTime string
	useLocalTime interface{}
}

type MobileLobApp struct {
	assignments interface{}
	categories interface{}
	committedContentVersion string
	contentVersions interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	fileName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
	size interface{}
}

type MobileLobAppCollectionResponse struct {
	value interface{}
}

type MobileThreatDefenseConnector struct {
	androidDeviceBlockedOnMissingPartnerData interface{}
	androidEnabled interface{}
	id string
	iosDeviceBlockedOnMissingPartnerData interface{}
	iosEnabled interface{}
	lastHeartbeatDateTime string
	partnerState string
	partnerUnresponsivenessThresholdInDays interface{}
	partnerUnsupportedOsVersionBlocked interface{}
}

type MobileThreatDefenseConnectorCollectionResponse struct {
	value interface{}
}

type ModifiedProperty struct {
	displayName string
	newValue string
	oldValue string
}

type ModifiedPropertyCollectionResponse struct {
	value interface{}
}

type MultiValueLegacyExtendedProperty struct {
	id string
	value interface{}
}

type MultiValueLegacyExtendedPropertyCollectionResponse struct {
	value interface{}
}

type MuteParticipantOperation struct {
	clientContext string
	id string
	resultInfo interface{}
	status string
}

type MuteParticipantOperationCollectionResponse struct {
	value interface{}
}

type NamedLocation struct {
	createdDateTime string
	displayName string
	id string
	modifiedDateTime string
}

type NamedLocationCollectionResponse struct {
	value interface{}
}

type NetworkConnection struct {
	applicationName string
	destinationAddress string
	destinationDomain string
	destinationLocation string
	destinationPort string
	destinationUrl string
	direction interface{}
	domainRegisteredDateTime string
	localDnsName string
	natDestinationAddress string
	natDestinationPort string
	natSourceAddress string
	natSourcePort string
	protocol interface{}
	riskScore string
	sourceAddress string
	sourceLocation string
	sourcePort string
	status interface{}
	urlParameters string
}

type NetworkConnectionCollectionResponse struct {
	value interface{}
}

type NetworkInfo struct {
	bandwidthLowEventRatio interface{}
	basicServiceSetIdentifier string
	connectionType string
	delayEventRatio interface{}
	dnsSuffix string
	ipAddress string
	linkSpeed interface{}
	macAddress string
	networkTransportProtocol string
	port interface{}
	receivedQualityEventRatio interface{}
	reflexiveIPAddress string
	relayIPAddress string
	relayPort interface{}
	sentQualityEventRatio interface{}
	subnet string
	traceRouteHops interface{}
	wifiBand string
	wifiBatteryCharge interface{}
	wifiChannel interface{}
	wifiMicrosoftDriver string
	wifiMicrosoftDriverVersion string
	wifiRadioType string
	wifiSignalStrength interface{}
	wifiVendorDriver string
	wifiVendorDriverVersion string
}

type Notebook struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	id string
	isDefault interface{}
	isShared interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	links interface{}
	sectionGroups interface{}
	sectionGroupsUrl string
	sections interface{}
	sectionsUrl string
	self string
	userRole interface{}
}

type NotebookCollectionResponse struct {
	value interface{}
}

type NotebookLinks struct {
	oneNoteClientUrl interface{}
	oneNoteWebUrl interface{}
}

type NotificationMessageTemplate struct {
	brandingOptions string
	defaultLocale string
	displayName string
	id string
	lastModifiedDateTime string
	localizedNotificationMessages interface{}
}

type NotificationMessageTemplateCollectionResponse struct {
	value interface{}
}

type NumberColumn struct {
	decimalPlaces string
	displayAs string
	maximum interface{}
	minimum interface{}
}

type OAuth2PermissionGrant struct {
	clientId string
	consentType string
	id string
	principalId string
	resourceId string
	scope string
}

type OAuth2PermissionGrantCollectionResponse struct {
	value interface{}
}

type ODataErrorsErrorDetails struct {
	code string
	message string
	target string
}

type ODataErrorsInnerError struct {
	Date string
	client-request-id string
	request-id string
}

type ODataErrorsMainError struct {
	code string
	details interface{}
	innererror interface{}
	message string
	target string
}

type ODataErrorsODataError struct {
	error interface{}
}

type ODataErrorsODataErrorError struct {
	code string
	details interface{}
	innererror interface{}
	message string
	target string
}

type ObjectIdentity struct {
	issuer string
	issuerAssignedId string
	signInType string
}

type ObjectIdentityCollectionResponse struct {
	value interface{}
}

type OcrSettings struct {
	isEnabled interface{}
	maxImageSize interface{}
	timeout string
}

type OfferShiftRequest struct {
	assignedTo interface{}
	createdDateTime string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	managerActionDateTime string
	managerActionMessage string
	managerUserId string
	recipientActionDateTime string
	recipientActionMessage string
	recipientUserId string
	senderDateTime string
	senderMessage string
	senderShiftId string
	senderUserId string
	state interface{}
}

type OfferShiftRequestCollectionResponse struct {
	value interface{}
}

type OfficeGraphInsights struct {
	id string
	shared interface{}
	trending interface{}
	used interface{}
}

type OmaSetting struct {
	description string
	displayName string
	omaUri string
}

type OmaSettingBase64 struct {
	description string
	displayName string
	fileName string
	omaUri string
	value string
}

type OmaSettingBoolean struct {
	description string
	displayName string
	omaUri string
	value interface{}
}

type OmaSettingCollectionResponse struct {
	value interface{}
}

type OmaSettingDateTime struct {
	description string
	displayName string
	omaUri string
	value string
}

type OmaSettingFloatingPoint struct {
	description string
	displayName string
	omaUri string
	value interface{}
}

type OmaSettingInteger struct {
	description string
	displayName string
	omaUri string
	value interface{}
}

type OmaSettingString struct {
	description string
	displayName string
	omaUri string
	value string
}

type OmaSettingStringXml struct {
	description string
	displayName string
	fileName string
	omaUri string
	value string
}

type OnPremisesConditionalAccessSettings struct {
	enabled interface{}
	excludedGroups interface{}
	id string
	includedGroups interface{}
	overrideDefaultRule interface{}
}

type OnPremisesExtensionAttributes struct {
	extensionAttribute1 string
	extensionAttribute10 string
	extensionAttribute11 string
	extensionAttribute12 string
	extensionAttribute13 string
	extensionAttribute14 string
	extensionAttribute15 string
	extensionAttribute2 string
	extensionAttribute3 string
	extensionAttribute4 string
	extensionAttribute5 string
	extensionAttribute6 string
	extensionAttribute7 string
	extensionAttribute8 string
	extensionAttribute9 string
}

type OnPremisesProvisioningError struct {
	category string
	occurredDateTime string
	propertyCausingError string
	value string
}

type OnPremisesProvisioningErrorCollectionResponse struct {
	value interface{}
}

type Onenote struct {
	id string
	notebooks interface{}
	operations interface{}
	pages interface{}
	resources interface{}
	sectionGroups interface{}
	sections interface{}
}

type OnenoteEntityBaseModel struct {
	id string
	self string
}

type OnenoteEntityHierarchyModel struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	self string
}

type OnenoteEntitySchemaObjectModel struct {
	createdDateTime string
	id string
	self string
}

type OnenoteOperation struct {
	createdDateTime string
	error interface{}
	id string
	lastActionDateTime string
	percentComplete string
	resourceId string
	resourceLocation string
	status interface{}
}

type OnenoteOperationCollectionResponse struct {
	value interface{}
}

type OnenoteOperationError struct {
	code string
	message string
}

type OnenotePage struct {
	content string
	contentUrl string
	createdByAppId string
	createdDateTime string
	id string
	lastModifiedDateTime string
	level interface{}
	links interface{}
	order interface{}
	parentNotebook interface{}
	parentSection interface{}
	self string
	title string
	userTags interface{}
}

type OnenotePageCollectionResponse struct {
	value interface{}
}

type OnenotePagePreview struct {
	links interface{}
	previewText string
}

type OnenotePagePreviewLinks struct {
	previewImageUrl interface{}
}

type OnenotePatchContentCommand struct {
	action string
	content string
	position interface{}
	target string
}

type OnenoteResource struct {
	content string
	contentUrl string
	id string
	self string
}

type OnenoteResourceCollectionResponse struct {
	value interface{}
}

type OnenoteSection struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	id string
	isDefault interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	links interface{}
	pages interface{}
	pagesUrl string
	parentNotebook interface{}
	parentSectionGroup interface{}
	self string
}

type OnenoteSectionCollectionResponse struct {
	value interface{}
}

type OnlineMeeting struct {
	allowAttendeeToEnableCamera interface{}
	allowAttendeeToEnableMic interface{}
	allowMeetingChat interface{}
	allowTeamworkReactions interface{}
	allowedPresenters interface{}
	attendanceReports interface{}
	attendeeReport string
	audioConferencing interface{}
	broadcastSettings interface{}
	chatInfo interface{}
	creationDateTime string
	endDateTime string
	externalId string
	id string
	isBroadcast interface{}
	isEntryExitAnnounced interface{}
	joinInformation interface{}
	joinWebUrl string
	lobbyBypassSettings interface{}
	participants interface{}
	recordAutomatically interface{}
	startDateTime string
	subject string
	videoTeleconferenceId string
}

type OnlineMeetingCollectionResponse struct {
	value interface{}
}

type OnlineMeetingInfo struct {
	conferenceId string
	joinUrl string
	phones interface{}
	quickDial string
	tollFreeNumbers interface{}
	tollNumber string
}

type OpenShift struct {
	createdDateTime string
	draftOpenShift interface{}
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	schedulingGroupId string
	sharedOpenShift interface{}
}

type OpenShiftChangeRequest struct {
	assignedTo interface{}
	createdDateTime string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	managerActionDateTime string
	managerActionMessage string
	managerUserId string
	openShiftId string
	senderDateTime string
	senderMessage string
	senderUserId string
	state interface{}
}

type OpenShiftChangeRequestCollectionResponse struct {
	value interface{}
}

type OpenShiftCollectionResponse struct {
	value interface{}
}

type OpenShiftItem struct {
	activities interface{}
	displayName string
	endDateTime string
	notes string
	openSlotCount interface{}
	startDateTime string
	theme string
}

type OpenTypeExtension struct {
	extensionName string
	id string
}

type OpenTypeExtensionCollectionResponse struct {
	value interface{}
}

type Operation struct {
	createdDateTime string
	id string
	lastActionDateTime string
	status interface{}
}

type OperationError struct {
	code string
	message string
}

type OptionalClaim struct {
	additionalProperties interface{}
	essential interface{}
	name string
	source string
}

type OptionalClaimCollectionResponse struct {
	value interface{}
}

type OptionalClaims struct {
	accessToken interface{}
	idToken interface{}
	saml2Token interface{}
}

type OrgContact struct {
	addresses interface{}
	companyName string
	deletedDateTime string
	department string
	directReports interface{}
	displayName string
	givenName string
	id string
	jobTitle string
	mail string
	mailNickname string
	manager interface{}
	memberOf interface{}
	onPremisesLastSyncDateTime string
	onPremisesProvisioningErrors interface{}
	onPremisesSyncEnabled interface{}
	phones interface{}
	proxyAddresses interface{}
	surname string
	transitiveMemberOf interface{}
}

type OrgContactCollectionResponse struct {
	value interface{}
}

type Organization struct {
	assignedPlans interface{}
	branding interface{}
	businessPhones interface{}
	certificateBasedAuthConfiguration interface{}
	city string
	country string
	countryLetterCode string
	createdDateTime string
	deletedDateTime string
	displayName string
	extensions interface{}
	id string
	marketingNotificationEmails interface{}
	mobileDeviceManagementAuthority string
	onPremisesLastSyncDateTime string
	onPremisesSyncEnabled interface{}
	postalCode string
	preferredLanguage string
	privacyProfile interface{}
	provisionedPlans interface{}
	securityComplianceNotificationMails interface{}
	securityComplianceNotificationPhones interface{}
	state string
	street string
	technicalNotificationMails interface{}
	tenantType string
	verifiedDomains interface{}
}

type OrganizationCollectionResponse struct {
	value interface{}
}

type OrganizationalBranding struct {
	backgroundColor string
	backgroundImage string
	backgroundImageRelativeUrl string
	bannerLogo string
	bannerLogoRelativeUrl string
	cdnList interface{}
	id string
	localizations interface{}
	signInPageText string
	squareLogo string
	squareLogoRelativeUrl string
	usernameHintText string
}

type OrganizationalBrandingLocalization struct {
	backgroundColor string
	backgroundImage string
	backgroundImageRelativeUrl string
	bannerLogo string
	bannerLogoRelativeUrl string
	cdnList interface{}
	id string
	signInPageText string
	squareLogo string
	squareLogoRelativeUrl string
	usernameHintText string
}

type OrganizationalBrandingLocalizationCollectionResponse struct {
	value interface{}
}

type OrganizationalBrandingProperties struct {
	backgroundColor string
	backgroundImage string
	backgroundImageRelativeUrl string
	bannerLogo string
	bannerLogoRelativeUrl string
	cdnList interface{}
	id string
	signInPageText string
	squareLogo string
	squareLogoRelativeUrl string
	usernameHintText string
}

type OrganizerMeetingInfo struct {
	organizer interface{}
}

type OutgoingCallOptions struct {
	hideBotAfterEscalation interface{}
}

type OutlookCategory struct {
	color interface{}
	displayName string
	id string
}

type OutlookCategoryCollectionResponse struct {
	value interface{}
}

type OutlookGeoCoordinates struct {
	accuracy interface{}
	altitude interface{}
	altitudeAccuracy interface{}
	latitude interface{}
	longitude interface{}
}

type OutlookItem struct {
	categories interface{}
	changeKey string
	createdDateTime string
	id string
	lastModifiedDateTime string
}

type OutlookUser struct {
	id string
	masterCategories interface{}
}

type Package struct {
	type string
}

type PageLinks struct {
	oneNoteClientUrl interface{}
	oneNoteWebUrl interface{}
}

type ParentalControlSettings struct {
	countriesBlockedForMinors interface{}
	legalAgeGroupRule string
}

type Participant struct {
	id string
	info interface{}
	isInLobby interface{}
	isMuted interface{}
	mediaStreams interface{}
	metadata string
	recordingInfo interface{}
}

type ParticipantCollectionResponse struct {
	value interface{}
}

type ParticipantInfo struct {
	countryCode string
	endpointType interface{}
	identity interface{}
	languageId string
	participantId string
	region string
}

type ParticipantJoiningNotification struct {
	call interface{}
	id string
}

type ParticipantLeftNotification struct {
	call interface{}
	id string
	participantId string
}

type PasswordAuthenticationMethod struct {
	createdDateTime string
	id string
	password string
}

type PasswordAuthenticationMethodCollectionResponse struct {
	value interface{}
}

type PasswordCredential struct {
	customKeyIdentifier string
	displayName string
	endDateTime string
	hint string
	keyId string
	secretText string
	startDateTime string
}

type PasswordCredentialCollectionResponse struct {
	value interface{}
}

type PasswordProfile struct {
	forceChangePasswordNextSignIn interface{}
	forceChangePasswordNextSignInWithMfa interface{}
	password string
}

type PasswordResetResponse struct {
	newPassword string
}

type PatternedRecurrence struct {
	pattern interface{}
	range interface{}
}

type PendingContentUpdate struct {
	queuedDateTime string
}

type PendingOperations struct {
	pendingContentUpdate interface{}
}

type Permission struct {
	expirationDateTime string
	grantedTo interface{}
	grantedToIdentities interface{}
	grantedToIdentitiesV2 interface{}
	grantedToV2 interface{}
	hasPassword interface{}
	id string
	inheritedFrom interface{}
	invitation interface{}
	link interface{}
	roles interface{}
	shareId string
}

type PermissionCollectionResponse struct {
	value interface{}
}

type PermissionGrantConditionSet struct {
	clientApplicationIds interface{}
	clientApplicationPublisherIds interface{}
	clientApplicationTenantIds interface{}
	clientApplicationsFromVerifiedPublisherOnly interface{}
	id string
	permissionClassification string
	permissionType interface{}
	permissions interface{}
	resourceApplication string
}

type PermissionGrantConditionSetCollectionResponse struct {
	value interface{}
}

type PermissionGrantPolicy struct {
	deletedDateTime string
	description string
	displayName string
	excludes interface{}
	id string
	includes interface{}
}

type PermissionGrantPolicyCollectionResponse struct {
	value interface{}
}

type PermissionScope struct {
	adminConsentDescription string
	adminConsentDisplayName string
	id string
	isEnabled interface{}
	origin string
	type string
	userConsentDescription string
	userConsentDisplayName string
	value string
}

type PermissionScopeCollectionResponse struct {
	value interface{}
}

type PersistentBrowserSessionControl struct {
	isEnabled interface{}
	mode interface{}
}

type Person struct {
	birthday string
	companyName string
	department string
	displayName string
	givenName string
	id string
	imAddress string
	isFavorite interface{}
	jobTitle string
	officeLocation string
	personNotes string
	personType interface{}
	phones interface{}
	postalAddresses interface{}
	profession string
	scoredEmailAddresses interface{}
	surname string
	userPrincipalName string
	websites interface{}
	yomiCompany string
}

type PersonCollectionResponse struct {
	value interface{}
}

type PersonOrGroupColumn struct {
	allowMultipleSelection interface{}
	chooseFromType string
	displayAs string
}

type PersonType struct {
	class string
	subclass string
}

type Phone struct {
	language string
	number string
	region string
	type interface{}
}

type PhoneAuthenticationMethod struct {
	id string
	phoneNumber string
	phoneType interface{}
	smsSignInState interface{}
}

type PhoneAuthenticationMethodCollectionResponse struct {
	value interface{}
}

type PhoneCollectionResponse struct {
	value interface{}
}

type Photo struct {
	cameraMake string
	cameraModel string
	exposureDenominator interface{}
	exposureNumerator interface{}
	fNumber interface{}
	focalLength interface{}
	iso interface{}
	orientation interface{}
	takenDateTime string
}

type PhysicalAddress struct {
	city string
	countryOrRegion string
	postalCode string
	state string
	street string
}

type PhysicalAddressCollectionResponse struct {
	value interface{}
}

type PhysicalOfficeAddress struct {
	city string
	countryOrRegion string
	officeLocation string
	postalCode string
	state string
	street string
}

type PhysicalOfficeAddressCollectionResponse struct {
	value interface{}
}

type Pkcs12Certificate struct {
	password string
	pkcs12Value string
}

type Pkcs12CertificateInformation struct {
	isActive interface{}
	notAfter interface{}
	notBefore interface{}
	thumbprint string
}

type Pkcs12CertificateInformationCollectionResponse struct {
	value interface{}
}

type Place struct {
	address interface{}
	displayName string
	geoCoordinates interface{}
	id string
	phone string
}

type PlaceCollectionResponse struct {
	value interface{}
}

type Planner struct {
	buckets interface{}
	id string
	plans interface{}
	tasks interface{}
}

type PlannerAssignedToTaskBoardTaskFormat struct {
	id string
	orderHintsByAssignee interface{}
	unassignedOrderHint string
}

type PlannerAssignment struct {
	assignedBy interface{}
	assignedDateTime string
	orderHint string
}

type PlannerBucket struct {
	id string
	name string
	orderHint string
	planId string
	tasks interface{}
}

type PlannerBucketCollectionResponse struct {
	value interface{}
}

type PlannerBucketTaskBoardTaskFormat struct {
	id string
	orderHint string
}

type PlannerCategoryDescriptions struct {
	category1 string
	category10 string
	category11 string
	category12 string
	category13 string
	category14 string
	category15 string
	category16 string
	category17 string
	category18 string
	category19 string
	category2 string
	category20 string
	category21 string
	category22 string
	category23 string
	category24 string
	category25 string
	category3 string
	category4 string
	category5 string
	category6 string
	category7 string
	category8 string
	category9 string
}

type PlannerChecklistItem struct {
	isChecked interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	orderHint string
	title string
}

type PlannerExternalReference struct {
	alias string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	previewPriority string
	type string
}

type PlannerGroup struct {
	id string
	plans interface{}
}

type PlannerPlan struct {
	buckets interface{}
	container interface{}
	createdBy interface{}
	createdDateTime string
	details interface{}
	id string
	owner string
	tasks interface{}
	title string
}

type PlannerPlanCollectionResponse struct {
	value interface{}
}

type PlannerPlanContainer struct {
	containerId string
	type string
	url string
}

type PlannerPlanDetails struct {
	categoryDescriptions interface{}
	id string
	sharedWith interface{}
}

type PlannerProgressTaskBoardTaskFormat struct {
	id string
	orderHint string
}

type PlannerTask struct {
	activeChecklistItemCount interface{}
	appliedCategories interface{}
	assignedToTaskBoardFormat interface{}
	assigneePriority string
	assignments interface{}
	bucketId string
	bucketTaskBoardFormat interface{}
	checklistItemCount interface{}
	completedBy interface{}
	completedDateTime string
	conversationThreadId string
	createdBy interface{}
	createdDateTime string
	details interface{}
	dueDateTime string
	hasDescription interface{}
	id string
	orderHint string
	percentComplete interface{}
	planId string
	previewType interface{}
	priority interface{}
	progressTaskBoardFormat interface{}
	referenceCount interface{}
	startDateTime string
	title string
}

type PlannerTaskCollectionResponse struct {
	value interface{}
}

type PlannerTaskDetails struct {
	checklist interface{}
	description string
	id string
	previewType interface{}
	references interface{}
}

type PlannerUser struct {
	id string
	plans interface{}
	tasks interface{}
}

type PlayPromptOperation struct {
	clientContext string
	id string
	resultInfo interface{}
	status string
}

type PlayPromptOperationCollectionResponse struct {
	value interface{}
}

type PolicyBase struct {
	deletedDateTime string
	description string
	displayName string
	id string
}

type PolicyBaseCollectionResponse struct {
	value interface{}
}

type PolicyRoot struct {
	activityBasedTimeoutPolicies interface{}
	adminConsentRequestPolicy interface{}
	authenticationFlowsPolicy interface{}
	authenticationMethodsPolicy interface{}
	authorizationPolicy interface{}
	claimsMappingPolicies interface{}
	conditionalAccessPolicies interface{}
	crossTenantAccessPolicy interface{}
	featureRolloutPolicies interface{}
	homeRealmDiscoveryPolicies interface{}
	id string
	identitySecurityDefaultsEnforcementPolicy interface{}
	permissionGrantPolicies interface{}
	roleManagementPolicies interface{}
	roleManagementPolicyAssignments interface{}
	tokenIssuancePolicies interface{}
	tokenLifetimePolicies interface{}
}

type Post struct {
	attachments interface{}
	body interface{}
	categories interface{}
	changeKey string
	conversationId string
	conversationThreadId string
	createdDateTime string
	extensions interface{}
	from interface{}
	hasAttachments interface{}
	id string
	inReplyTo interface{}
	lastModifiedDateTime string
	multiValueExtendedProperties interface{}
	newParticipants interface{}
	receivedDateTime string
	sender interface{}
	singleValueExtendedProperties interface{}
}

type PostCollectionResponse struct {
	value interface{}
}

type PreAuthorizedApplication struct {
	appId string
	delegatedPermissionIds interface{}
}

type PreAuthorizedApplicationCollectionResponse struct {
	value interface{}
}

type Presence struct {
	activity string
	availability string
	id string
}

type PresenceCollectionResponse struct {
	value interface{}
}

type PrincipalResourceMembershipsScope struct {
	principalScopes interface{}
	resourceScopes interface{}
}

type Print struct {
	connectors interface{}
	operations interface{}
	printers interface{}
	services interface{}
	settings interface{}
	shares interface{}
	taskDefinitions interface{}
}

type PrintCertificateSigningRequest struct {
	content string
	transportKey string
}

type PrintConnector struct {
	appVersion string
	displayName string
	fullyQualifiedDomainName string
	id string
	location interface{}
	operatingSystem string
	registeredDateTime string
}

type PrintConnectorCollectionResponse struct {
	value interface{}
}

type PrintDocument struct {
	contentType string
	displayName string
	id string
	size interface{}
}

type PrintDocumentCollectionResponse struct {
	value interface{}
}

type PrintDocumentUploadProperties struct {
	contentType string
	documentName string
	size interface{}
}

type PrintJob struct {
	configuration interface{}
	createdBy interface{}
	createdDateTime string
	documents interface{}
	id string
	isFetchable interface{}
	redirectedFrom string
	redirectedTo string
	status interface{}
	tasks interface{}
}

type PrintJobCollectionResponse struct {
	value interface{}
}

type PrintJobConfiguration struct {
	collate interface{}
	colorMode interface{}
	copies interface{}
	dpi interface{}
	duplexMode interface{}
	feedOrientation interface{}
	finishings interface{}
	fitPdfToPage interface{}
	inputBin string
	margin interface{}
	mediaSize string
	mediaType string
	multipageLayout interface{}
	orientation interface{}
	outputBin string
	pageRanges interface{}
	pagesPerSheet interface{}
	quality interface{}
	scaling interface{}
}

type PrintJobStatus struct {
	description string
	details interface{}
	isAcquiredByPrinter interface{}
	state string
}

type PrintMargin struct {
	bottom interface{}
	left interface{}
	right interface{}
	top interface{}
}

type PrintOperation struct {
	createdDateTime string
	id string
	status interface{}
}

type PrintOperationCollectionResponse struct {
	value interface{}
}

type PrintOperationStatus struct {
	description string
	state string
}

type PrintService struct {
	endpoints interface{}
	id string
}

type PrintServiceCollectionResponse struct {
	value interface{}
}

type PrintServiceEndpoint struct {
	displayName string
	id string
	uri string
}

type PrintServiceEndpointCollectionResponse struct {
	value interface{}
}

type PrintSettings struct {
	documentConversionEnabled interface{}
}

type PrintTask struct {
	definition interface{}
	id string
	parentUrl string
	status interface{}
	trigger interface{}
}

type PrintTaskCollectionResponse struct {
	value interface{}
}

type PrintTaskDefinition struct {
	createdBy interface{}
	displayName string
	id string
	tasks interface{}
}

type PrintTaskDefinitionCollectionResponse struct {
	value interface{}
}

type PrintTaskStatus struct {
	description string
	state string
}

type PrintTaskTrigger struct {
	definition interface{}
	event string
	id string
}

type PrintTaskTriggerCollectionResponse struct {
	value interface{}
}

type PrintUsage struct {
	completedBlackAndWhiteJobCount interface{}
	completedColorJobCount interface{}
	id string
	incompleteJobCount interface{}
	usageDate string
}

type PrintUsageByPrinter struct {
	completedBlackAndWhiteJobCount interface{}
	completedColorJobCount interface{}
	id string
	incompleteJobCount interface{}
	printerId string
	usageDate string
}

type PrintUsageByPrinterCollectionResponse struct {
	value interface{}
}

type PrintUsageByUser struct {
	completedBlackAndWhiteJobCount interface{}
	completedColorJobCount interface{}
	id string
	incompleteJobCount interface{}
	usageDate string
	userPrincipalName string
}

type PrintUsageByUserCollectionResponse struct {
	value interface{}
}

type Printer struct {
	capabilities interface{}
	connectors interface{}
	defaults interface{}
	displayName string
	hasPhysicalDevice interface{}
	id string
	isAcceptingJobs interface{}
	isShared interface{}
	jobs interface{}
	lastSeenDateTime string
	location interface{}
	manufacturer string
	model string
	registeredDateTime string
	shares interface{}
	status interface{}
	taskTriggers interface{}
}

type PrinterBase struct {
	capabilities interface{}
	defaults interface{}
	displayName string
	id string
	isAcceptingJobs interface{}
	jobs interface{}
	location interface{}
	manufacturer string
	model string
	status interface{}
}

type PrinterCapabilities struct {
	bottomMargins interface{}
	collation interface{}
	colorModes interface{}
	contentTypes interface{}
	copiesPerJob interface{}
	dpis interface{}
	duplexModes interface{}
	feedOrientations interface{}
	finishings interface{}
	inputBins interface{}
	isColorPrintingSupported interface{}
	isPageRangeSupported interface{}
	leftMargins interface{}
	mediaColors interface{}
	mediaSizes interface{}
	mediaTypes interface{}
	multipageLayouts interface{}
	orientations interface{}
	outputBins interface{}
	pagesPerSheet interface{}
	qualities interface{}
	rightMargins interface{}
	scalings interface{}
	supportsFitPdfToPage interface{}
	topMargins interface{}
}

type PrinterCollectionResponse struct {
	value interface{}
}

type PrinterCreateOperation struct {
	certificate string
	createdDateTime string
	id string
	printer interface{}
	status interface{}
}

type PrinterCreateOperationCollectionResponse struct {
	value interface{}
}

type PrinterDefaults struct {
	colorMode interface{}
	contentType string
	copiesPerJob interface{}
	dpi interface{}
	duplexMode interface{}
	finishings interface{}
	fitPdfToPage interface{}
	inputBin string
	mediaColor string
	mediaSize string
	mediaType string
	multipageLayout interface{}
	orientation interface{}
	outputBin string
	pagesPerSheet interface{}
	quality interface{}
	scaling interface{}
}

type PrinterLocation struct {
	altitudeInMeters interface{}
	building string
	city string
	countryOrRegion string
	floor string
	floorDescription string
	latitude interface{}
	longitude interface{}
	organization interface{}
	postalCode string
	roomDescription string
	roomName string
	site string
	stateOrProvince string
	streetAddress string
	subdivision interface{}
	subunit interface{}
}

type PrinterShare struct {
	allowAllUsers interface{}
	allowedGroups interface{}
	allowedUsers interface{}
	capabilities interface{}
	createdDateTime string
	defaults interface{}
	displayName string
	id string
	isAcceptingJobs interface{}
	jobs interface{}
	location interface{}
	manufacturer string
	model string
	printer interface{}
	status interface{}
}

type PrinterShareCollectionResponse struct {
	value interface{}
}

type PrinterStatus struct {
	description string
	details interface{}
	state string
}

type Privacy struct {
	subjectRightsRequests interface{}
}

type PrivacyProfile struct {
	contactEmail string
	statementUrl string
}

type Process struct {
	accountName string
	commandLine string
	createdDateTime string
	fileHash interface{}
	integrityLevel interface{}
	isElevated interface{}
	name string
	parentProcessCreatedDateTime string
	parentProcessId interface{}
	parentProcessName string
	path string
	processId interface{}
}

type ProcessCollectionResponse struct {
	value interface{}
}

type ProfilePhoto struct {
	height interface{}
	id string
	width interface{}
}

type ProfilePhotoCollectionResponse struct {
	value interface{}
}

type ProvisionChannelEmailResult struct {
	email string
}

type ProvisionedIdentity struct {
	details interface{}
	displayName string
	id string
	identityType string
}

type ProvisionedPlan struct {
	capabilityStatus string
	provisioningStatus string
	service string
}

type ProvisionedPlanCollectionResponse struct {
	value interface{}
}

type ProvisioningErrorInfo struct {
	additionalDetails string
	errorCategory interface{}
	errorCode string
	reason string
	recommendedAction string
}

type ProvisioningObjectSummary struct {
	activityDateTime string
	changeId string
	cycleId string
	durationInMilliseconds interface{}
	id string
	initiatedBy interface{}
	jobId string
	modifiedProperties interface{}
	provisioningAction interface{}
	provisioningStatusInfo interface{}
	provisioningSteps interface{}
	servicePrincipal interface{}
	sourceIdentity interface{}
	sourceSystem interface{}
	targetIdentity interface{}
	targetSystem interface{}
	tenantId string
}

type ProvisioningObjectSummaryCollectionResponse struct {
	value interface{}
}

type ProvisioningServicePrincipal struct {
	displayName string
	id string
}

type ProvisioningStatusInfo struct {
	errorInformation interface{}
	status interface{}
}

type ProvisioningStep struct {
	description string
	details interface{}
	name string
	provisioningStepType interface{}
	status interface{}
}

type ProvisioningStepCollectionResponse struct {
	value interface{}
}

type ProvisioningSystem struct {
	details interface{}
	displayName string
	id string
}

type ProxiedDomain struct {
	ipAddressOrFQDN string
	proxy string
}

type ProxiedDomainCollectionResponse struct {
	value interface{}
}

type PublicClientApplication struct {
	redirectUris interface{}
}

type PublicError struct {
	code string
	details interface{}
	innerError interface{}
	message string
	target string
}

type PublicErrorDetail struct {
	code string
	message string
	target string
}

type PublicErrorDetailCollectionResponse struct {
	value interface{}
}

type PublicInnerError struct {
	code string
	details interface{}
	message string
	target string
}

type PublicationFacet struct {
	level string
	versionId string
}

type Quota struct {
	deleted interface{}
	remaining interface{}
	state string
	storagePlanInformation interface{}
	total interface{}
	used interface{}
}

type RbacApplication struct {
	id string
	roleAssignmentScheduleInstances interface{}
	roleAssignmentScheduleRequests interface{}
	roleAssignmentSchedules interface{}
	roleAssignments interface{}
	roleDefinitions interface{}
	roleEligibilityScheduleInstances interface{}
	roleEligibilityScheduleRequests interface{}
	roleEligibilitySchedules interface{}
}

type RecentNotebook struct {
	displayName string
	lastAccessedTime string
	links interface{}
	sourceService interface{}
}

type RecentNotebookLinks struct {
	oneNoteClientUrl interface{}
	oneNoteWebUrl interface{}
}

type Recipient struct {
	emailAddress interface{}
}

type RecipientCollectionResponse struct {
	value interface{}
}

type RecordOperation struct {
	clientContext string
	id string
	recordingAccessToken string
	recordingLocation string
	resultInfo interface{}
	status string
}

type RecordOperationCollectionResponse struct {
	value interface{}
}

type RecordingInfo struct {
	initiator interface{}
	recordingStatus string
}

type RecurrencePattern struct {
	dayOfMonth interface{}
	daysOfWeek interface{}
	firstDayOfWeek interface{}
	index interface{}
	interval interface{}
	month interface{}
	type interface{}
}

type RecurrenceRange struct {
	endDate string
	numberOfOccurrences interface{}
	recurrenceTimeZone string
	startDate string
	type interface{}
}

type RedundancyDetectionSettings struct {
	isEnabled interface{}
	maxWords interface{}
	minWords interface{}
	similarityThreshold interface{}
}

type ReferenceAttachment struct {
	contentType string
	id string
	isInline interface{}
	lastModifiedDateTime string
	name string
	size interface{}
}

type ReferenceAttachmentCollectionResponse struct {
	value interface{}
}

type RegistrationEnforcement struct {
	authenticationMethodsRegistrationCampaign interface{}
}

type RegistryKeyState struct {
	hive interface{}
	key string
	oldKey string
	oldValueData string
	oldValueName string
	operation interface{}
	processId interface{}
	valueData string
	valueName string
	valueType interface{}
}

type RegistryKeyStateCollectionResponse struct {
	value interface{}
}

type RejectJoinResponse struct {
	reason string
}

type RelatedContact struct {
	accessConsent interface{}
	displayName string
	emailAddress string
	mobilePhone string
	relationship string
}

type RelatedContactCollectionResponse struct {
	value interface{}
}

type Reminder struct {
	changeKey string
	eventEndTime interface{}
	eventId string
	eventLocation interface{}
	eventStartTime interface{}
	eventSubject string
	eventWebLink string
	reminderFireTime interface{}
}

type RemoteAssistancePartner struct {
	displayName string
	id string
	lastConnectionDateTime string
	onboardingStatus string
	onboardingUrl string
}

type RemoteAssistancePartnerCollectionResponse struct {
	value interface{}
}

type RemoteItem struct {
	createdBy interface{}
	createdDateTime string
	file interface{}
	fileSystemInfo interface{}
	folder interface{}
	id string
	image interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	name string
	package interface{}
	parentReference interface{}
	shared interface{}
	sharepointIds interface{}
	size interface{}
	specialFolder interface{}
	video interface{}
	webDavUrl string
	webUrl string
}

type RemoteLockActionResult struct {
	actionName string
	actionState string
	lastUpdatedDateTime string
	startDateTime string
	unlockPin string
}

type Report struct {
	content string
}

type ReportRoot struct {
	dailyPrintUsageByPrinter interface{}
	dailyPrintUsageByUser interface{}
	id string
	monthlyPrintUsageByPrinter interface{}
	monthlyPrintUsageByUser interface{}
}

type Request struct {
	approvalId string
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	customData string
	id string
	status string
}

type RequestSchedule struct {
	expiration interface{}
	recurrence interface{}
	startDateTime string
}

type RequestorManager struct {
	managerLevel interface{}
}

type RequiredResourceAccess struct {
	resourceAccess interface{}
	resourceAppId string
}

type RequiredResourceAccessCollectionResponse struct {
	value interface{}
}

type ResetPasscodeActionResult struct {
	actionName string
	actionState string
	lastUpdatedDateTime string
	passcode string
	startDateTime string
}

type ResourceAccess struct {
	id string
	type string
}

type ResourceAccessCollectionResponse struct {
	value interface{}
}

type ResourceAction struct {
	allowedResourceActions interface{}
	notAllowedResourceActions interface{}
}

type ResourceActionCollectionResponse struct {
	value interface{}
}

type ResourceOperation struct {
	actionName string
	description string
	id string
	resourceName string
}

type ResourceOperationCollectionResponse struct {
	value interface{}
}

type ResourcePermission struct {
	type string
	value string
}

type ResourcePermissionCollectionResponse struct {
	value interface{}
}

type ResourceReference struct {
	id string
	type string
	webUrl string
}

type ResourceSpecificPermission struct {
	description string
	displayName string
	id string
	isEnabled interface{}
	value string
}

type ResourceSpecificPermissionCollectionResponse struct {
	value interface{}
}

type ResourceSpecificPermissionGrant struct {
	clientAppId string
	clientId string
	deletedDateTime string
	id string
	permission string
	permissionType string
	resourceAppId string
}

type ResourceSpecificPermissionGrantCollectionResponse struct {
	value interface{}
}

type ResourceVisualization struct {
	containerDisplayName string
	containerType string
	containerWebUrl string
	mediaType string
	previewImageUrl string
	previewText string
	title string
	type string
}

type ResponseStatus struct {
	response interface{}
	time string
}

type RestrictedSignIn struct {
	appDisplayName string
	appId string
	appliedConditionalAccessPolicies interface{}
	clientAppUsed string
	conditionalAccessStatus interface{}
	correlationId string
	createdDateTime string
	deviceDetail interface{}
	id string
	ipAddress string
	isInteractive interface{}
	location interface{}
	resourceDisplayName string
	resourceId string
	riskDetail interface{}
	riskEventTypes interface{}
	riskEventTypes_v2 interface{}
	riskLevelAggregated interface{}
	riskLevelDuringSignIn interface{}
	riskState interface{}
	status interface{}
	targetTenantId string
	userDisplayName string
	userId string
	userPrincipalName string
}

type RestrictedSignInCollectionResponse struct {
	value interface{}
}

type ResultInfo struct {
	code interface{}
	message string
	subcode interface{}
}

type ResultTemplate struct {
	body interface{}
	displayName string
}

type ResultTemplateOption struct {
	enableResultTemplate interface{}
}

type RgbColor struct {
	b interface{}
	g interface{}
	r interface{}
}

type RichLongRunningOperation struct {
	createdDateTime string
	error interface{}
	id string
	lastActionDateTime string
	percentageComplete interface{}
	resourceId string
	resourceLocation string
	status interface{}
	statusDetail string
	type string
}

type RichLongRunningOperationCollectionResponse struct {
	value interface{}
}

type RiskDetection struct {
	activity interface{}
	activityDateTime string
	additionalInfo string
	correlationId string
	detectedDateTime string
	detectionTimingType interface{}
	id string
	ipAddress string
	lastUpdatedDateTime string
	location interface{}
	requestId string
	riskDetail interface{}
	riskEventType string
	riskLevel interface{}
	riskState interface{}
	source string
	tokenIssuerType interface{}
	userDisplayName string
	userId string
	userPrincipalName string
}

type RiskDetectionCollectionResponse struct {
	value interface{}
}

type RiskUserActivity struct {
	detail interface{}
	riskEventTypes interface{}
}

type RiskyUser struct {
	history interface{}
	id string
	isDeleted interface{}
	isProcessing interface{}
	riskDetail interface{}
	riskLastUpdatedDateTime string
	riskLevel interface{}
	riskState interface{}
	userDisplayName string
	userPrincipalName string
}

type RiskyUserCollectionResponse struct {
	value interface{}
}

type RiskyUserHistoryItem struct {
	activity interface{}
	history interface{}
	id string
	initiatedBy string
	isDeleted interface{}
	isProcessing interface{}
	riskDetail interface{}
	riskLastUpdatedDateTime string
	riskLevel interface{}
	riskState interface{}
	userDisplayName string
	userId string
	userPrincipalName string
}

type RiskyUserHistoryItemCollectionResponse struct {
	value interface{}
}

type RoleAssignment struct {
	description string
	displayName string
	id string
	resourceScopes interface{}
	roleDefinition interface{}
}

type RoleAssignmentCollectionResponse struct {
	value interface{}
}

type RoleDefinition struct {
	description string
	displayName string
	id string
	isBuiltIn interface{}
	roleAssignments interface{}
	rolePermissions interface{}
}

type RoleDefinitionCollectionResponse struct {
	value interface{}
}

type RoleManagement struct {
	directory interface{}
	entitlementManagement interface{}
}

type RolePermission struct {
	resourceActions interface{}
}

type RolePermissionCollectionResponse struct {
	value interface{}
}

type Room struct {
	address interface{}
	audioDeviceName string
	bookingType interface{}
	building string
	capacity interface{}
	displayDeviceName string
	displayName string
	emailAddress string
	floorLabel string
	floorNumber interface{}
	geoCoordinates interface{}
	id string
	isWheelChairAccessible interface{}
	label string
	nickname string
	phone string
	tags interface{}
	videoDeviceName string
}

type RoomCollectionResponse struct {
	value interface{}
}

type RoomList struct {
	address interface{}
	displayName string
	emailAddress string
	geoCoordinates interface{}
	id string
	phone string
	rooms interface{}
}

type RoomListCollectionResponse struct {
	value interface{}
}

type RubricCriterion struct {
	description interface{}
}

type RubricCriterionCollectionResponse struct {
	value interface{}
}

type RubricLevel struct {
	description interface{}
	displayName string
	grading interface{}
	levelId string
}

type RubricLevelCollectionResponse struct {
	value interface{}
}

type RubricQuality struct {
	criteria interface{}
	description interface{}
	displayName string
	qualityId string
	weight interface{}
}

type RubricQualityCollectionResponse struct {
	value interface{}
}

type RubricQualityFeedbackModel struct {
	feedback interface{}
	qualityId string
}

type RubricQualityFeedbackModelCollectionResponse struct {
	value interface{}
}

type RubricQualitySelectedColumnModel struct {
	columnId string
	qualityId string
}

type RubricQualitySelectedColumnModelCollectionResponse struct {
	value interface{}
}

type SamlOrWsFedExternalDomainFederation struct {
	displayName string
	domains interface{}
	id string
	issuerUri string
	metadataExchangeUri string
	passiveSignInUri string
	preferredAuthenticationProtocol interface{}
	signingCertificate string
}

type SamlOrWsFedExternalDomainFederationCollectionResponse struct {
	value interface{}
}

type SamlOrWsFedProvider struct {
	displayName string
	id string
	issuerUri string
	metadataExchangeUri string
	passiveSignInUri string
	preferredAuthenticationProtocol interface{}
	signingCertificate string
}

type SamlOrWsFedProviderCollectionResponse struct {
	value interface{}
}

type SamlSingleSignOnSettings struct {
	relayState string
}

type Schedule struct {
	enabled interface{}
	id string
	offerShiftRequests interface{}
	offerShiftRequestsEnabled interface{}
	openShiftChangeRequests interface{}
	openShifts interface{}
	openShiftsEnabled interface{}
	provisionStatus interface{}
	provisionStatusCode string
	schedulingGroups interface{}
	shifts interface{}
	swapShiftsChangeRequests interface{}
	swapShiftsRequestsEnabled interface{}
	timeClockEnabled interface{}
	timeOffReasons interface{}
	timeOffRequests interface{}
	timeOffRequestsEnabled interface{}
	timeZone string
	timesOff interface{}
	workforceIntegrationIds interface{}
}

type ScheduleChangeRequest struct {
	assignedTo interface{}
	createdDateTime string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	managerActionDateTime string
	managerActionMessage string
	managerUserId string
	senderDateTime string
	senderMessage string
	senderUserId string
	state interface{}
}

type ScheduleEntity struct {
	endDateTime string
	startDateTime string
	theme string
}

type ScheduleInformation struct {
	availabilityView string
	error interface{}
	scheduleId string
	scheduleItems interface{}
	workingHours interface{}
}

type ScheduleItem struct {
	end interface{}
	isPrivate interface{}
	location string
	start interface{}
	status interface{}
	subject string
}

type ScheduleItemCollectionResponse struct {
	value interface{}
}

type SchedulingGroup struct {
	createdDateTime string
	displayName string
	id string
	isActive interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	userIds interface{}
}

type SchedulingGroupCollectionResponse struct {
	value interface{}
}

type Schema struct {
	baseType string
	id string
	properties interface{}
}

type SchemaExtension struct {
	description string
	id string
	owner string
	properties interface{}
	status string
	targetTypes interface{}
}

type SchemaExtensionCollectionResponse struct {
	value interface{}
}

type ScopedRoleMembership struct {
	administrativeUnitId string
	id string
	roleId string
	roleMemberInfo interface{}
}

type ScopedRoleMembershipCollectionResponse struct {
	value interface{}
}

type ScoredEmailAddress struct {
	address string
	itemId string
	relevanceScore interface{}
	selectionLikelihood interface{}
}

type ScoredEmailAddressCollectionResponse struct {
	value interface{}
}

type SearchAggregation struct {
	buckets interface{}
	field string
}

type SearchAggregationCollectionResponse struct {
	value interface{}
}

type SearchAlteration struct {
	alteredHighlightedQueryString string
	alteredQueryString string
	alteredQueryTokens interface{}
}

type SearchAlterationOptions struct {
	enableModification interface{}
	enableSuggestion interface{}
}

type SearchBucket struct {
	aggregationFilterToken string
	count interface{}
	key string
}

type SearchBucketCollectionResponse struct {
	value interface{}
}

type SearchEntity struct {
	id string
}

type SearchHit struct {
	contentSource string
	hitId string
	rank interface{}
	resource interface{}
	resultTemplateId string
	summary string
}

type SearchHitCollectionResponse struct {
	value interface{}
}

type SearchHitsContainer struct {
	aggregations interface{}
	hits interface{}
	moreResultsAvailable interface{}
	total interface{}
}

type SearchHitsContainerCollectionResponse struct {
	value interface{}
}

type SearchQuery struct {
	queryString string
}

type SearchRequest struct {
	aggregationFilters interface{}
	aggregations interface{}
	contentSources interface{}
	enableTopResults interface{}
	entityTypes interface{}
	fields interface{}
	from interface{}
	query interface{}
	queryAlterationOptions interface{}
	resultTemplateOptions interface{}
	size interface{}
	sortProperties interface{}
}

type SearchResponse struct {
	hitsContainers interface{}
	queryAlterationResponse interface{}
	resultTemplates interface{}
	searchTerms interface{}
}

type SearchResult struct {
	onClickTelemetryUrl string
}

type SectionGroup struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	parentNotebook interface{}
	parentSectionGroup interface{}
	sectionGroups interface{}
	sectionGroupsUrl string
	sections interface{}
	sectionsUrl string
	self string
}

type SectionGroupCollectionResponse struct {
	value interface{}
}

type SectionLinks struct {
	oneNoteClientUrl interface{}
	oneNoteWebUrl interface{}
}

type SecureScore struct {
	activeUserCount interface{}
	averageComparativeScores interface{}
	azureTenantId string
	controlScores interface{}
	createdDateTime string
	currentScore interface{}
	enabledServices interface{}
	id string
	licensedUserCount interface{}
	maxScore interface{}
	vendorInformation interface{}
}

type SecureScoreCollectionResponse struct {
	value interface{}
}

type SecureScoreControlProfile struct {
	actionType string
	actionUrl string
	azureTenantId string
	complianceInformation interface{}
	controlCategory string
	controlStateUpdates interface{}
	deprecated interface{}
	id string
	implementationCost string
	lastModifiedDateTime string
	maxScore interface{}
	rank interface{}
	remediation string
	remediationImpact string
	service string
	threats interface{}
	tier string
	title string
	userImpact string
	vendorInformation interface{}
}

type SecureScoreControlProfileCollectionResponse struct {
	value interface{}
}

type SecureScoreControlStateUpdate struct {
	assignedTo string
	comment string
	state string
	updatedBy string
	updatedDateTime string
}

type SecureScoreControlStateUpdateCollectionResponse struct {
	value interface{}
}

type Security struct {
	alerts interface{}
	cases interface{}
	id string
	secureScoreControlProfiles interface{}
	secureScores interface{}
}

type SecurityCase struct {
	createdDateTime string
	description string
	displayName string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	status interface{}
}

type SecurityCaseOperation struct {
	action interface{}
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	id string
	percentProgress interface{}
	resultInfo interface{}
	status interface{}
}

type SecurityCaseOperationCollectionResponse struct {
	value interface{}
}

type SecurityCasesRoot struct {
	ediscoveryCases interface{}
	id string
}

type SecurityDataSet struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	id string
}

type SecurityDataSource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	holdStatus interface{}
	id string
}

type SecurityDataSourceCollectionResponse struct {
	value interface{}
}

type SecurityDataSourceContainer struct {
	createdDateTime string
	displayName string
	holdStatus interface{}
	id string
	lastModifiedDateTime string
	releasedDateTime string
	status interface{}
}

type SecurityEdiscoveryAddToReviewSetOperation struct {
	action interface{}
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	id string
	percentProgress interface{}
	resultInfo interface{}
	reviewSet interface{}
	search interface{}
	status interface{}
}

type SecurityEdiscoveryAddToReviewSetOperationCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoveryCase struct {
	closedBy interface{}
	closedDateTime string
	createdDateTime string
	custodians interface{}
	description string
	displayName string
	externalId string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	noncustodialDataSources interface{}
	operations interface{}
	reviewSets interface{}
	searches interface{}
	settings interface{}
	status interface{}
	tags interface{}
}

type SecurityEdiscoveryCaseCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoveryCaseSettings struct {
	id string
	ocr interface{}
	redundancyDetection interface{}
	topicModeling interface{}
}

type SecurityEdiscoveryCustodian struct {
	acknowledgedDateTime string
	createdDateTime string
	displayName string
	email string
	holdStatus interface{}
	id string
	lastIndexOperation interface{}
	lastModifiedDateTime string
	releasedDateTime string
	siteSources interface{}
	status interface{}
	unifiedGroupSources interface{}
	userSources interface{}
}

type SecurityEdiscoveryCustodianCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoveryEstimateOperation struct {
	action interface{}
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	id string
	indexedItemCount interface{}
	indexedItemsSize interface{}
	mailboxCount interface{}
	percentProgress interface{}
	resultInfo interface{}
	search interface{}
	siteCount interface{}
	status interface{}
	unindexedItemCount interface{}
	unindexedItemsSize interface{}
}

type SecurityEdiscoveryEstimateOperationCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoveryHoldOperation struct {
	action interface{}
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	id string
	percentProgress interface{}
	resultInfo interface{}
	status interface{}
}

type SecurityEdiscoveryHoldOperationCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoveryIndexOperation struct {
	action interface{}
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	id string
	percentProgress interface{}
	resultInfo interface{}
	status interface{}
}

type SecurityEdiscoveryIndexOperationCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoveryNoncustodialDataSource struct {
	createdDateTime string
	dataSource interface{}
	displayName string
	holdStatus interface{}
	id string
	lastIndexOperation interface{}
	lastModifiedDateTime string
	releasedDateTime string
	status interface{}
}

type SecurityEdiscoveryNoncustodialDataSourceCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoveryReviewSet struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	id string
	queries interface{}
}

type SecurityEdiscoveryReviewSetCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoveryReviewSetQuery struct {
	contentQuery string
	createdBy interface{}
	createdDateTime string
	description string
	displayName string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type SecurityEdiscoveryReviewSetQueryCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoveryReviewTag struct {
	childSelectability interface{}
	childTags interface{}
	createdBy interface{}
	description string
	displayName string
	id string
	lastModifiedDateTime string
	parent interface{}
}

type SecurityEdiscoveryReviewTagCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoverySearch struct {
	addToReviewSetOperation interface{}
	additionalSources interface{}
	contentQuery string
	createdBy interface{}
	createdDateTime string
	custodianSources interface{}
	dataSourceScopes interface{}
	description string
	displayName string
	id string
	lastEstimateStatisticsOperation interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	noncustodialSources interface{}
}

type SecurityEdiscoverySearchCollectionResponse struct {
	value interface{}
}

type SecurityEdiscoveryTagOperation struct {
	action interface{}
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	id string
	percentProgress interface{}
	resultInfo interface{}
	status interface{}
}

type SecurityEdiscoveryTagOperationCollectionResponse struct {
	value interface{}
}

type SecurityOcrSettings struct {
	isEnabled interface{}
	maxImageSize interface{}
	timeout string
}

type SecurityRedundancyDetectionSettings struct {
	isEnabled interface{}
	maxWords interface{}
	minWords interface{}
	similarityThreshold interface{}
}

type SecurityResource struct {
	resource string
	resourceType interface{}
}

type SecurityResourceCollectionResponse struct {
	value interface{}
}

type SecuritySearch struct {
	contentQuery string
	createdBy interface{}
	createdDateTime string
	description string
	displayName string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type SecuritySiteSource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	holdStatus interface{}
	id string
	site interface{}
}

type SecuritySiteSourceCollectionResponse struct {
	value interface{}
}

type SecurityTag struct {
	createdBy interface{}
	description string
	displayName string
	id string
	lastModifiedDateTime string
}

type SecurityTopicModelingSettings struct {
	dynamicallyAdjustTopicCount interface{}
	ignoreNumbers interface{}
	isEnabled interface{}
	topicCount interface{}
}

type SecurityUnifiedGroupSource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	group interface{}
	holdStatus interface{}
	id string
	includedSources interface{}
}

type SecurityUnifiedGroupSourceCollectionResponse struct {
	value interface{}
}

type SecurityUserSource struct {
	createdBy interface{}
	createdDateTime string
	displayName string
	email string
	holdStatus interface{}
	id string
	includedSources interface{}
	siteWebUrl string
}

type SecurityUserSourceCollectionResponse struct {
	value interface{}
}

type SecurityVendorInformation struct {
	provider string
	providerVersion string
	subProvider string
	vendor string
}

type SelfServiceSignUpAuthenticationFlowConfiguration struct {
	isEnabled interface{}
}

type SelfSignedCertificate struct {
	customKeyIdentifier string
	displayName string
	endDateTime string
	key string
	keyId string
	startDateTime string
	thumbprint string
	type string
	usage string
}

type ServiceAnnouncement struct {
	healthOverviews interface{}
	id string
	issues interface{}
	messages interface{}
}

type ServiceAnnouncementAttachment struct {
	content string
	contentType string
	id string
	lastModifiedDateTime string
	name string
	size interface{}
}

type ServiceAnnouncementAttachmentCollectionResponse struct {
	value interface{}
}

type ServiceAnnouncementBase struct {
	details interface{}
	endDateTime string
	id string
	lastModifiedDateTime string
	startDateTime string
	title string
}

type ServiceHealth struct {
	id string
	issues interface{}
	service string
	status string
}

type ServiceHealthCollectionResponse struct {
	value interface{}
}

type ServiceHealthIssue struct {
	classification string
	details interface{}
	endDateTime string
	feature string
	featureGroup string
	id string
	impactDescription string
	isResolved interface{}
	lastModifiedDateTime string
	origin string
	posts interface{}
	service string
	startDateTime string
	status string
	title string
}

type ServiceHealthIssueCollectionResponse struct {
	value interface{}
}

type ServiceHealthIssuePost struct {
	createdDateTime string
	description interface{}
	postType interface{}
}

type ServiceHealthIssuePostCollectionResponse struct {
	value interface{}
}

type ServiceHostedMediaConfig struct {
	preFetchMedia interface{}
}

type ServicePlanInfo struct {
	appliesTo string
	provisioningStatus string
	servicePlanId string
	servicePlanName string
}

type ServicePlanInfoCollectionResponse struct {
	value interface{}
}

type ServicePrincipal struct {
	accountEnabled interface{}
	addIns interface{}
	alternativeNames interface{}
	appDescription string
	appDisplayName string
	appId string
	appOwnerOrganizationId string
	appRoleAssignedTo interface{}
	appRoleAssignmentRequired interface{}
	appRoleAssignments interface{}
	appRoles interface{}
	applicationTemplateId string
	claimsMappingPolicies interface{}
	createdObjects interface{}
	delegatedPermissionClassifications interface{}
	deletedDateTime string
	description string
	disabledByMicrosoftStatus string
	displayName string
	endpoints interface{}
	federatedIdentityCredentials interface{}
	homeRealmDiscoveryPolicies interface{}
	homepage string
	id string
	info interface{}
	keyCredentials interface{}
	loginUrl string
	logoutUrl string
	memberOf interface{}
	notes string
	notificationEmailAddresses interface{}
	oauth2PermissionGrants interface{}
	oauth2PermissionScopes interface{}
	ownedObjects interface{}
	owners interface{}
	passwordCredentials interface{}
	preferredSingleSignOnMode string
	preferredTokenSigningKeyThumbprint string
	replyUrls interface{}
	resourceSpecificApplicationPermissions interface{}
	samlSingleSignOnSettings interface{}
	servicePrincipalNames interface{}
	servicePrincipalType string
	signInAudience string
	tags interface{}
	tokenEncryptionKeyId string
	tokenIssuancePolicies interface{}
	tokenLifetimePolicies interface{}
	transitiveMemberOf interface{}
	verifiedPublisher interface{}
}

type ServicePrincipalCollectionResponse struct {
	value interface{}
}

type ServicePrincipalIdentity struct {
	appId string
	displayName string
	id string
}

type ServiceUpdateMessage struct {
	actionRequiredByDateTime string
	attachments interface{}
	attachmentsArchive string
	body interface{}
	category string
	details interface{}
	endDateTime string
	hasAttachments interface{}
	id string
	isMajorChange interface{}
	lastModifiedDateTime string
	services interface{}
	severity string
	startDateTime string
	tags interface{}
	title string
	viewPoint interface{}
}

type ServiceUpdateMessageCollectionResponse struct {
	value interface{}
}

type ServiceUpdateMessageViewpoint struct {
	isArchived interface{}
	isFavorited interface{}
	isRead interface{}
}

type Set struct {
	children interface{}
	createdDateTime string
	description string
	id string
	localizedNames interface{}
	parentGroup interface{}
	properties interface{}
	relations interface{}
	terms interface{}
}

type SettingSource struct {
	displayName string
	id string
	sourceType string
}

type SettingSourceCollectionResponse struct {
	value interface{}
}

type SettingStateDeviceSummary struct {
	compliantDeviceCount interface{}
	conflictDeviceCount interface{}
	errorDeviceCount interface{}
	id string
	instancePath string
	nonCompliantDeviceCount interface{}
	notApplicableDeviceCount interface{}
	remediatedDeviceCount interface{}
	settingName string
	unknownDeviceCount interface{}
}

type SettingStateDeviceSummaryCollectionResponse struct {
	value interface{}
}

type SettingTemplateValue struct {
	defaultValue string
	description string
	name string
	type string
}

type SettingTemplateValueCollectionResponse struct {
	value interface{}
}

type SettingValue struct {
	name string
	value string
}

type SettingValueCollectionResponse struct {
	value interface{}
}

type SharePointIdentity struct {
	displayName string
	id string
	loginName string
}

type SharePointIdentitySet struct {
	application interface{}
	device interface{}
	group interface{}
	siteGroup interface{}
	siteUser interface{}
	user interface{}
}

type SharePointIdentitySetCollectionResponse struct {
	value interface{}
}

type Shared struct {
	owner interface{}
	scope string
	sharedBy interface{}
	sharedDateTime string
}

type SharedDriveItem struct {
	createdBy interface{}
	createdByUser interface{}
	createdDateTime string
	description string
	driveItem interface{}
	eTag string
	id string
	items interface{}
	lastModifiedBy interface{}
	lastModifiedByUser interface{}
	lastModifiedDateTime string
	list interface{}
	listItem interface{}
	name string
	owner interface{}
	parentReference interface{}
	permission interface{}
	root interface{}
	site interface{}
	webUrl string
}

type SharedDriveItemCollectionResponse struct {
	value interface{}
}

type SharedInsight struct {
	id string
	lastShared interface{}
	lastSharedMethod interface{}
	resource interface{}
	resourceReference interface{}
	resourceVisualization interface{}
	sharingHistory interface{}
}

type SharedInsightCollectionResponse struct {
	value interface{}
}

type SharedPCAccountManagerPolicy struct {
	accountDeletionPolicy string
	cacheAccountsAboveDiskFreePercentage interface{}
	inactiveThresholdDays interface{}
	removeAccountsBelowDiskFreePercentage interface{}
}

type SharedPCConfiguration struct {
	accountManagerPolicy interface{}
	allowLocalStorage interface{}
	allowedAccounts string
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	disableAccountManager interface{}
	disableEduPolicies interface{}
	disablePowerPolicies interface{}
	disableSignInOnResume interface{}
	displayName string
	enabled interface{}
	id string
	idleTimeBeforeSleepInSeconds interface{}
	kioskAppDisplayName string
	kioskAppUserModelId string
	lastModifiedDateTime string
	maintenanceStartTime string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type SharedPCConfigurationCollectionResponse struct {
	value interface{}
}

type SharedWithChannelTeamInfo struct {
	allowedMembers interface{}
	displayName string
	id string
	isHostTeam interface{}
	team interface{}
	tenantId string
}

type SharedWithChannelTeamInfoCollectionResponse struct {
	value interface{}
}

type SharepointIds struct {
	listId string
	listItemId string
	listItemUniqueId string
	siteId string
	siteUrl string
	tenantId string
	webId string
}

type SharingDetail struct {
	sharedBy interface{}
	sharedDateTime string
	sharingReference interface{}
	sharingSubject string
	sharingType string
}

type SharingDetailCollectionResponse struct {
	value interface{}
}

type SharingInvitation struct {
	email string
	invitedBy interface{}
	redeemedBy string
	signInRequired interface{}
}

type SharingLink struct {
	application interface{}
	preventsDownload interface{}
	scope string
	type string
	webHtml string
	webUrl string
}

type Shift struct {
	createdDateTime string
	draftShift interface{}
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	schedulingGroupId string
	sharedShift interface{}
	userId string
}

type ShiftActivity struct {
	code string
	displayName string
	endDateTime string
	isPaid interface{}
	startDateTime string
	theme string
}

type ShiftActivityCollectionResponse struct {
	value interface{}
}

type ShiftAvailability struct {
	recurrence interface{}
	timeSlots interface{}
	timeZone string
}

type ShiftAvailabilityCollectionResponse struct {
	value interface{}
}

type ShiftCollectionResponse struct {
	value interface{}
}

type ShiftItem struct {
	activities interface{}
	displayName string
	endDateTime string
	notes string
	startDateTime string
	theme string
}

type ShiftPreferences struct {
	availability interface{}
	createdDateTime string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type SignIn struct {
	appDisplayName string
	appId string
	appliedConditionalAccessPolicies interface{}
	clientAppUsed string
	conditionalAccessStatus interface{}
	correlationId string
	createdDateTime string
	deviceDetail interface{}
	id string
	ipAddress string
	isInteractive interface{}
	location interface{}
	resourceDisplayName string
	resourceId string
	riskDetail interface{}
	riskEventTypes interface{}
	riskEventTypes_v2 interface{}
	riskLevelAggregated interface{}
	riskLevelDuringSignIn interface{}
	riskState interface{}
	status interface{}
	userDisplayName string
	userId string
	userPrincipalName string
}

type SignInCollectionResponse struct {
	value interface{}
}

type SignInFrequencySessionControl struct {
	authenticationType interface{}
	frequencyInterval interface{}
	isEnabled interface{}
	type interface{}
	value interface{}
}

type SignInLocation struct {
	city string
	countryOrRegion string
	geoCoordinates interface{}
	state string
}

type SignInStatus struct {
	additionalDetails string
	errorCode interface{}
	failureReason string
}

type SigningCertificateUpdateStatus struct {
	certificateUpdateResult string
	lastRunDateTime string
}

type SingleServicePrincipal struct {
	description string
	servicePrincipalId string
}

type SingleUser struct {
	description string
	userId string
}

type SingleValueLegacyExtendedProperty struct {
	id string
	value string
}

type SingleValueLegacyExtendedPropertyCollectionResponse struct {
	value interface{}
}

type Site struct {
	analytics interface{}
	columns interface{}
	contentTypes interface{}
	createdBy interface{}
	createdByUser interface{}
	createdDateTime string
	description string
	displayName string
	drive interface{}
	drives interface{}
	eTag string
	error interface{}
	externalColumns interface{}
	id string
	items interface{}
	lastModifiedBy interface{}
	lastModifiedByUser interface{}
	lastModifiedDateTime string
	lists interface{}
	name string
	onenote interface{}
	operations interface{}
	parentReference interface{}
	permissions interface{}
	root interface{}
	sharepointIds interface{}
	siteCollection interface{}
	sites interface{}
	termStore interface{}
	termStores interface{}
	webUrl string
}

type SiteCollection struct {
	dataLocationCode string
	hostname string
	root interface{}
}

type SiteCollectionResponse struct {
	value interface{}
}

type SizeRange struct {
	maximumSize interface{}
	minimumSize interface{}
}

type SocialIdentityProvider struct {
	clientId string
	clientSecret string
	displayName string
	id string
	identityProviderType string
}

type SocialIdentityProviderCollectionResponse struct {
	value interface{}
}

type SoftwareOathAuthenticationMethod struct {
	id string
	secretKey string
}

type SoftwareOathAuthenticationMethodCollectionResponse struct {
	value interface{}
}

type SoftwareUpdateStatusSummary struct {
	compliantDeviceCount interface{}
	compliantUserCount interface{}
	conflictDeviceCount interface{}
	conflictUserCount interface{}
	displayName string
	errorDeviceCount interface{}
	errorUserCount interface{}
	id string
	nonCompliantDeviceCount interface{}
	nonCompliantUserCount interface{}
	notApplicableDeviceCount interface{}
	notApplicableUserCount interface{}
	remediatedDeviceCount interface{}
	remediatedUserCount interface{}
	unknownDeviceCount interface{}
	unknownUserCount interface{}
}

type SolutionsRoot struct {
	bookingBusinesses interface{}
	bookingCurrencies interface{}
}

type SortProperty struct {
	isDescending interface{}
	name string
}

type SortPropertyCollectionResponse struct {
	value interface{}
}

type SpaApplication struct {
	redirectUris interface{}
}

type SpecialFolder struct {
	name string
}

type StaffAvailabilityItem struct {
	availabilityItems interface{}
	staffId string
}

type StandardTimeZoneOffset struct {
	dayOccurrence interface{}
	dayOfWeek interface{}
	month interface{}
	time string
	year interface{}
}

type StartHoldMusicOperation struct {
	clientContext string
	id string
	resultInfo interface{}
	status string
}

type StartHoldMusicOperationCollectionResponse struct {
	value interface{}
}

type StopHoldMusicOperation struct {
	clientContext string
	id string
	resultInfo interface{}
	status string
}

type StopHoldMusicOperationCollectionResponse struct {
	value interface{}
}

type StoragePlanInformation struct {
	upgradeAvailable interface{}
}

type Store struct {
	defaultLanguageTag string
	groups interface{}
	id string
	languageTags interface{}
	sets interface{}
}

type StringCollectionResponse struct {
	value interface{}
}

type StsPolicy struct {
	appliesTo interface{}
	definition interface{}
	deletedDateTime string
	description string
	displayName string
	id string
	isOrganizationDefault interface{}
}

type StsPolicyCollectionResponse struct {
	value interface{}
}

type SubjectRightsRequest struct {
	assignedTo interface{}
	closedDateTime string
	createdBy interface{}
	createdDateTime string
	dataSubject interface{}
	dataSubjectType interface{}
	description string
	displayName string
	history interface{}
	id string
	insight interface{}
	internalDueDateTime string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	notes interface{}
	regulations interface{}
	stages interface{}
	status interface{}
	team interface{}
	type interface{}
}

type SubjectRightsRequestCollectionResponse struct {
	value interface{}
}

type SubjectRightsRequestDetail struct {
	excludedItemCount interface{}
	insightCounts interface{}
	itemCount interface{}
	itemNeedReview interface{}
	productItemCounts interface{}
	signedOffItemCount interface{}
	totalItemSize interface{}
}

type SubjectRightsRequestHistory struct {
	changedBy interface{}
	eventDateTime string
	stage interface{}
	stageStatus interface{}
	type string
}

type SubjectRightsRequestHistoryCollectionResponse struct {
	value interface{}
}

type SubjectRightsRequestStageDetail struct {
	error interface{}
	stage interface{}
	status interface{}
}

type SubjectRightsRequestStageDetailCollectionResponse struct {
	value interface{}
}

type SubjectSetCollectionResponse struct {
	value interface{}
}

type SubscribeToToneOperation struct {
	clientContext string
	id string
	resultInfo interface{}
	status string
}

type SubscribeToToneOperationCollectionResponse struct {
	value interface{}
}

type SubscribedSku struct {
	appliesTo string
	capabilityStatus string
	consumedUnits interface{}
	id string
	prepaidUnits interface{}
	servicePlans interface{}
	skuId string
	skuPartNumber string
}

type SubscribedSkuCollectionResponse struct {
	value interface{}
}

type Subscription struct {
	applicationId string
	changeType string
	clientState string
	creatorId string
	encryptionCertificate string
	encryptionCertificateId string
	expirationDateTime string
	id string
	includeResourceData interface{}
	latestSupportedTlsVersion string
	lifecycleNotificationUrl string
	notificationQueryOptions string
	notificationUrl string
	notificationUrlAppId string
	resource string
}

type SubscriptionCollectionResponse struct {
	value interface{}
}

type SwapShiftsChangeRequest struct {
	assignedTo interface{}
	createdDateTime string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	managerActionDateTime string
	managerActionMessage string
	managerUserId string
	recipientActionDateTime string
	recipientActionMessage string
	recipientShiftId string
	recipientUserId string
	senderDateTime string
	senderMessage string
	senderShiftId string
	senderUserId string
	state interface{}
}

type SwapShiftsChangeRequestCollectionResponse struct {
	value interface{}
}

type TabUpdatedEventMessageDetail struct {
	initiator interface{}
	tabId string
}

type TargetManager struct {
	managerLevel interface{}
}

type TargetResource struct {
	displayName string
	groupType interface{}
	id string
	modifiedProperties interface{}
	type string
	userPrincipalName string
}

type TargetResourceCollectionResponse struct {
	value interface{}
}

type TargetedManagedAppConfiguration struct {
	apps interface{}
	assignments interface{}
	createdDateTime string
	customSettings interface{}
	deployedAppCount interface{}
	deploymentSummary interface{}
	description string
	displayName string
	id string
	isAssigned interface{}
	lastModifiedDateTime string
	version string
}

type TargetedManagedAppConfigurationCollectionResponse struct {
	value interface{}
}

type TargetedManagedAppPolicyAssignment struct {
	id string
	target interface{}
}

type TargetedManagedAppPolicyAssignmentCollectionResponse struct {
	value interface{}
}

type TargetedManagedAppProtection struct {
	allowedDataStorageLocations interface{}
	allowedInboundDataTransferSources string
	allowedOutboundClipboardSharingLevel string
	allowedOutboundDataTransferDestinations string
	assignments interface{}
	contactSyncBlocked interface{}
	createdDateTime string
	dataBackupBlocked interface{}
	description string
	deviceComplianceRequired interface{}
	disableAppPinIfDevicePinIsSet interface{}
	displayName string
	fingerprintBlocked interface{}
	id string
	isAssigned interface{}
	lastModifiedDateTime string
	managedBrowser string
	managedBrowserToOpenLinksRequired interface{}
	maximumPinRetries interface{}
	minimumPinLength interface{}
	minimumRequiredAppVersion string
	minimumRequiredOsVersion string
	minimumWarningAppVersion string
	minimumWarningOsVersion string
	organizationalCredentialsRequired interface{}
	periodBeforePinReset string
	periodOfflineBeforeAccessCheck string
	periodOfflineBeforeWipeIsEnforced string
	periodOnlineBeforeAccessCheck string
	pinCharacterSet string
	pinRequired interface{}
	printBlocked interface{}
	saveAsBlocked interface{}
	simplePinBlocked interface{}
	version string
}

type TargetedManagedAppProtectionCollectionResponse struct {
	value interface{}
}

type TaskFileAttachment struct {
	contentBytes string
	contentType string
	id string
	lastModifiedDateTime string
	name string
	size interface{}
}

type TaskFileAttachmentCollectionResponse struct {
	value interface{}
}

type Team struct {
	allChannels interface{}
	channels interface{}
	classification string
	createdDateTime string
	description string
	displayName string
	funSettings interface{}
	group interface{}
	guestSettings interface{}
	id string
	incomingChannels interface{}
	installedApps interface{}
	internalId string
	isArchived interface{}
	memberSettings interface{}
	members interface{}
	messagingSettings interface{}
	operations interface{}
	photo interface{}
	primaryChannel interface{}
	schedule interface{}
	specialization interface{}
	summary interface{}
	template interface{}
	tenantId string
	visibility interface{}
	webUrl string
}

type TeamArchivedEventMessageDetail struct {
	initiator interface{}
	teamId string
}

type TeamClassSettings struct {
	notifyGuardiansAboutAssignments interface{}
}

type TeamCollectionResponse struct {
	value interface{}
}

type TeamCreatedEventMessageDetail struct {
	initiator interface{}
	teamDescription string
	teamDisplayName string
	teamId string
}

type TeamDescriptionUpdatedEventMessageDetail struct {
	initiator interface{}
	teamDescription string
	teamId string
}

type TeamFunSettings struct {
	allowCustomMemes interface{}
	allowGiphy interface{}
	allowStickersAndMemes interface{}
	giphyContentRating interface{}
}

type TeamGuestSettings struct {
	allowCreateUpdateChannels interface{}
	allowDeleteChannels interface{}
}

type TeamInfo struct {
	displayName string
	id string
	team interface{}
	tenantId string
}

type TeamJoiningDisabledEventMessageDetail struct {
	initiator interface{}
	teamId string
}

type TeamJoiningEnabledEventMessageDetail struct {
	initiator interface{}
	teamId string
}

type TeamMemberSettings struct {
	allowAddRemoveApps interface{}
	allowCreatePrivateChannels interface{}
	allowCreateUpdateChannels interface{}
	allowCreateUpdateRemoveConnectors interface{}
	allowCreateUpdateRemoveTabs interface{}
	allowDeleteChannels interface{}
}

type TeamMessagingSettings struct {
	allowChannelMentions interface{}
	allowOwnerDeleteMessages interface{}
	allowTeamMentions interface{}
	allowUserDeleteMessages interface{}
	allowUserEditMessages interface{}
}

type TeamRenamedEventMessageDetail struct {
	initiator interface{}
	teamDisplayName string
	teamId string
}

type TeamSummary struct {
	guestsCount interface{}
	membersCount interface{}
	ownersCount interface{}
}

type TeamUnarchivedEventMessageDetail struct {
	initiator interface{}
	teamId string
}

type TeamsApp struct {
	appDefinitions interface{}
	displayName string
	distributionMethod interface{}
	externalId string
	id string
}

type TeamsAppCollectionResponse struct {
	value interface{}
}

type TeamsAppDefinition struct {
	bot interface{}
	createdBy interface{}
	description string
	displayName string
	id string
	lastModifiedDateTime string
	publishingState interface{}
	shortDescription string
	teamsAppId string
	version string
}

type TeamsAppDefinitionCollectionResponse struct {
	value interface{}
}

type TeamsAppInstallation struct {
	id string
	teamsApp interface{}
	teamsAppDefinition interface{}
}

type TeamsAppInstallationCollectionResponse struct {
	value interface{}
}

type TeamsAppInstalledEventMessageDetail struct {
	initiator interface{}
	teamsAppDisplayName string
	teamsAppId string
}

type TeamsAppRemovedEventMessageDetail struct {
	initiator interface{}
	teamsAppDisplayName string
	teamsAppId string
}

type TeamsAppUpgradedEventMessageDetail struct {
	initiator interface{}
	teamsAppDisplayName string
	teamsAppId string
}

type TeamsAsyncOperation struct {
	attemptsCount interface{}
	createdDateTime string
	error interface{}
	id string
	lastActionDateTime string
	operationType string
	status string
	targetResourceId string
	targetResourceLocation string
}

type TeamsAsyncOperationCollectionResponse struct {
	value interface{}
}

type TeamsTab struct {
	configuration interface{}
	displayName string
	id string
	teamsApp interface{}
	webUrl string
}

type TeamsTabCollectionResponse struct {
	value interface{}
}

type TeamsTabConfiguration struct {
	contentUrl string
	entityId string
	removeUrl string
	websiteUrl string
}

type TeamsTemplate struct {
	id string
}

type TeamsTemplateCollectionResponse struct {
	value interface{}
}

type Teamwork struct {
	id string
	workforceIntegrations interface{}
}

type TeamworkActivityTopic struct {
	source interface{}
	value string
	webUrl string
}

type TeamworkApplicationIdentity struct {
	applicationIdentityType interface{}
	displayName string
	id string
}

type TeamworkBot struct {
	id string
}

type TeamworkConversationIdentity struct {
	conversationIdentityType interface{}
	displayName string
	id string
}

type TeamworkHostedContent struct {
	contentBytes string
	contentType string
	id string
}

type TeamworkOnlineMeetingInfo struct {
	calendarEventId string
	joinWebUrl string
	organizer interface{}
}

type TeamworkTagIdentity struct {
	displayName string
	id string
}

type TeamworkUserIdentity struct {
	displayName string
	id string
	userIdentityType interface{}
}

type TeamworkUserIdentityCollectionResponse struct {
	value interface{}
}

type TelecomExpenseManagementPartner struct {
	appAuthorized interface{}
	displayName string
	enabled interface{}
	id string
	lastConnectionDateTime string
	url string
}

type TelecomExpenseManagementPartnerCollectionResponse struct {
	value interface{}
}

type TeleconferenceDeviceAudioQuality struct {
	averageInboundJitter string
	averageInboundPacketLossRateInPercentage interface{}
	averageInboundRoundTripDelay string
	averageOutboundJitter string
	averageOutboundPacketLossRateInPercentage interface{}
	averageOutboundRoundTripDelay string
	channelIndex interface{}
	inboundPackets interface{}
	localIPAddress string
	localPort interface{}
	maximumInboundJitter string
	maximumInboundPacketLossRateInPercentage interface{}
	maximumInboundRoundTripDelay string
	maximumOutboundJitter string
	maximumOutboundPacketLossRateInPercentage interface{}
	maximumOutboundRoundTripDelay string
	mediaDuration string
	networkLinkSpeedInBytes interface{}
	outboundPackets interface{}
	remoteIPAddress string
	remotePort interface{}
}

type TeleconferenceDeviceMediaQuality struct {
	averageInboundJitter string
	averageInboundPacketLossRateInPercentage interface{}
	averageInboundRoundTripDelay string
	averageOutboundJitter string
	averageOutboundPacketLossRateInPercentage interface{}
	averageOutboundRoundTripDelay string
	channelIndex interface{}
	inboundPackets interface{}
	localIPAddress string
	localPort interface{}
	maximumInboundJitter string
	maximumInboundPacketLossRateInPercentage interface{}
	maximumInboundRoundTripDelay string
	maximumOutboundJitter string
	maximumOutboundPacketLossRateInPercentage interface{}
	maximumOutboundRoundTripDelay string
	mediaDuration string
	networkLinkSpeedInBytes interface{}
	outboundPackets interface{}
	remoteIPAddress string
	remotePort interface{}
}

type TeleconferenceDeviceMediaQualityCollectionResponse struct {
	value interface{}
}

type TeleconferenceDeviceQuality struct {
	callChainId string
	cloudServiceDeploymentEnvironment string
	cloudServiceDeploymentId string
	cloudServiceInstanceName string
	cloudServiceName string
	deviceDescription string
	deviceName string
	mediaLegId string
	mediaQualityList interface{}
	participantId string
}

type TeleconferenceDeviceScreenSharingQuality struct {
	averageInboundBitRate interface{}
	averageInboundFrameRate interface{}
	averageInboundJitter string
	averageInboundPacketLossRateInPercentage interface{}
	averageInboundRoundTripDelay string
	averageOutboundBitRate interface{}
	averageOutboundFrameRate interface{}
	averageOutboundJitter string
	averageOutboundPacketLossRateInPercentage interface{}
	averageOutboundRoundTripDelay string
	channelIndex interface{}
	inboundPackets interface{}
	localIPAddress string
	localPort interface{}
	maximumInboundJitter string
	maximumInboundPacketLossRateInPercentage interface{}
	maximumInboundRoundTripDelay string
	maximumOutboundJitter string
	maximumOutboundPacketLossRateInPercentage interface{}
	maximumOutboundRoundTripDelay string
	mediaDuration string
	networkLinkSpeedInBytes interface{}
	outboundPackets interface{}
	remoteIPAddress string
	remotePort interface{}
}

type TeleconferenceDeviceVideoQuality struct {
	averageInboundBitRate interface{}
	averageInboundFrameRate interface{}
	averageInboundJitter string
	averageInboundPacketLossRateInPercentage interface{}
	averageInboundRoundTripDelay string
	averageOutboundBitRate interface{}
	averageOutboundFrameRate interface{}
	averageOutboundJitter string
	averageOutboundPacketLossRateInPercentage interface{}
	averageOutboundRoundTripDelay string
	channelIndex interface{}
	inboundPackets interface{}
	localIPAddress string
	localPort interface{}
	maximumInboundJitter string
	maximumInboundPacketLossRateInPercentage interface{}
	maximumInboundRoundTripDelay string
	maximumOutboundJitter string
	maximumOutboundPacketLossRateInPercentage interface{}
	maximumOutboundRoundTripDelay string
	mediaDuration string
	networkLinkSpeedInBytes interface{}
	outboundPackets interface{}
	remoteIPAddress string
	remotePort interface{}
}

type TemporaryAccessPassAuthenticationMethod struct {
	createdDateTime string
	id string
	isUsable interface{}
	isUsableOnce interface{}
	lifetimeInMinutes interface{}
	methodUsabilityReason string
	startDateTime string
	temporaryAccessPass string
}

type TemporaryAccessPassAuthenticationMethodCollectionResponse struct {
	value interface{}
}

type TemporaryAccessPassAuthenticationMethodConfiguration struct {
	defaultLength interface{}
	defaultLifetimeInMinutes interface{}
	id string
	includeTargets interface{}
	isUsableOnce interface{}
	maximumLifetimeInMinutes interface{}
	minimumLifetimeInMinutes interface{}
	state interface{}
}

type TemporaryAccessPassAuthenticationMethodConfigurationCollectionResponse struct {
	value interface{}
}

type Term struct {
	children interface{}
	createdDateTime string
	descriptions interface{}
	id string
	labels interface{}
	lastModifiedDateTime string
	properties interface{}
	relations interface{}
	set interface{}
}

type TermColumn struct {
	allowMultipleValues interface{}
	parentTerm interface{}
	showFullyQualifiedName interface{}
	termSet interface{}
}

type TermStoreGroup struct {
	createdDateTime string
	description string
	displayName string
	id string
	parentSiteId string
	scope interface{}
	sets interface{}
}

type TermStoreGroupCollectionResponse struct {
	value interface{}
}

type TermStoreLocalizedDescription struct {
	description string
	languageTag string
}

type TermStoreLocalizedDescriptionCollectionResponse struct {
	value interface{}
}

type TermStoreLocalizedLabel struct {
	isDefault interface{}
	languageTag string
	name string
}

type TermStoreLocalizedLabelCollectionResponse struct {
	value interface{}
}

type TermStoreLocalizedName struct {
	languageTag string
	name string
}

type TermStoreLocalizedNameCollectionResponse struct {
	value interface{}
}

type TermStoreRelation struct {
	fromTerm interface{}
	id string
	relationship interface{}
	set interface{}
	toTerm interface{}
}

type TermStoreRelationCollectionResponse struct {
	value interface{}
}

type TermStoreSet struct {
	children interface{}
	createdDateTime string
	description string
	id string
	localizedNames interface{}
	parentGroup interface{}
	properties interface{}
	relations interface{}
	terms interface{}
}

type TermStoreSetCollectionResponse struct {
	value interface{}
}

type TermStoreStore struct {
	defaultLanguageTag string
	groups interface{}
	id string
	languageTags interface{}
	sets interface{}
}

type TermStoreStoreCollectionResponse struct {
	value interface{}
}

type TermStoreTerm struct {
	children interface{}
	createdDateTime string
	descriptions interface{}
	id string
	labels interface{}
	lastModifiedDateTime string
	properties interface{}
	relations interface{}
	set interface{}
}

type TermStoreTermCollectionResponse struct {
	value interface{}
}

type TermsAndConditions struct {
	acceptanceStatement string
	acceptanceStatuses interface{}
	assignments interface{}
	bodyText string
	createdDateTime string
	description string
	displayName string
	id string
	lastModifiedDateTime string
	title string
	version interface{}
}

type TermsAndConditionsAcceptanceStatus struct {
	acceptedDateTime string
	acceptedVersion interface{}
	id string
	termsAndConditions interface{}
	userDisplayName string
	userPrincipalName string
}

type TermsAndConditionsAcceptanceStatusCollectionResponse struct {
	value interface{}
}

type TermsAndConditionsAssignment struct {
	id string
	target interface{}
}

type TermsAndConditionsAssignmentCollectionResponse struct {
	value interface{}
}

type TermsAndConditionsCollectionResponse struct {
	value interface{}
}

type TermsExpiration struct {
	frequency string
	startDateTime string
}

type TermsOfUseContainer struct {
	agreementAcceptances interface{}
	agreements interface{}
	id string
}

type TextColumn struct {
	allowMultipleLines interface{}
	appendChangesToExistingText interface{}
	linesForEditing interface{}
	maxLength interface{}
	textType string
}

type ThreatAssessmentRequest struct {
	category string
	contentType interface{}
	createdBy interface{}
	createdDateTime string
	expectedAssessment string
	id string
	requestSource interface{}
	results interface{}
	status interface{}
}

type ThreatAssessmentRequestCollectionResponse struct {
	value interface{}
}

type ThreatAssessmentResult struct {
	createdDateTime string
	id string
	message string
	resultType interface{}
}

type ThreatAssessmentResultCollectionResponse struct {
	value interface{}
}

type Thumbnail struct {
	content string
	height interface{}
	sourceItemId string
	url string
	width interface{}
}

type ThumbnailSet struct {
	id string
	large interface{}
	medium interface{}
	small interface{}
	source interface{}
}

type ThumbnailSetCollectionResponse struct {
	value interface{}
}

type TicketInfo struct {
	ticketNumber string
	ticketSystem string
}

type TimeConstraint struct {
	activityDomain interface{}
	timeSlots interface{}
}

type TimeOff struct {
	createdDateTime string
	draftTimeOff interface{}
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	sharedTimeOff interface{}
	userId string
}

type TimeOffCollectionResponse struct {
	value interface{}
}

type TimeOffItem struct {
	endDateTime string
	startDateTime string
	theme string
	timeOffReasonId string
}

type TimeOffReason struct {
	createdDateTime string
	displayName string
	iconType interface{}
	id string
	isActive interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
}

type TimeOffReasonCollectionResponse struct {
	value interface{}
}

type TimeOffRequest struct {
	assignedTo interface{}
	createdDateTime string
	endDateTime string
	id string
	lastModifiedBy interface{}
	lastModifiedDateTime string
	managerActionDateTime string
	managerActionMessage string
	managerUserId string
	senderDateTime string
	senderMessage string
	senderUserId string
	startDateTime string
	state interface{}
	timeOffReasonId string
}

type TimeOffRequestCollectionResponse struct {
	value interface{}
}

type TimeRange struct {
	endTime string
	startTime string
}

type TimeRangeCollectionResponse struct {
	value interface{}
}

type TimeSlot struct {
	end interface{}
	start interface{}
}

type TimeSlotCollectionResponse struct {
	value interface{}
}

type TimeZoneBase struct {
	name string
}

type TimeZoneInformation struct {
	alias string
	displayName string
}

type Todo struct {
	id string
	lists interface{}
}

type TodoTask struct {
	attachmentSessions interface{}
	attachments interface{}
	body interface{}
	bodyLastModifiedDateTime string
	categories interface{}
	checklistItems interface{}
	completedDateTime interface{}
	createdDateTime string
	dueDateTime interface{}
	extensions interface{}
	hasAttachments interface{}
	id string
	importance string
	isReminderOn interface{}
	lastModifiedDateTime string
	linkedResources interface{}
	recurrence interface{}
	reminderDateTime interface{}
	startDateTime interface{}
	status string
	title string
}

type TodoTaskCollectionResponse struct {
	value interface{}
}

type TodoTaskList struct {
	displayName string
	extensions interface{}
	id string
	isOwner interface{}
	isShared interface{}
	tasks interface{}
	wellknownListName string
}

type TodoTaskListCollectionResponse struct {
	value interface{}
}

type TokenIssuancePolicy struct {
	appliesTo interface{}
	definition interface{}
	deletedDateTime string
	description string
	displayName string
	id string
	isOrganizationDefault interface{}
}

type TokenIssuancePolicyCollectionResponse struct {
	value interface{}
}

type TokenLifetimePolicy struct {
	appliesTo interface{}
	definition interface{}
	deletedDateTime string
	description string
	displayName string
	id string
	isOrganizationDefault interface{}
}

type TokenLifetimePolicyCollectionResponse struct {
	value interface{}
}

type TokenMeetingInfo struct {
	token string
}

type ToneInfo struct {
	sequenceId interface{}
	tone string
}

type TopicModelingSettings struct {
	dynamicallyAdjustTopicCount interface{}
	ignoreNumbers interface{}
	isEnabled interface{}
	topicCount interface{}
}

type Trending struct {
	id string
	lastModifiedDateTime string
	resource interface{}
	resourceReference interface{}
	resourceVisualization interface{}
	weight interface{}
}

type TrendingCollectionResponse struct {
	value interface{}
}

type UnifiedApprovalStage struct {
	approvalStageTimeOutInDays interface{}
	escalationApprovers interface{}
	escalationTimeInMinutes interface{}
	isApproverJustificationRequired interface{}
	isEscalationEnabled interface{}
	primaryApprovers interface{}
}

type UnifiedApprovalStageCollectionResponse struct {
	value interface{}
}

type UnifiedRoleAssignment struct {
	appScope interface{}
	appScopeId string
	condition string
	directoryScope interface{}
	directoryScopeId string
	id string
	principal interface{}
	principalId string
	roleDefinition interface{}
	roleDefinitionId string
}

type UnifiedRoleAssignmentCollectionResponse struct {
	value interface{}
}

type UnifiedRoleAssignmentSchedule struct {
	activatedUsing interface{}
	appScope interface{}
	appScopeId string
	assignmentType string
	createdDateTime string
	createdUsing string
	directoryScope interface{}
	directoryScopeId string
	id string
	memberType string
	modifiedDateTime string
	principal interface{}
	principalId string
	roleDefinition interface{}
	roleDefinitionId string
	scheduleInfo interface{}
	status string
}

type UnifiedRoleAssignmentScheduleCollectionResponse struct {
	value interface{}
}

type UnifiedRoleAssignmentScheduleInstance struct {
	activatedUsing interface{}
	appScope interface{}
	appScopeId string
	assignmentType string
	directoryScope interface{}
	directoryScopeId string
	endDateTime string
	id string
	memberType string
	principal interface{}
	principalId string
	roleAssignmentOriginId string
	roleAssignmentScheduleId string
	roleDefinition interface{}
	roleDefinitionId string
	startDateTime string
}

type UnifiedRoleAssignmentScheduleInstanceCollectionResponse struct {
	value interface{}
}

type UnifiedRoleAssignmentScheduleRequest struct {
	action interface{}
	activatedUsing interface{}
	appScope interface{}
	appScopeId string
	approvalId string
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	customData string
	directoryScope interface{}
	directoryScopeId string
	id string
	isValidationOnly interface{}
	justification string
	principal interface{}
	principalId string
	roleDefinition interface{}
	roleDefinitionId string
	scheduleInfo interface{}
	status string
	targetSchedule interface{}
	targetScheduleId string
	ticketInfo interface{}
}

type UnifiedRoleAssignmentScheduleRequestCollectionResponse struct {
	value interface{}
}

type UnifiedRoleDefinition struct {
	description string
	displayName string
	id string
	inheritsPermissionsFrom interface{}
	isBuiltIn interface{}
	isEnabled interface{}
	resourceScopes interface{}
	rolePermissions interface{}
	templateId string
	version string
}

type UnifiedRoleDefinitionCollectionResponse struct {
	value interface{}
}

type UnifiedRoleEligibilitySchedule struct {
	appScope interface{}
	appScopeId string
	createdDateTime string
	createdUsing string
	directoryScope interface{}
	directoryScopeId string
	id string
	memberType string
	modifiedDateTime string
	principal interface{}
	principalId string
	roleDefinition interface{}
	roleDefinitionId string
	scheduleInfo interface{}
	status string
}

type UnifiedRoleEligibilityScheduleCollectionResponse struct {
	value interface{}
}

type UnifiedRoleEligibilityScheduleInstance struct {
	appScope interface{}
	appScopeId string
	directoryScope interface{}
	directoryScopeId string
	endDateTime string
	id string
	memberType string
	principal interface{}
	principalId string
	roleDefinition interface{}
	roleDefinitionId string
	roleEligibilityScheduleId string
	startDateTime string
}

type UnifiedRoleEligibilityScheduleInstanceCollectionResponse struct {
	value interface{}
}

type UnifiedRoleEligibilityScheduleRequest struct {
	action interface{}
	appScope interface{}
	appScopeId string
	approvalId string
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	customData string
	directoryScope interface{}
	directoryScopeId string
	id string
	isValidationOnly interface{}
	justification string
	principal interface{}
	principalId string
	roleDefinition interface{}
	roleDefinitionId string
	scheduleInfo interface{}
	status string
	targetSchedule interface{}
	targetScheduleId string
	ticketInfo interface{}
}

type UnifiedRoleEligibilityScheduleRequestCollectionResponse struct {
	value interface{}
}

type UnifiedRoleManagementPolicy struct {
	description string
	displayName string
	effectiveRules interface{}
	id string
	isOrganizationDefault interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	rules interface{}
	scopeId string
	scopeType string
}

type UnifiedRoleManagementPolicyApprovalRule struct {
	id string
	setting interface{}
	target interface{}
}

type UnifiedRoleManagementPolicyApprovalRuleCollectionResponse struct {
	value interface{}
}

type UnifiedRoleManagementPolicyAssignment struct {
	id string
	policy interface{}
	policyId string
	roleDefinitionId string
	scopeId string
	scopeType string
}

type UnifiedRoleManagementPolicyAssignmentCollectionResponse struct {
	value interface{}
}

type UnifiedRoleManagementPolicyAuthenticationContextRule struct {
	claimValue string
	id string
	isEnabled interface{}
	target interface{}
}

type UnifiedRoleManagementPolicyAuthenticationContextRuleCollectionResponse struct {
	value interface{}
}

type UnifiedRoleManagementPolicyCollectionResponse struct {
	value interface{}
}

type UnifiedRoleManagementPolicyEnablementRule struct {
	enabledRules interface{}
	id string
	target interface{}
}

type UnifiedRoleManagementPolicyEnablementRuleCollectionResponse struct {
	value interface{}
}

type UnifiedRoleManagementPolicyExpirationRule struct {
	id string
	isExpirationRequired interface{}
	maximumDuration string
	target interface{}
}

type UnifiedRoleManagementPolicyExpirationRuleCollectionResponse struct {
	value interface{}
}

type UnifiedRoleManagementPolicyNotificationRule struct {
	id string
	isDefaultRecipientsEnabled interface{}
	notificationLevel string
	notificationRecipients interface{}
	notificationType string
	recipientType string
	target interface{}
}

type UnifiedRoleManagementPolicyNotificationRuleCollectionResponse struct {
	value interface{}
}

type UnifiedRoleManagementPolicyRule struct {
	id string
	target interface{}
}

type UnifiedRoleManagementPolicyRuleCollectionResponse struct {
	value interface{}
}

type UnifiedRoleManagementPolicyRuleTarget struct {
	caller string
	enforcedSettings interface{}
	inheritableSettings interface{}
	level string
	operations interface{}
	targetObjects interface{}
}

type UnifiedRolePermission struct {
	allowedResourceActions interface{}
	condition string
	excludedResourceActions interface{}
}

type UnifiedRolePermissionCollectionResponse struct {
	value interface{}
}

type UnifiedRoleScheduleBase struct {
	appScope interface{}
	appScopeId string
	createdDateTime string
	createdUsing string
	directoryScope interface{}
	directoryScopeId string
	id string
	modifiedDateTime string
	principal interface{}
	principalId string
	roleDefinition interface{}
	roleDefinitionId string
	status string
}

type UnifiedRoleScheduleInstanceBase struct {
	appScope interface{}
	appScopeId string
	directoryScope interface{}
	directoryScopeId string
	id string
	principal interface{}
	principalId string
	roleDefinition interface{}
	roleDefinitionId string
}

type UnmuteParticipantOperation struct {
	clientContext string
	id string
	resultInfo interface{}
	status string
}

type UnmuteParticipantOperationCollectionResponse struct {
	value interface{}
}

type UpdateRecordingStatusOperation struct {
	clientContext string
	id string
	resultInfo interface{}
	status string
}

type UpdateRecordingStatusOperationCollectionResponse struct {
	value interface{}
}

type UpdateWindowsDeviceAccountActionParameter struct {
	calendarSyncEnabled interface{}
	deviceAccount interface{}
	deviceAccountEmail string
	exchangeServer string
	passwordRotationEnabled interface{}
	sessionInitiationProtocalAddress string
}

type UploadSession struct {
	expirationDateTime string
	nextExpectedRanges interface{}
	uploadUrl string
}

type UriClickSecurityState struct {
	clickAction string
	clickDateTime string
	id string
	sourceId string
	uriDomain string
	verdict string
}

type UriClickSecurityStateCollectionResponse struct {
	value interface{}
}

type UrlAssessmentRequest struct {
	category string
	contentType interface{}
	createdBy interface{}
	createdDateTime string
	expectedAssessment string
	id string
	requestSource interface{}
	results interface{}
	status interface{}
	url string
}

type UrlAssessmentRequestCollectionResponse struct {
	value interface{}
}

type UsageDetails struct {
	lastAccessedDateTime string
	lastModifiedDateTime string
}

type UsedInsight struct {
	id string
	lastUsed interface{}
	resource interface{}
	resourceReference interface{}
	resourceVisualization interface{}
}

type UsedInsightCollectionResponse struct {
	value interface{}
}

type User struct {
	aboutMe string
	accountEnabled interface{}
	activities interface{}
	ageGroup string
	agreementAcceptances interface{}
	appRoleAssignments interface{}
	assignedLicenses interface{}
	assignedPlans interface{}
	authentication interface{}
	birthday string
	businessPhones interface{}
	calendar interface{}
	calendarGroups interface{}
	calendarView interface{}
	calendars interface{}
	chats interface{}
	city string
	companyName string
	consentProvidedForMinor string
	contactFolders interface{}
	contacts interface{}
	country string
	createdDateTime string
	createdObjects interface{}
	creationType string
	deletedDateTime string
	department string
	deviceEnrollmentLimit interface{}
	deviceManagementTroubleshootingEvents interface{}
	directReports interface{}
	displayName string
	drive interface{}
	drives interface{}
	employeeHireDate string
	employeeId string
	employeeOrgData interface{}
	employeeType string
	events interface{}
	extensions interface{}
	externalUserState string
	externalUserStateChangeDateTime string
	faxNumber string
	followedSites interface{}
	givenName string
	hireDate string
	id string
	identities interface{}
	imAddresses interface{}
	inferenceClassification interface{}
	insights interface{}
	interests interface{}
	isResourceAccount interface{}
	jobTitle string
	joinedTeams interface{}
	lastPasswordChangeDateTime string
	legalAgeGroupClassification string
	licenseAssignmentStates interface{}
	licenseDetails interface{}
	mail string
	mailFolders interface{}
	mailNickname string
	mailboxSettings interface{}
	managedAppRegistrations interface{}
	managedDevices interface{}
	manager interface{}
	memberOf interface{}
	messages interface{}
	mobilePhone string
	mySite string
	oauth2PermissionGrants interface{}
	officeLocation string
	onPremisesDistinguishedName string
	onPremisesDomainName string
	onPremisesExtensionAttributes interface{}
	onPremisesImmutableId string
	onPremisesLastSyncDateTime string
	onPremisesProvisioningErrors interface{}
	onPremisesSamAccountName string
	onPremisesSecurityIdentifier string
	onPremisesSyncEnabled interface{}
	onPremisesUserPrincipalName string
	onenote interface{}
	onlineMeetings interface{}
	otherMails interface{}
	outlook interface{}
	ownedDevices interface{}
	ownedObjects interface{}
	passwordPolicies string
	passwordProfile interface{}
	pastProjects interface{}
	people interface{}
	photo interface{}
	photos interface{}
	planner interface{}
	postalCode string
	preferredDataLocation string
	preferredLanguage string
	preferredName string
	presence interface{}
	provisionedPlans interface{}
	proxyAddresses interface{}
	registeredDevices interface{}
	responsibilities interface{}
	schools interface{}
	scopedRoleMemberOf interface{}
	settings interface{}
	showInAddressList interface{}
	signInSessionsValidFromDateTime string
	skills interface{}
	state string
	streetAddress string
	surname string
	teamwork interface{}
	todo interface{}
	transitiveMemberOf interface{}
	usageLocation string
	userPrincipalName string
	userType string
}

type UserActivity struct {
	activationUrl string
	activitySourceHost string
	appActivityId string
	appDisplayName string
	contentInfo interface{}
	contentUrl string
	createdDateTime string
	expirationDateTime string
	fallbackUrl string
	historyItems interface{}
	id string
	lastModifiedDateTime string
	status interface{}
	userTimezone string
	visualElements interface{}
}

type UserActivityCollectionResponse struct {
	value interface{}
}

type UserAgent struct {
	applicationVersion string
	headerValue string
}

type UserAttributeValuesItem struct {
	isDefault interface{}
	name string
	value string
}

type UserAttributeValuesItemCollectionResponse struct {
	value interface{}
}

type UserCollectionResponse struct {
	value interface{}
}

type UserConsentRequest struct {
	approval interface{}
	approvalId string
	completedDateTime string
	createdBy interface{}
	createdDateTime string
	customData string
	id string
	reason string
	status string
}

type UserConsentRequestCollectionResponse struct {
	value interface{}
}

type UserExperienceAnalyticsDevicePerformance struct {
	averageBlueScreens interface{}
	averageRestarts interface{}
	blueScreenCount interface{}
	bootScore interface{}
	coreBootTimeInMs interface{}
	coreLoginTimeInMs interface{}
	deviceCount interface{}
	deviceName string
	diskType string
	groupPolicyBootTimeInMs interface{}
	groupPolicyLoginTimeInMs interface{}
	healthStatus string
	id string
	loginScore interface{}
	manufacturer string
	model string
	modelStartupPerformanceScore interface{}
	operatingSystemVersion string
	responsiveDesktopTimeInMs interface{}
	restartCount interface{}
	startupPerformanceScore interface{}
}

type UserFeedback struct {
	rating string
	text string
	tokens interface{}
}

type UserFlowApiConnectorConfiguration struct {
	postAttributeCollection interface{}
	postFederationSignup interface{}
}

type UserFlowLanguageConfiguration struct {
	defaultPages interface{}
	displayName string
	id string
	isEnabled interface{}
	overridesPages interface{}
}

type UserFlowLanguageConfigurationCollectionResponse struct {
	value interface{}
}

type UserFlowLanguagePage struct {
	id string
}

type UserFlowLanguagePageCollectionResponse struct {
	value interface{}
}

type UserIdentity struct {
	displayName string
	id string
	ipAddress string
	userPrincipalName string
}

type UserInstallStateSummary struct {
	deviceStates interface{}
	failedDeviceCount interface{}
	id string
	installedDeviceCount interface{}
	notInstalledDeviceCount interface{}
	userName string
}

type UserInstallStateSummaryCollectionResponse struct {
	value interface{}
}

type UserScopeTeamsAppInstallation struct {
	chat interface{}
	id string
	teamsApp interface{}
	teamsAppDefinition interface{}
}

type UserScopeTeamsAppInstallationCollectionResponse struct {
	value interface{}
}

type UserSecurityState struct {
	aadUserId string
	accountName string
	domainName string
	emailRole interface{}
	isVpn interface{}
	logonDateTime string
	logonId string
	logonIp string
	logonLocation string
	logonType interface{}
	onPremisesSecurityIdentifier string
	riskScore string
	userAccountType interface{}
	userPrincipalName string
}

type UserSecurityStateCollectionResponse struct {
	value interface{}
}

type UserSettings struct {
	contributionToContentDiscoveryAsOrganizationDisabled interface{}
	contributionToContentDiscoveryDisabled interface{}
	id string
	shiftPreferences interface{}
}

type UserTeamwork struct {
	associatedTeams interface{}
	id string
	installedApps interface{}
}

type VerifiedDomain struct {
	capabilities string
	isDefault interface{}
	isInitial interface{}
	name string
	type string
}

type VerifiedDomainCollectionResponse struct {
	value interface{}
}

type VerifiedPublisher struct {
	addedDateTime string
	displayName string
	verifiedPublisherId string
}

type Video struct {
	audioBitsPerSample interface{}
	audioChannels interface{}
	audioFormat string
	audioSamplesPerSecond interface{}
	bitrate interface{}
	duration interface{}
	fourCC string
	frameRate interface{}
	height interface{}
	width interface{}
}

type VisualInfo struct {
	attribution interface{}
	backgroundColor string
	content interface{}
	description string
	displayText string
}

type VppLicensingType struct {
	supportsDeviceLicensing interface{}
	supportsUserLicensing interface{}
}

type VppToken struct {
	appleId string
	automaticallyUpdateApps interface{}
	countryOrRegion string
	expirationDateTime string
	id string
	lastModifiedDateTime string
	lastSyncDateTime string
	lastSyncStatus string
	organizationName string
	state string
	token string
	vppTokenAccountType string
}

type VppTokenCollectionResponse struct {
	value interface{}
}

type VulnerabilityState struct {
	cve string
	severity string
	wasRunning interface{}
}

type VulnerabilityStateCollectionResponse struct {
	value interface{}
}

type WebApp struct {
	appUrl string
	assignments interface{}
	categories interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	id string
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
	useManagedBrowser interface{}
}

type WebAppCollectionResponse struct {
	value interface{}
}

type WebApplication struct {
	homePageUrl string
	implicitGrantSettings interface{}
	logoutUrl string
	redirectUris interface{}
}

type Website struct {
	address string
	displayName string
	type interface{}
}

type WebsiteCollectionResponse struct {
	value interface{}
}

type Win32LobApp struct {
	applicableArchitectures string
	assignments interface{}
	categories interface{}
	committedContentVersion string
	contentVersions interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	fileName string
	id string
	informationUrl string
	installCommandLine string
	installExperience interface{}
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	minimumCpuSpeedInMHz interface{}
	minimumFreeDiskSpaceInMB interface{}
	minimumMemoryInMB interface{}
	minimumNumberOfProcessors interface{}
	minimumSupportedWindowsRelease string
	msiInformation interface{}
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
	returnCodes interface{}
	rules interface{}
	setupFilePath string
	size interface{}
	uninstallCommandLine string
}

type Win32LobAppAssignmentSettings struct {
	deliveryOptimizationPriority string
	installTimeSettings interface{}
	notifications string
	restartSettings interface{}
}

type Win32LobAppCollectionResponse struct {
	value interface{}
}

type Win32LobAppFileSystemRule struct {
	check32BitOn64System interface{}
	comparisonValue string
	fileOrFolderName string
	operationType string
	operator string
	path string
	ruleType string
}

type Win32LobAppInstallExperience struct {
	deviceRestartBehavior string
	runAsAccount string
}

type Win32LobAppMsiInformation struct {
	packageType string
	productCode string
	productName string
	productVersion string
	publisher string
	requiresReboot interface{}
	upgradeCode string
}

type Win32LobAppPowerShellScriptRule struct {
	comparisonValue string
	displayName string
	enforceSignatureCheck interface{}
	operationType string
	operator string
	ruleType string
	runAs32Bit interface{}
	runAsAccount interface{}
	scriptContent string
}

type Win32LobAppProductCodeRule struct {
	productCode string
	productVersion string
	productVersionOperator string
	ruleType string
}

type Win32LobAppRegistryRule struct {
	check32BitOn64System interface{}
	comparisonValue string
	keyPath string
	operationType string
	operator string
	ruleType string
	valueName string
}

type Win32LobAppRestartSettings struct {
	countdownDisplayBeforeRestartInMinutes interface{}
	gracePeriodInMinutes interface{}
	restartNotificationSnoozeDurationInMinutes interface{}
}

type Win32LobAppReturnCode struct {
	returnCode interface{}
	type string
}

type Win32LobAppReturnCodeCollectionResponse struct {
	value interface{}
}

type Win32LobAppRule struct {
	ruleType string
}

type Win32LobAppRuleCollectionResponse struct {
	value interface{}
}

type Windows10CompliancePolicy struct {
	assignments interface{}
	bitLockerEnabled interface{}
	codeIntegrityEnabled interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	earlyLaunchAntiMalwareDriverEnabled interface{}
	id string
	lastModifiedDateTime string
	mobileOsMaximumVersion string
	mobileOsMinimumVersion string
	osMaximumVersion string
	osMinimumVersion string
	passwordBlockSimple interface{}
	passwordExpirationDays interface{}
	passwordMinimumCharacterSetCount interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeLock interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequired interface{}
	passwordRequiredToUnlockFromIdle interface{}
	passwordRequiredType string
	requireHealthyDeviceReport interface{}
	scheduledActionsForRule interface{}
	secureBootEnabled interface{}
	storageRequireEncryption interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type Windows10CompliancePolicyCollectionResponse struct {
	value interface{}
}

type Windows10CustomConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	omaSettings interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type Windows10CustomConfigurationCollectionResponse struct {
	value interface{}
}

type Windows10EndpointProtectionConfiguration struct {
	appLockerApplicationControl string
	applicationGuardAllowPersistence interface{}
	applicationGuardAllowPrintToLocalPrinters interface{}
	applicationGuardAllowPrintToNetworkPrinters interface{}
	applicationGuardAllowPrintToPDF interface{}
	applicationGuardAllowPrintToXPS interface{}
	applicationGuardBlockClipboardSharing string
	applicationGuardBlockFileTransfer string
	applicationGuardBlockNonEnterpriseContent interface{}
	applicationGuardEnabled interface{}
	applicationGuardForceAuditing interface{}
	assignments interface{}
	bitLockerDisableWarningForOtherDiskEncryption interface{}
	bitLockerEnableStorageCardEncryptionOnMobile interface{}
	bitLockerEncryptDevice interface{}
	bitLockerRemovableDrivePolicy interface{}
	createdDateTime string
	defenderAdditionalGuardedFolders interface{}
	defenderAttackSurfaceReductionExcludedPaths interface{}
	defenderExploitProtectionXml string
	defenderExploitProtectionXmlFileName string
	defenderGuardedFoldersAllowedAppPaths interface{}
	defenderSecurityCenterBlockExploitProtectionOverride interface{}
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	firewallBlockStatefulFTP interface{}
	firewallCertificateRevocationListCheckMethod string
	firewallIPSecExemptionsAllowDHCP interface{}
	firewallIPSecExemptionsAllowICMP interface{}
	firewallIPSecExemptionsAllowNeighborDiscovery interface{}
	firewallIPSecExemptionsAllowRouterDiscovery interface{}
	firewallIdleTimeoutForSecurityAssociationInSeconds interface{}
	firewallMergeKeyingModuleSettings interface{}
	firewallPacketQueueingMethod string
	firewallPreSharedKeyEncodingMethod string
	firewallProfileDomain interface{}
	firewallProfilePrivate interface{}
	firewallProfilePublic interface{}
	id string
	lastModifiedDateTime string
	smartScreenBlockOverrideForFiles interface{}
	smartScreenEnableInShell interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type Windows10EndpointProtectionConfigurationCollectionResponse struct {
	value interface{}
}

type Windows10EnterpriseModernAppManagementConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	uninstallBuiltInApps interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type Windows10EnterpriseModernAppManagementConfigurationCollectionResponse struct {
	value interface{}
}

type Windows10GeneralConfiguration struct {
	accountsBlockAddingNonMicrosoftAccountEmail interface{}
	antiTheftModeBlocked interface{}
	appsAllowTrustedAppsSideloading string
	appsBlockWindowsStoreOriginatedApps interface{}
	assignments interface{}
	bluetoothAllowedServices interface{}
	bluetoothBlockAdvertising interface{}
	bluetoothBlockDiscoverableMode interface{}
	bluetoothBlockPrePairing interface{}
	bluetoothBlocked interface{}
	cameraBlocked interface{}
	cellularBlockDataWhenRoaming interface{}
	cellularBlockVpn interface{}
	cellularBlockVpnWhenRoaming interface{}
	certificatesBlockManualRootCertificateInstallation interface{}
	connectedDevicesServiceBlocked interface{}
	copyPasteBlocked interface{}
	cortanaBlocked interface{}
	createdDateTime string
	defenderBlockEndUserAccess interface{}
	defenderCloudBlockLevel string
	defenderDaysBeforeDeletingQuarantinedMalware interface{}
	defenderDetectedMalwareActions interface{}
	defenderFileExtensionsToExclude interface{}
	defenderFilesAndFoldersToExclude interface{}
	defenderMonitorFileActivity string
	defenderProcessesToExclude interface{}
	defenderPromptForSampleSubmission string
	defenderRequireBehaviorMonitoring interface{}
	defenderRequireCloudProtection interface{}
	defenderRequireNetworkInspectionSystem interface{}
	defenderRequireRealTimeMonitoring interface{}
	defenderScanArchiveFiles interface{}
	defenderScanDownloads interface{}
	defenderScanIncomingMail interface{}
	defenderScanMappedNetworkDrivesDuringFullScan interface{}
	defenderScanMaxCpu interface{}
	defenderScanNetworkFiles interface{}
	defenderScanRemovableDrivesDuringFullScan interface{}
	defenderScanScriptsLoadedInInternetExplorer interface{}
	defenderScanType string
	defenderScheduledQuickScanTime string
	defenderScheduledScanTime string
	defenderSignatureUpdateIntervalInHours interface{}
	defenderSystemScanSchedule string
	description string
	developerUnlockSetting string
	deviceManagementBlockFactoryResetOnMobile interface{}
	deviceManagementBlockManualUnenroll interface{}
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	diagnosticsDataSubmissionMode string
	displayName string
	edgeAllowStartPagesModification interface{}
	edgeBlockAccessToAboutFlags interface{}
	edgeBlockAddressBarDropdown interface{}
	edgeBlockAutofill interface{}
	edgeBlockCompatibilityList interface{}
	edgeBlockDeveloperTools interface{}
	edgeBlockExtensions interface{}
	edgeBlockInPrivateBrowsing interface{}
	edgeBlockJavaScript interface{}
	edgeBlockLiveTileDataCollection interface{}
	edgeBlockPasswordManager interface{}
	edgeBlockPopups interface{}
	edgeBlockSearchSuggestions interface{}
	edgeBlockSendingDoNotTrackHeader interface{}
	edgeBlockSendingIntranetTrafficToInternetExplorer interface{}
	edgeBlocked interface{}
	edgeClearBrowsingDataOnExit interface{}
	edgeCookiePolicy string
	edgeDisableFirstRunPage interface{}
	edgeEnterpriseModeSiteListLocation string
	edgeFirstRunUrl string
	edgeHomepageUrls interface{}
	edgeRequireSmartScreen interface{}
	edgeSearchEngine interface{}
	edgeSendIntranetTrafficToInternetExplorer interface{}
	edgeSyncFavoritesWithInternetExplorer interface{}
	enterpriseCloudPrintDiscoveryEndPoint string
	enterpriseCloudPrintDiscoveryMaxLimit interface{}
	enterpriseCloudPrintMopriaDiscoveryResourceIdentifier string
	enterpriseCloudPrintOAuthAuthority string
	enterpriseCloudPrintOAuthClientIdentifier string
	enterpriseCloudPrintResourceIdentifier string
	experienceBlockDeviceDiscovery interface{}
	experienceBlockErrorDialogWhenNoSIM interface{}
	experienceBlockTaskSwitcher interface{}
	gameDvrBlocked interface{}
	id string
	internetSharingBlocked interface{}
	lastModifiedDateTime string
	locationServicesBlocked interface{}
	lockScreenAllowTimeoutConfiguration interface{}
	lockScreenBlockActionCenterNotifications interface{}
	lockScreenBlockCortana interface{}
	lockScreenBlockToastNotifications interface{}
	lockScreenTimeoutInSeconds interface{}
	logonBlockFastUserSwitching interface{}
	microsoftAccountBlockSettingsSync interface{}
	microsoftAccountBlocked interface{}
	networkProxyApplySettingsDeviceWide interface{}
	networkProxyAutomaticConfigurationUrl string
	networkProxyDisableAutoDetect interface{}
	networkProxyServer interface{}
	nfcBlocked interface{}
	oneDriveDisableFileSync interface{}
	passwordBlockSimple interface{}
	passwordExpirationDays interface{}
	passwordMinimumCharacterSetCount interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeScreenTimeout interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequireWhenResumeFromIdleState interface{}
	passwordRequired interface{}
	passwordRequiredType string
	passwordSignInFailureCountBeforeFactoryReset interface{}
	personalizationDesktopImageUrl string
	personalizationLockScreenImageUrl string
	privacyAdvertisingId string
	privacyAutoAcceptPairingAndConsentPrompts interface{}
	privacyBlockInputPersonalization interface{}
	resetProtectionModeBlocked interface{}
	safeSearchFilter string
	screenCaptureBlocked interface{}
	searchBlockDiacritics interface{}
	searchDisableAutoLanguageDetection interface{}
	searchDisableIndexerBackoff interface{}
	searchDisableIndexingEncryptedItems interface{}
	searchDisableIndexingRemovableDrive interface{}
	searchEnableAutomaticIndexSizeManangement interface{}
	searchEnableRemoteQueries interface{}
	settingsBlockAccountsPage interface{}
	settingsBlockAddProvisioningPackage interface{}
	settingsBlockAppsPage interface{}
	settingsBlockChangeLanguage interface{}
	settingsBlockChangePowerSleep interface{}
	settingsBlockChangeRegion interface{}
	settingsBlockChangeSystemTime interface{}
	settingsBlockDevicesPage interface{}
	settingsBlockEaseOfAccessPage interface{}
	settingsBlockEditDeviceName interface{}
	settingsBlockGamingPage interface{}
	settingsBlockNetworkInternetPage interface{}
	settingsBlockPersonalizationPage interface{}
	settingsBlockPrivacyPage interface{}
	settingsBlockRemoveProvisioningPackage interface{}
	settingsBlockSettingsApp interface{}
	settingsBlockSystemPage interface{}
	settingsBlockTimeLanguagePage interface{}
	settingsBlockUpdateSecurityPage interface{}
	sharedUserAppDataAllowed interface{}
	smartScreenBlockPromptOverride interface{}
	smartScreenBlockPromptOverrideForFiles interface{}
	smartScreenEnableAppInstallControl interface{}
	startBlockUnpinningAppsFromTaskbar interface{}
	startMenuAppListVisibility string
	startMenuHideChangeAccountSettings interface{}
	startMenuHideFrequentlyUsedApps interface{}
	startMenuHideHibernate interface{}
	startMenuHideLock interface{}
	startMenuHidePowerButton interface{}
	startMenuHideRecentJumpLists interface{}
	startMenuHideRecentlyAddedApps interface{}
	startMenuHideRestartOptions interface{}
	startMenuHideShutDown interface{}
	startMenuHideSignOut interface{}
	startMenuHideSleep interface{}
	startMenuHideSwitchAccount interface{}
	startMenuHideUserTile interface{}
	startMenuLayoutEdgeAssetsXml string
	startMenuLayoutXml string
	startMenuMode string
	startMenuPinnedFolderDocuments string
	startMenuPinnedFolderDownloads string
	startMenuPinnedFolderFileExplorer string
	startMenuPinnedFolderHomeGroup string
	startMenuPinnedFolderMusic string
	startMenuPinnedFolderNetwork string
	startMenuPinnedFolderPersonalFolder string
	startMenuPinnedFolderPictures string
	startMenuPinnedFolderSettings string
	startMenuPinnedFolderVideos string
	storageBlockRemovableStorage interface{}
	storageRequireMobileDeviceEncryption interface{}
	storageRestrictAppDataToSystemVolume interface{}
	storageRestrictAppInstallToSystemVolume interface{}
	tenantLockdownRequireNetworkDuringOutOfBoxExperience interface{}
	usbBlocked interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
	voiceRecordingBlocked interface{}
	webRtcBlockLocalhostIpAddress interface{}
	wiFiBlockAutomaticConnectHotspots interface{}
	wiFiBlockManualConfiguration interface{}
	wiFiBlocked interface{}
	wiFiScanInterval interface{}
	windowsSpotlightBlockConsumerSpecificFeatures interface{}
	windowsSpotlightBlockOnActionCenter interface{}
	windowsSpotlightBlockTailoredExperiences interface{}
	windowsSpotlightBlockThirdPartyNotifications interface{}
	windowsSpotlightBlockWelcomeExperience interface{}
	windowsSpotlightBlockWindowsTips interface{}
	windowsSpotlightBlocked interface{}
	windowsSpotlightConfigureOnLockScreen string
	windowsStoreBlockAutoUpdate interface{}
	windowsStoreBlocked interface{}
	windowsStoreEnablePrivateStoreOnly interface{}
	wirelessDisplayBlockProjectionToThisDevice interface{}
	wirelessDisplayBlockUserInputFromReceiver interface{}
	wirelessDisplayRequirePinForPairing interface{}
}

type Windows10GeneralConfigurationCollectionResponse struct {
	value interface{}
}

type Windows10MobileCompliancePolicy struct {
	assignments interface{}
	bitLockerEnabled interface{}
	codeIntegrityEnabled interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	earlyLaunchAntiMalwareDriverEnabled interface{}
	id string
	lastModifiedDateTime string
	osMaximumVersion string
	osMinimumVersion string
	passwordBlockSimple interface{}
	passwordExpirationDays interface{}
	passwordMinimumCharacterSetCount interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeLock interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequireToUnlockFromIdle interface{}
	passwordRequired interface{}
	passwordRequiredType string
	scheduledActionsForRule interface{}
	secureBootEnabled interface{}
	storageRequireEncryption interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type Windows10MobileCompliancePolicyCollectionResponse struct {
	value interface{}
}

type Windows10NetworkProxyServer struct {
	address string
	exceptions interface{}
	useForLocalAddresses interface{}
}

type Windows10SecureAssessmentConfiguration struct {
	allowPrinting interface{}
	allowScreenCapture interface{}
	allowTextSuggestion interface{}
	assignments interface{}
	configurationAccount string
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	launchUri string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type Windows10SecureAssessmentConfigurationCollectionResponse struct {
	value interface{}
}

type Windows10TeamGeneralConfiguration struct {
	assignments interface{}
	azureOperationalInsightsBlockTelemetry interface{}
	azureOperationalInsightsWorkspaceId string
	azureOperationalInsightsWorkspaceKey string
	connectAppBlockAutoLaunch interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	maintenanceWindowBlocked interface{}
	maintenanceWindowDurationInHours interface{}
	maintenanceWindowStartTime string
	miracastBlocked interface{}
	miracastChannel string
	miracastRequirePin interface{}
	settingsBlockMyMeetingsAndFiles interface{}
	settingsBlockSessionResume interface{}
	settingsBlockSigninSuggestions interface{}
	settingsDefaultVolume interface{}
	settingsScreenTimeoutInMinutes interface{}
	settingsSessionTimeoutInMinutes interface{}
	settingsSleepTimeoutInMinutes interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
	welcomeScreenBackgroundImageUrl string
	welcomeScreenBlockAutomaticWakeUp interface{}
	welcomeScreenMeetingInformation string
}

type Windows10TeamGeneralConfigurationCollectionResponse struct {
	value interface{}
}

type Windows81CompliancePolicy struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	osMaximumVersion string
	osMinimumVersion string
	passwordBlockSimple interface{}
	passwordExpirationDays interface{}
	passwordMinimumCharacterSetCount interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeLock interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequired interface{}
	passwordRequiredType string
	scheduledActionsForRule interface{}
	storageRequireEncryption interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type Windows81CompliancePolicyCollectionResponse struct {
	value interface{}
}

type Windows81GeneralConfiguration struct {
	accountsBlockAddingNonMicrosoftAccountEmail interface{}
	applyOnlyToWindows81 interface{}
	assignments interface{}
	browserBlockAutofill interface{}
	browserBlockAutomaticDetectionOfIntranetSites interface{}
	browserBlockEnterpriseModeAccess interface{}
	browserBlockJavaScript interface{}
	browserBlockPlugins interface{}
	browserBlockPopups interface{}
	browserBlockSendingDoNotTrackHeader interface{}
	browserBlockSingleWordEntryOnIntranetSites interface{}
	browserEnterpriseModeSiteListLocation string
	browserInternetSecurityLevel string
	browserIntranetSecurityLevel string
	browserLoggingReportLocation string
	browserRequireFirewall interface{}
	browserRequireFraudWarning interface{}
	browserRequireHighSecurityForRestrictedSites interface{}
	browserRequireSmartScreen interface{}
	browserTrustedSitesSecurityLevel string
	cellularBlockDataRoaming interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	diagnosticsBlockDataSubmission interface{}
	displayName string
	id string
	lastModifiedDateTime string
	passwordBlockPicturePasswordAndPin interface{}
	passwordExpirationDays interface{}
	passwordMinimumCharacterSetCount interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeScreenTimeout interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequiredType string
	passwordSignInFailureCountBeforeFactoryReset interface{}
	storageRequireDeviceEncryption interface{}
	updatesRequireAutomaticUpdates interface{}
	userAccountControlSettings string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
	workFoldersUrl string
}

type Windows81GeneralConfigurationCollectionResponse struct {
	value interface{}
}

type WindowsAutopilotDeviceIdentity struct {
	addressableUserName string
	azureActiveDirectoryDeviceId string
	displayName string
	enrollmentState string
	groupTag string
	id string
	lastContactedDateTime string
	managedDeviceId string
	manufacturer string
	model string
	productKey string
	purchaseOrderIdentifier string
	resourceName string
	serialNumber string
	skuNumber string
	systemFamily string
	userPrincipalName string
}

type WindowsAutopilotDeviceIdentityCollectionResponse struct {
	value interface{}
}

type WindowsDefenderAdvancedThreatProtectionConfiguration struct {
	allowSampleSharing interface{}
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	enableExpeditedTelemetryReporting interface{}
	id string
	lastModifiedDateTime string
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type WindowsDefenderAdvancedThreatProtectionConfigurationCollectionResponse struct {
	value interface{}
}

type WindowsDefenderScanActionResult struct {
	actionName string
	actionState string
	lastUpdatedDateTime string
	scanType string
	startDateTime string
}

type WindowsDeviceADAccount struct {
	domainName string
	password string
	userName string
}

type WindowsDeviceAccount struct {
	password string
}

type WindowsDeviceAzureADAccount struct {
	password string
	userPrincipalName string
}

type WindowsFirewallNetworkProfile struct {
	authorizedApplicationRulesFromGroupPolicyMerged interface{}
	connectionSecurityRulesFromGroupPolicyMerged interface{}
	firewallEnabled string
	globalPortRulesFromGroupPolicyMerged interface{}
	inboundConnectionsBlocked interface{}
	inboundNotificationsBlocked interface{}
	incomingTrafficBlocked interface{}
	outboundConnectionsBlocked interface{}
	policyRulesFromGroupPolicyMerged interface{}
	securedPacketExemptionAllowed interface{}
	stealthModeBlocked interface{}
	unicastResponsesToMulticastBroadcastsBlocked interface{}
}

type WindowsHelloForBusinessAuthenticationMethod struct {
	createdDateTime string
	device interface{}
	displayName string
	id string
	keyStrength interface{}
}

type WindowsHelloForBusinessAuthenticationMethodCollectionResponse struct {
	value interface{}
}

type WindowsInformationProtection struct {
	assignments interface{}
	azureRightsManagementServicesAllowed interface{}
	createdDateTime string
	dataRecoveryCertificate interface{}
	description string
	displayName string
	enforcementLevel string
	enterpriseDomain string
	enterpriseIPRanges interface{}
	enterpriseIPRangesAreAuthoritative interface{}
	enterpriseInternalProxyServers interface{}
	enterpriseNetworkDomainNames interface{}
	enterpriseProtectedDomainNames interface{}
	enterpriseProxiedDomains interface{}
	enterpriseProxyServers interface{}
	enterpriseProxyServersAreAuthoritative interface{}
	exemptAppLockerFiles interface{}
	exemptApps interface{}
	iconsVisible interface{}
	id string
	indexingEncryptedStoresOrItemsBlocked interface{}
	isAssigned interface{}
	lastModifiedDateTime string
	neutralDomainResources interface{}
	protectedAppLockerFiles interface{}
	protectedApps interface{}
	protectionUnderLockConfigRequired interface{}
	revokeOnUnenrollDisabled interface{}
	rightsManagementServicesTemplateId string
	smbAutoEncryptedFileExtensions interface{}
	version string
}

type WindowsInformationProtectionApp struct {
	denied interface{}
	description string
	displayName string
	productName string
	publisherName string
}

type WindowsInformationProtectionAppCollectionResponse struct {
	value interface{}
}

type WindowsInformationProtectionAppLearningSummary struct {
	applicationName string
	applicationType string
	deviceCount interface{}
	id string
}

type WindowsInformationProtectionAppLearningSummaryCollectionResponse struct {
	value interface{}
}

type WindowsInformationProtectionAppLockerFile struct {
	displayName string
	file string
	fileHash string
	id string
	version string
}

type WindowsInformationProtectionAppLockerFileCollectionResponse struct {
	value interface{}
}

type WindowsInformationProtectionCollectionResponse struct {
	value interface{}
}

type WindowsInformationProtectionDataRecoveryCertificate struct {
	certificate string
	description string
	expirationDateTime string
	subjectName string
}

type WindowsInformationProtectionDesktopApp struct {
	binaryName string
	binaryVersionHigh string
	binaryVersionLow string
	denied interface{}
	description string
	displayName string
	productName string
	publisherName string
}

type WindowsInformationProtectionIPRangeCollection struct {
	displayName string
	ranges interface{}
}

type WindowsInformationProtectionIPRangeCollectionCollectionResponse struct {
	value interface{}
}

type WindowsInformationProtectionNetworkLearningSummary struct {
	deviceCount interface{}
	id string
	url string
}

type WindowsInformationProtectionNetworkLearningSummaryCollectionResponse struct {
	value interface{}
}

type WindowsInformationProtectionPolicy struct {
	assignments interface{}
	azureRightsManagementServicesAllowed interface{}
	createdDateTime string
	dataRecoveryCertificate interface{}
	daysWithoutContactBeforeUnenroll interface{}
	description string
	displayName string
	enforcementLevel string
	enterpriseDomain string
	enterpriseIPRanges interface{}
	enterpriseIPRangesAreAuthoritative interface{}
	enterpriseInternalProxyServers interface{}
	enterpriseNetworkDomainNames interface{}
	enterpriseProtectedDomainNames interface{}
	enterpriseProxiedDomains interface{}
	enterpriseProxyServers interface{}
	enterpriseProxyServersAreAuthoritative interface{}
	exemptAppLockerFiles interface{}
	exemptApps interface{}
	iconsVisible interface{}
	id string
	indexingEncryptedStoresOrItemsBlocked interface{}
	isAssigned interface{}
	lastModifiedDateTime string
	mdmEnrollmentUrl string
	minutesOfInactivityBeforeDeviceLock interface{}
	neutralDomainResources interface{}
	numberOfPastPinsRemembered interface{}
	passwordMaximumAttemptCount interface{}
	pinExpirationDays interface{}
	pinLowercaseLetters string
	pinMinimumLength interface{}
	pinSpecialCharacters string
	pinUppercaseLetters string
	protectedAppLockerFiles interface{}
	protectedApps interface{}
	protectionUnderLockConfigRequired interface{}
	revokeOnMdmHandoffDisabled interface{}
	revokeOnUnenrollDisabled interface{}
	rightsManagementServicesTemplateId string
	smbAutoEncryptedFileExtensions interface{}
	version string
	windowsHelloForBusinessBlocked interface{}
}

type WindowsInformationProtectionPolicyCollectionResponse struct {
	value interface{}
}

type WindowsInformationProtectionProxiedDomainCollection struct {
	displayName string
	proxiedDomains interface{}
}

type WindowsInformationProtectionProxiedDomainCollectionCollectionResponse struct {
	value interface{}
}

type WindowsInformationProtectionResourceCollection struct {
	displayName string
	resources interface{}
}

type WindowsInformationProtectionResourceCollectionCollectionResponse struct {
	value interface{}
}

type WindowsInformationProtectionStoreApp struct {
	denied interface{}
	description string
	displayName string
	productName string
	publisherName string
}

type WindowsMinimumOperatingSystem struct {
	v10_0 interface{}
	v8_0 interface{}
	v8_1 interface{}
}

type WindowsMobileMSI struct {
	assignments interface{}
	categories interface{}
	commandLine string
	committedContentVersion string
	contentVersions interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	fileName string
	id string
	ignoreVersionDetection interface{}
	informationUrl string
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	notes string
	owner string
	privacyInformationUrl string
	productCode string
	productVersion string
	publisher string
	publishingState string
	size interface{}
}

type WindowsMobileMSICollectionResponse struct {
	value interface{}
}

type WindowsPhone81CompliancePolicy struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	osMaximumVersion string
	osMinimumVersion string
	passwordBlockSimple interface{}
	passwordExpirationDays interface{}
	passwordMinimumCharacterSetCount interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeLock interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequired interface{}
	passwordRequiredType string
	scheduledActionsForRule interface{}
	storageRequireEncryption interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type WindowsPhone81CompliancePolicyCollectionResponse struct {
	value interface{}
}

type WindowsPhone81CustomConfiguration struct {
	assignments interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	id string
	lastModifiedDateTime string
	omaSettings interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type WindowsPhone81CustomConfigurationCollectionResponse struct {
	value interface{}
}

type WindowsPhone81GeneralConfiguration struct {
	applyOnlyToWindowsPhone81 interface{}
	appsBlockCopyPaste interface{}
	assignments interface{}
	bluetoothBlocked interface{}
	cameraBlocked interface{}
	cellularBlockWifiTethering interface{}
	compliantAppListType string
	compliantAppsList interface{}
	createdDateTime string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	diagnosticDataBlockSubmission interface{}
	displayName string
	emailBlockAddingAccounts interface{}
	id string
	lastModifiedDateTime string
	locationServicesBlocked interface{}
	microsoftAccountBlocked interface{}
	nfcBlocked interface{}
	passwordBlockSimple interface{}
	passwordExpirationDays interface{}
	passwordMinimumCharacterSetCount interface{}
	passwordMinimumLength interface{}
	passwordMinutesOfInactivityBeforeScreenTimeout interface{}
	passwordPreviousPasswordBlockCount interface{}
	passwordRequired interface{}
	passwordRequiredType string
	passwordSignInFailureCountBeforeFactoryReset interface{}
	screenCaptureBlocked interface{}
	storageBlockRemovableStorage interface{}
	storageRequireEncryption interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
	webBrowserBlocked interface{}
	wifiBlockAutomaticConnectHotspots interface{}
	wifiBlockHotspotReporting interface{}
	wifiBlocked interface{}
	windowsStoreBlocked interface{}
}

type WindowsPhone81GeneralConfigurationCollectionResponse struct {
	value interface{}
}

type WindowsUniversalAppX struct {
	applicableArchitectures string
	applicableDeviceTypes string
	assignments interface{}
	categories interface{}
	committedContentVersion string
	contentVersions interface{}
	createdDateTime string
	description string
	developer string
	displayName string
	fileName string
	id string
	identityName string
	identityPublisherHash string
	identityResourceIdentifier string
	identityVersion string
	informationUrl string
	isBundle interface{}
	isFeatured interface{}
	largeIcon interface{}
	lastModifiedDateTime string
	minimumSupportedOperatingSystem interface{}
	notes string
	owner string
	privacyInformationUrl string
	publisher string
	publishingState string
	size interface{}
}

type WindowsUniversalAppXCollectionResponse struct {
	value interface{}
}

type WindowsUpdateActiveHoursInstall struct {
	activeHoursEnd string
	activeHoursStart string
}

type WindowsUpdateForBusinessConfiguration struct {
	assignments interface{}
	automaticUpdateMode string
	businessReadyUpdatesOnly string
	createdDateTime string
	deliveryOptimizationMode string
	description string
	deviceSettingStateSummaries interface{}
	deviceStatusOverview interface{}
	deviceStatuses interface{}
	displayName string
	driversExcluded interface{}
	featureUpdatesDeferralPeriodInDays interface{}
	featureUpdatesPauseExpiryDateTime string
	featureUpdatesPaused interface{}
	id string
	installationSchedule interface{}
	lastModifiedDateTime string
	microsoftUpdateServiceAllowed interface{}
	prereleaseFeatures string
	qualityUpdatesDeferralPeriodInDays interface{}
	qualityUpdatesPauseExpiryDateTime string
	qualityUpdatesPaused interface{}
	userStatusOverview interface{}
	userStatuses interface{}
	version interface{}
}

type WindowsUpdateForBusinessConfigurationCollectionResponse struct {
	value interface{}
}

type WindowsUpdateScheduledInstall struct {
	scheduledInstallDay string
	scheduledInstallTime string
}

type Workbook struct {
	application interface{}
	comments interface{}
	functions interface{}
	id string
	names interface{}
	operations interface{}
	tables interface{}
	worksheets interface{}
}

type WorkbookApplication struct {
	calculationMode string
	id string
}

type WorkbookChart struct {
	axes interface{}
	dataLabels interface{}
	format interface{}
	height interface{}
	id string
	left interface{}
	legend interface{}
	name string
	series interface{}
	title interface{}
	top interface{}
	width interface{}
	worksheet interface{}
}

type WorkbookChartAreaFormat struct {
	fill interface{}
	font interface{}
	id string
}

type WorkbookChartAxes struct {
	categoryAxis interface{}
	id string
	seriesAxis interface{}
	valueAxis interface{}
}

type WorkbookChartAxis struct {
	format interface{}
	id string
	majorGridlines interface{}
	majorUnit interface{}
	maximum interface{}
	minimum interface{}
	minorGridlines interface{}
	minorUnit interface{}
	title interface{}
}

type WorkbookChartAxisFormat struct {
	font interface{}
	id string
	line interface{}
}

type WorkbookChartAxisTitle struct {
	format interface{}
	id string
	text string
	visible interface{}
}

type WorkbookChartAxisTitleFormat struct {
	font interface{}
	id string
}

type WorkbookChartCollectionResponse struct {
	value interface{}
}

type WorkbookChartDataLabelFormat struct {
	fill interface{}
	font interface{}
	id string
}

type WorkbookChartDataLabels struct {
	format interface{}
	id string
	position string
	separator string
	showBubbleSize interface{}
	showCategoryName interface{}
	showLegendKey interface{}
	showPercentage interface{}
	showSeriesName interface{}
	showValue interface{}
}

type WorkbookChartFill struct {
	id string
}

type WorkbookChartFont struct {
	bold interface{}
	color string
	id string
	italic interface{}
	name string
	size interface{}
	underline string
}

type WorkbookChartGridlines struct {
	format interface{}
	id string
	visible interface{}
}

type WorkbookChartGridlinesFormat struct {
	id string
	line interface{}
}

type WorkbookChartLegend struct {
	format interface{}
	id string
	overlay interface{}
	position string
	visible interface{}
}

type WorkbookChartLegendFormat struct {
	fill interface{}
	font interface{}
	id string
}

type WorkbookChartLineFormat struct {
	color string
	id string
}

type WorkbookChartPoint struct {
	format interface{}
	id string
	value interface{}
}

type WorkbookChartPointCollectionResponse struct {
	value interface{}
}

type WorkbookChartPointFormat struct {
	fill interface{}
	id string
}

type WorkbookChartSeries struct {
	format interface{}
	id string
	name string
	points interface{}
}

type WorkbookChartSeriesCollectionResponse struct {
	value interface{}
}

type WorkbookChartSeriesFormat struct {
	fill interface{}
	id string
	line interface{}
}

type WorkbookChartTitle struct {
	format interface{}
	id string
	overlay interface{}
	text string
	visible interface{}
}

type WorkbookChartTitleFormat struct {
	fill interface{}
	font interface{}
	id string
}

type WorkbookComment struct {
	content string
	contentType string
	id string
	replies interface{}
}

type WorkbookCommentCollectionResponse struct {
	value interface{}
}

type WorkbookCommentReply struct {
	content string
	contentType string
	id string
}

type WorkbookCommentReplyCollectionResponse struct {
	value interface{}
}

type WorkbookFilter struct {
	criteria interface{}
	id string
}

type WorkbookFilterCriteria struct {
	color string
	criterion1 string
	criterion2 string
	dynamicCriteria string
	filterOn string
	icon interface{}
	operator string
	values interface{}
}

type WorkbookFilterDatetime struct {
	date string
	specificity string
}

type WorkbookFormatProtection struct {
	formulaHidden interface{}
	id string
	locked interface{}
}

type WorkbookFunctionResult struct {
	error string
	id string
	value interface{}
}

type WorkbookFunctions struct {
	id string
}

type WorkbookIcon struct {
	index interface{}
	set string
}

type WorkbookNamedItem struct {
	comment string
	id string
	name string
	scope string
	type string
	value interface{}
	visible interface{}
	worksheet interface{}
}

type WorkbookNamedItemCollectionResponse struct {
	value interface{}
}

type WorkbookOperation struct {
	error interface{}
	id string
	resourceLocation string
	status string
}

type WorkbookOperationCollectionResponse struct {
	value interface{}
}

type WorkbookOperationError struct {
	code string
	innerError interface{}
	message string
}

type WorkbookPivotTable struct {
	id string
	name string
	worksheet interface{}
}

type WorkbookPivotTableCollectionResponse struct {
	value interface{}
}

type WorkbookRange struct {
	address string
	addressLocal string
	cellCount interface{}
	columnCount interface{}
	columnHidden interface{}
	columnIndex interface{}
	format interface{}
	formulas interface{}
	formulasLocal interface{}
	formulasR1C1 interface{}
	hidden interface{}
	id string
	numberFormat interface{}
	rowCount interface{}
	rowHidden interface{}
	rowIndex interface{}
	sort interface{}
	text interface{}
	valueTypes interface{}
	values interface{}
	worksheet interface{}
}

type WorkbookRangeBorder struct {
	color string
	id string
	sideIndex string
	style string
	weight string
}

type WorkbookRangeBorderCollectionResponse struct {
	value interface{}
}

type WorkbookRangeFill struct {
	color string
	id string
}

type WorkbookRangeFont struct {
	bold interface{}
	color string
	id string
	italic interface{}
	name string
	size interface{}
	underline string
}

type WorkbookRangeFormat struct {
	borders interface{}
	columnWidth interface{}
	fill interface{}
	font interface{}
	horizontalAlignment string
	id string
	protection interface{}
	rowHeight interface{}
	verticalAlignment string
	wrapText interface{}
}

type WorkbookRangeReference struct {
	address string
}

type WorkbookRangeSort struct {
	id string
}

type WorkbookRangeView struct {
	cellAddresses interface{}
	columnCount interface{}
	formulas interface{}
	formulasLocal interface{}
	formulasR1C1 interface{}
	id string
	index interface{}
	numberFormat interface{}
	rowCount interface{}
	rows interface{}
	text interface{}
	valueTypes interface{}
	values interface{}
}

type WorkbookRangeViewCollectionResponse struct {
	value interface{}
}

type WorkbookSessionInfo struct {
	id string
	persistChanges interface{}
}

type WorkbookSortField struct {
	ascending interface{}
	color string
	dataOption string
	icon interface{}
	key interface{}
	sortOn string
}

type WorkbookSortFieldCollectionResponse struct {
	value interface{}
}

type WorkbookTable struct {
	columns interface{}
	highlightFirstColumn interface{}
	highlightLastColumn interface{}
	id string
	legacyId string
	name string
	rows interface{}
	showBandedColumns interface{}
	showBandedRows interface{}
	showFilterButton interface{}
	showHeaders interface{}
	showTotals interface{}
	sort interface{}
	style string
	worksheet interface{}
}

type WorkbookTableCollectionResponse struct {
	value interface{}
}

type WorkbookTableColumn struct {
	filter interface{}
	id string
	index interface{}
	name string
	values interface{}
}

type WorkbookTableColumnCollectionResponse struct {
	value interface{}
}

type WorkbookTableRow struct {
	id string
	index interface{}
	values interface{}
}

type WorkbookTableRowCollectionResponse struct {
	value interface{}
}

type WorkbookTableSort struct {
	fields interface{}
	id string
	matchCase interface{}
	method string
}

type WorkbookWorksheet struct {
	charts interface{}
	id string
	name string
	names interface{}
	pivotTables interface{}
	position interface{}
	protection interface{}
	tables interface{}
	visibility string
}

type WorkbookWorksheetCollectionResponse struct {
	value interface{}
}

type WorkbookWorksheetProtection struct {
	id string
	options interface{}
	protected interface{}
}

type WorkbookWorksheetProtectionOptions struct {
	allowAutoFilter interface{}
	allowDeleteColumns interface{}
	allowDeleteRows interface{}
	allowFormatCells interface{}
	allowFormatColumns interface{}
	allowFormatRows interface{}
	allowInsertColumns interface{}
	allowInsertHyperlinks interface{}
	allowInsertRows interface{}
	allowPivotTables interface{}
	allowSort interface{}
}

type WorkforceIntegration struct {
	apiVersion interface{}
	createdDateTime string
	displayName string
	encryption interface{}
	id string
	isActive interface{}
	lastModifiedBy interface{}
	lastModifiedDateTime string
	supportedEntities interface{}
	url string
}

type WorkforceIntegrationCollectionResponse struct {
	value interface{}
}

type WorkforceIntegrationEncryption struct {
	protocol interface{}
	secret string
}

type WorkingHours struct {
	daysOfWeek interface{}
	endTime string
	startTime string
	timeZone interface{}
}