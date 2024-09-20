package azure

import "github.com/infracost/infracost/internal/schema"

// ResourceRegistry grouped alphabetically
var ResourceRegistry []*schema.RegistryItem = []*schema.RegistryItem{
	// getActiveDirectoryDomainServiceRegistryItem(),
	// getActiveDirectoryDomainServiceReplicaSetRegistryItem(),
	// getAPIManagementRegistryItem(),
	// getApplicationGatewayRegistryItem(),
	// getAppServiceEnvironmentRegistryItem(),
	// GetAzureRMAppIntegrationServiceEnvironmentRegistryItem(),
	// getFunctionAppRegistryItem(),
	// GetAzureRMAppNATGatewayRegistryItem(),
	// getAppServiceCertificateBindingRegistryItem(),
	// getAppServiceCertificateOrderRegistryItem(),
	// getAppServiceCustomHostnameBindingRegistryItem(),
	// getAppServicePlanRegistryItem(),
	// getApplicationInsightsWebTestRegistryItem(),
	// getApplicationInsightsRegistryItem(),
	// getAutomationAccountRegistryItem(),
	// getAutomationDSCConfigurationRegistryItem(),
	// getAutomationDSCNodeConfigurationRegistryItem(),
	// getAutomationJobScheduleRegistryItem(),
	// getBastionHostRegistryItem(),
	// GetAzureRMCDNEndpointRegistryItem(),
	// getContainerRegistryRegistryItem(),
	// getCosmosDBAccountRegistryItem(),
	// GetAzureRMCosmosdbCassandraKeyspaceRegistryItem(),
	// GetAzureRMCosmosdbCassandraTableRegistryItem(),
	// GetAzureRMCosmosdbGremlinDatabaseRegistryItem(),
	// GetAzureRMCosmosdbGremlinGraphRegistryItem(),
	// GetAzureRMCosmosdbMongoCollectionRegistryItem(),
	// GetAzureRMCosmosdbMongoDatabaseRegistryItem(),
	// GetAzureRMCosmosdbSQLContainerRegistryItem(),
	// GetAzureRMCosmosdbSQLDatabaseRegistryItem(),
	// GetAzureRMCosmosdbTableRegistryItem(),
	// getDatabricksWorkspaceRegistryItem(),
	// getDNSARecordRegistryItem(),
	// getDNSAAAARecordRegistryItem(),
	// getDNSCAARecordRegistryItem(),
	// getDNSCNameRecordRegistryItem(),
	// getDNSMXRecordRegistryItem(),
	// getDNSNSRecordRegistryItem(),
	// getDNSPtrRecordRegistryItem(),
	// getDNSSrvRecordRegistryItem(),
	// getDNSTxtRecordRegistryItem(),
	// getDNSPrivateZoneRegistryItem(),
	// getDNSZoneRegistryItem(),
	// GetAzureRMEventHubsNamespaceRegistryItem(),
	// getExpressRouteConnectionRegistryItem(),
	// getExpressRouteGatewayRegistryItem(),
	// GetAzureRMFirewallRegistryItem(),
	// getAzureRMFirewallPolicyRegistryItem(),
	// getAzureRMFirewallPolicyRuleCollectionGroupRegistryItem(),
	// getFrontdoorFirewallPolicyRegistryItem(),
	// getFrontdoorRegistryItem(),
	// GetAzureRMHDInsightHadoopClusterRegistryItem(),
	// GetAzureRMHDInsightHBaseClusterRegistryItem(),
	// GetAzureRMHDInsightInteractiveQueryClusterRegistryItem(),
	// GetAzureRMHDInsightKafkaClusterRegistryItem(),
	// GetAzureRMHDInsightSparkClusterRegistryItem(),
	// GetAzureRMKeyVaultCertificateRegistryItem(),
	// GetAzureRMKeyVaultKeyRegistryItem(),
	// GetAzureRMKeyVaultManagedHSMRegistryItem(),
	// getKubernetesClusterRegistryItem(),
	// getKubernetesClusterNodePoolRegistryItem(),
	// getLoadBalancerRegistryItem(),
	// GetAzureRMLoadBalancerRuleRegistryItem(),
	// GetAzureRMLoadBalancerOutboundRuleRegistryItem(),
	// getLinuxFunctionAppRegistryItem(),
	getLinuxVirtualMachineRegistryItem(),
	// getLinuxVirtualMachineScaleSetRegistryItem(),
	// getLogAnalyticsWorkspaceRegistryItem(),
	getManagedDiskRegistryItem(),
	// GetAzureRMMariaDBServerRegistryItem(),
	// getMSSQLDatabaseRegistryItem(),
	// GetAzureRMMySQLServerRegistryItem(),
	// GetAzureRMNotificationHubNamespaceRegistryItem(),
	// getPointToSiteVpnGatewayRegistryItem(),
	// getPostgreSQLFlexibleServerRegistryItem(),
	// GetAzureRMPostgreSQLServerRegistryItem(),
	// getPrivateDNSARecordRegistryItem(),
	// getPrivateDNSAAAARecordRegistryItem(),
	// getPrivateDNSCNameRecordRegistryItem(),
	// getPrivateDNSMXRecordRegistryItem(),
	// getPrivateDNSPTRRecordRegistryItem(),
	// getPrivateDNSSRVRecordRegistryItem(),
	// getPrivateDNSTXTRecordRegistryItem(),
	// GetAzureRMPrivateEndpointRegistryItem(),
	// GetAzureRMPublicIPRegistryItem(),
	// GetAzureRMPublicIPPrefixRegistryItem(),
	// GetAzureRMSearchServiceRegistryItem(),
	// GetAzureRMRedisCacheRegistryItem(),
	// getAzureRMMSSQLManagedInstanceRegistryItem(),
	// getStorageAccountRegistryItem(),
	// getSQLDatabaseRegistryItem(),
	// getSQLManagedInstanceRegistryItem(),
	// GetAzureRMSynapseSparkPoolRegistryItem(),
	// GetAzureRMSynapseSQLPoolRegistryItem(),
	// GetAzureRMSynapseWorkspacRegistryItem(),
	// getVirtualHubRegistryItem(),
	// getVirtualMachineScaleSetRegistryItem(),
	// getVirtualMachineRegistryItem(),
	// GetAzureRMVirtualNetworkGatewayConnectionRegistryItem(),
	// GetAzureRMVirtualNetworkGatewayRegistryItem(),
	// getWindowsVirtualMachineRegistryItem(),
	// getWindowsVirtualMachineScaleSetRegistryItem(),
	// getVPNGatewayRegistryItem(),
	// getVPNGatewayConnectionRegistryItem(),
	// getDataFactoryRegistryItem(),
	// getDataFactoryIntegrationRuntimeAzureRegistryItem(),
	// getDataFactoryIntegrationRuntimeAzureSSISRegistryItem(),
	// getDataFactoryIntegrationRuntimeManagedRegistryItem(),
	// getDataFactoryIntegrationRuntimeSelfHostedRegistryItem(),
	// getLogAnalyticsSolutionRegistryItem(),
	// getMySQLFlexibleServerRegistryItem(),
	// getServicePlanRegistryItem(),
	// getSentinelDataConnectorAwsCloudTrailRegistryItem(),
	// getSentinelDataConnectorAzureActiveDirectoryRegistryItem(),
	// getSentinelDataConnectorAzureAdvancedThreatProtectionRegistryItem(),
	// getSentinelDataConnectorAzureSecurityCenterRegistryItem(),
	// getSentinelDataConnectorMicrosoftCloudAppSecurityRegistryItem(),
	// getSentinelDataConnectorMicrosoftDefenderAdvancedThreatProtectionRegistryItem(),
	// getSentinelDataConnectorOffice365RegistryItem(),
	// getSentinelDataConnectorThreatIntelligenceRegistryItem(),
	// getIoTHubRegistryItem(),
	// getIoTHubDPSRegistryItem(),
	// getVirtualNetworkPeeringRegistryItem(),
	// geWindowsFunctionAppRegistryItem(),
	// getPowerBIEmbeddedRegistryItem(),
	// getMSSQLElasticPoolRegistryItem(),
	// getSQLElasticPoolRegistryItem(),
	// getMonitorActionGroupRegistryItem(),
	// getMonitorDataCollectionRuleRegistryItem(),
	// getMonitorDiagnosticSettingRegistryItem(),
	// getMonitorMetricAlertRegistryItem(),
	// getMonitorScheduledQueryRulesAlertRegistryItem(),
	// getMonitorScheduledQueryRulesAlertV2RegistryItem(),
	// getApplicationInsightsStandardWebTestRegistryItem(),
	// getRecoveryServicesVaultRegistryItem(),
	// getBackupProtectedVmRegistryItem(),
	// getStorageManagementPolicyRegistryItem(),
	// getStorageQueueRegistryItem(),
	// getStorageShareRegistryItem(),
	// getLogicAppIntegrationAccountRegistryItem(),
	// getSignalRServiceRegistryItem(),
	// getTrafficManagerProfileRegistryItem(),
	// getTrafficManagerAzureEndpointRegistryItem(),
	// getTrafficManagerExternalEndpointRegistryItem(),
	// getTrafficManagerNestedEndpointRegistryItem(),
	// getEventgridSystemTopicRegistryItem(),
	// getEventgridTopicRegistryItem(),
	// getSecurityCenterSubscriptionPricingRegistryItem(),
	// getNetworkWatcherFlowLogRegistryItem(),
	// getNetworkWatcherRegistryItem(),
	// getNetworkConnectionMonitorRegistryItem(),
	// getServiceBusNamespaceRegistryItem(),
	// getLogicAppStandardRegistryItem(),
	// getImageRegistryItem(),
	// getSnapshotRegistryItem(),
	// getPrivateDnsResolverInboundEndpointRegistryItem(),
	// getPrivateDnsResolverOutboundEndpointRegistryItem(),
	// getPrivateDnsResolverDnsForwardingRulesetRegistryItem(),
	// getMachineLearningComputeInstanceRegistryItem(),
	// getMachineLearningComputeClusterRegistryItem(),
	// getNetworkDdosProtectionPlanRegistryItem(),
	// getAppConfigurationRegistryItem(),
	// getFederatedIdentityCredentialRegistryItem(),
	// getCognitiveAccountRegistryItem(),
	// getCognitiveDeploymentRegistryItem(),
}

var FreeResources = []string{
	// Azure App Configuration
	"Microsoft.AppConfiguration/configurationStores/AppConfigurationFeature/Label",
	"Microsoft.AppConfiguration/configurationStores/AppConfigurationKey/Label",
	// Azure AI Services
	"Microsoft.CognitiveServices/accounts",
	// Azure Api Management
	"Microsoft.ApiManagement/service/apis",
	"Microsoft.ApiManagement/service/apis/diagnostics",
	"Microsoft.ApiManagement/service/apis/operations",
	"Microsoft.ApiManagement/service/apis/operations/tags",
	"Microsoft.ApiManagement/service/apis/schemas",
	"Microsoft.ApiManagement/service/apiVersionSets",
	"Microsoft.ApiManagement/service/authorizationServers",
	"Microsoft.ApiManagement/service/backends",
	"Microsoft.ApiManagement/service/certificates",
	"Microsoft.ApiManagement/service/customDomains",
	"Microsoft.ApiManagement/service/diagnostics",
	"Microsoft.ApiManagement/service/templates",
	"Microsoft.ApiManagement/service/groups",
	"Microsoft.ApiManagement/service/groups/users",
	"Microsoft.ApiManagement/service/identityProviders",
	"Microsoft.ApiManagement/service/loggers",
	"Microsoft.ApiManagement/service/namedValues",
	"Microsoft.ApiManagement/service/openidConnectProviders",
	"Microsoft.ApiManagement/service",
	"Microsoft.ApiManagement/service/products",
	"Microsoft.ApiManagement/service/products/apis",
	"Microsoft.ApiManagement/service/products/groups",
	"Microsoft.ApiManagement/service/subscriptions",
	"Microsoft.ApiManagement/service/users",

	// Azure Application Gateway
	"Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies",

	// Azure App Service
	"Microsoft.Web/sites",
	"Microsoft.Web/certificates",
	"Microsoft.Web/sites/slots",
	"Microsoft.Web/sites/slots/config",
	"Microsoft.Web/sites/config",

	// Azure Attestation
	"Microsoft.Attestation/attestationProviders",

	// Azure Automation
	"Microsoft.Automation/automationAccounts/certificates",
	"Microsoft.Automation/automationAccounts/connections",
	"Microsoft.Automation/automationAccounts/connectionTypes",
	"Microsoft.Automation/automationAccounts/credentials",
	"Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups/hybridRunbookWorkers",
	"Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups",
	"Microsoft.Automation/automationAccounts/modules",
	"Microsoft.Automation/automationAccounts/runbooks",
	"Microsoft.Automation/automationAccounts/schedules",
	"Microsoft.Automation/automationAccounts/softwareUpdateConfigurations",
	"Microsoft.Automation/automationAccounts/sourceControls",
	"Microsoft.Automation/automationAccounts/variables",
	"Microsoft.Automation/automationAccounts/webHooks",

	// Azure Backup & Recovery Services Vault
	"Microsoft.RecoveryServices/vaults/backupPolicies",
	"Microsoft.RecoveryServices/vaults/replicationFabrics/replicationNetworks/replicationNetworkMappings",
	"Microsoft.RecoveryServices/vaults/replicationPolicies",

	// Azure Base
	"Microsoft.Resources/resourceGroups",
	"Microsoft.PolicyInsights",
	"Microsoft.Subscription/aliases",
	"Microsoft.Authorization/roleAssignments",
	"Microsoft.Authorization/roleDefinitions",
	"Microsoft.ManagedIdentity/userAssignedIdentities",

	// Azure Blueprints
	"Microsoft.Blueprint/blueprintAssignments",

	// Azure CDN
	"Microsoft.Cdn/profiles/associations",
	"Microsoft.Cdn/profiles",

	// Azure Consumption
	"Microsoft.Consumption/budgets",

	// Azure CosmosDB
	"Microsoft.DocumentDB/databaseAccounts/notebookWorkspaces",
	"Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments",
	"Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions",
	"Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/storedProcedures",
	"Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/triggers",

	// Azure Cost Management
	"Microsoft.CostManagement/scheduledActions",
	"Microsoft.CostManagement/exports",
	"Microsoft.CostManagement/views",

	// Azure DNS
	"Microsoft.Network/privateDnsZones/virtualNetworkLinks",
	"Microsoft.Network/dnsResolvers",

	// Azure Dev Test
	"Microsoft.DevTestLab/schedules",
	"Microsoft.DevTestLab/labs/policySets/policies",
	"Microsoft.DevTestLab/labs/schedules",
	"Microsoft.DevTestLab/labs",

	// Azure Data Factory
	"Microsoft.DataFactory/factories/datasets",
	"Microsoft.DataFactory/factories/dataflows",
	"Microsoft.DataFactory/factories/datasets",
	"Microsoft.DataFactory/factories/linkedservices",
	"Microsoft.DataFactory/factories/managedVirtualNetworks/managedPrivateEndpoints",
	"Microsoft.DataFactory/factories/pipelines",
	"Microsoft.DataFactory/factories/triggers",

	// Azure Database
	"Microsoft.DBforMariaDB/servers/configurations",
	"Microsoft.DBforMariaDB/servers/databases",
	"Microsoft.DBforMariaDB/servers/firewallRules",
	"Microsoft.DBforMariaDB/servers/virtualNetworkRules",

	"Microsoft.DBforMySQL/servers/administrators",
	"Microsoft.DBforMySQL/servers/configurations",
	"Microsoft.DBforMySQL/servers/databases",
	"Microsoft.DBforMySQL/servers/firewallRules",
	"Microsoft.DBforMySQL/flexibleServers/databases",
	"Microsoft.DBforMySQL/flexibleServers/configurations",
	"Microsoft.DBforMySQL/flexibleServers/firewallRules",
	"Microsoft.DBforMySQL/servers/keys",
	"Microsoft.DBforMySQL/servers/virtualNetworkRules",

	"Microsoft.DBforPostgreSQL/servers",
	"Microsoft.DBforPostgreSQL/servers/configurations",
	"Microsoft.DBforPostgreSQL/servers/databases",
	"Microsoft.DBforPostgreSQL/servers/firewallRules",
	"Microsoft.DBforPostgreSQL/flexibleServers/administrators",
	"Microsoft.DBforPostgreSQL/flexibleServers/configurations",
	"Microsoft.DBforPostgreSQL/flexibleServers/databases",
	"Microsoft.DBforPostgreSQL/flexibleServers/firewallRules",
	"Microsoft.DBforPostgreSQL/servers/keys",
	"Microsoft.DBforPostgreSQL/servers/virtualNetworkRules",

	// Azure Event Grid
	"Microsoft.EventGrid/domains",
	"Microsoft.EventGrid/eventSubscriptions",
	"Microsoft.EventGrid/systemTopics/eventSubscriptions",

	// Azure Event Hub
	"Microsoft.EventHub/namespaces/eventhubs",
	"Microsoft.EventHub/namespaces/eventhubs/authorizationRules",
	"Microsoft.EventHub/clusters",
	"Microsoft.EventHub/namespaces/eventhubs/consumerGroups",
	"Microsoft.EventHub/namespaces/authorizationRules",
	"Microsoft.EventHub/namespaces",
	"Microsoft.EventHub/namespaces/disasterRecoveryConfigs",

	// Azure Firewall
	"Microsoft.Network/azureFirewalls/applicationRuleCollections",
	"Microsoft.Network/azureFirewalls/natRuleCollections",
	"Microsoft.Network/azureFirewalls/networkRuleCollections",

	// Azure Front Door
	"Microsoft.Network/frontDoors/customHttpsConfiguration",
	"Microsoft.Network/frontdoors/rulesEngines",

	// Azure Key Vault
	"Microsoft.KeyVault/vaults",
	"Microsoft.KeyVault/vaults/secrets",

	// Azure IoT
	"Microsoft.Devices/iotHubs/certificates",
	"Microsoft.Devices/iotHubs/eventHubEndpoints/consumerGroups",
	"Microsoft.Devices/provisioningServices/certificates",
	"Microsoft.Devices/provisioningServices/keys",
	"Microsoft.Devices/iotHubs/endpoints",
	"Microsoft.Devices/iotHubs/enrichments",
	"Microsoft.Devices/iotHubs/routes",
	"Microsoft.Devices/iotHubs/iotHubKeys",

	// Azure Lighthouse (Delegated Resource Management)
	"Microsoft.ManagedServices/registrationDefinitions",
	"Microsoft.ManagedServices/registrationAssignments",

	// Azure Load Balancer
	"Microsoft.Network/loadBalancers/backendAddressPools",
	"Microsoft.Network/loadBalancers/backendAddressPools/addresses",
	"Microsoft.Network/loadBalancers/inboundNatPools",
	"Microsoft.Network/loadBalancers/inboundNatRules",
	"Microsoft.Network/loadBalancers/probes",

	// Azure Logic App
	"Microsoft.Logic/workflows/actions",
	"Microsoft.Logic/workflows/actions",
	"Microsoft.Logic/integrationAccounts/agreements",
	"Microsoft.Logic/integrationAccounts/assemblies",
	"Microsoft.Logic/integrationAccounts/batchConfigurations",
	"Microsoft.Logic/integrationAccounts/certificates",
	"Microsoft.Logic/integrationAccounts/maps",
	"Microsoft.Logic/integrationAccounts/partners",
	"Microsoft.Logic/integrationAccounts/schemas",
	"Microsoft.Logic/integrationAccounts/sessions",
	"Microsoft.Logic/workflows/triggers",
	"Microsoft.Logic/workflows",

	// Azure Machine Learning
	"Microsoft.MachineLearningServices/workspaces",

	// Azure Management
	"Microsoft.Management/managementGroups",
	"Microsoft.Authorization/locks",

	// Azure Managed Applications
	"Microsoft.Solutions/applications",
	"Microsoft.Solutions/applicationDefinitions",

	// Azure Monitor
	"Microsoft.Insights/diagnosticSettings",
	"Microsoft.Insights/activityLogAlerts",
	"Microsoft.AlertsManagement/actionRules",
	"Microsoft.Insights/autoScaleSettings",
	"Microsoft.Insights/dataCollectionRuleAssociations",
	"Microsoft.Insights/logProfiles",
	"Microsoft.Insights/privateLinkScopes",
	"Microsoft.Insights/privateLinkScopes/scopedResources",
	"Microsoft.Insights/scheduledQueryRules",
	"Microsoft.AlertsManagement/smartDetectorAlertRules",

	// Azure Monitor - Application Insights
	"Microsoft.Insights/components/analyticsItems",
	"Microsoft.Insights/components/apiKeys",
	"Microsoft.Insights/components/smartDetectionRule",
	"Microsoft.Insights/workbooks",
	"Microsoft.Insights/workbookTemplates",

	// Azure Monitor - Log Analytics
	"Microsoft.OperationalInsights/clusters",
	"Microsoft.OperationalInsights/workspaces/dataExports",
	"Microsoft.OperationalInsights/workspaces/dataSources",
	"Microsoft.OperationalInsights/workspaces/linkedServices",
	"Microsoft.OperationalInsights/workspaces/linkedStorageAccounts",
	"Microsoft.OperationalInsights/queryPacks",
	"Microsoft.OperationalInsights/queryPacks/queries",
	"Microsoft.OperationalInsights/workspaces/savedSearches",
	"Microsoft.OperationalInsights/workspaces/storageInsightConfigs",

	// Azure Networking
	"Microsoft.Network/applicationSecurityGroups",
	"Microsoft.Network/ipGroups",
	"Microsoft.Network/localNetworkGateways",
	"Microsoft.Network/networkInterfaces",
	"Microsoft.Network/networkSecurityGroups",
	"Microsoft.Network/networkSecurityGroups/securityRules",
	"Microsoft.Network/privateLinkServices",
	"Microsoft.Network/routeTables/routes",
	"Microsoft.Network/routeFilters",
	"Microsoft.Network/virtualHubs/routeMaps",
	"Microsoft.Network/routeTables",
	"Microsoft.Storage/storageAccounts/localUsers",
	"Microsoft.Storage/storageAccounts",
	"Microsoft.Network/virtualNetworks/subnets",
	"Microsoft.Network/serviceEndpointPolicies",
	"Microsoft.Network/virtualNetworks",
	"Microsoft.Network/virtualNetworks/dnsServers",

	// Azure Notification Hub
	"Microsoft.NotificationHubs/namespaces/notificationHubs",

	// Azure Policy
	"Microsoft.Authorization/policyDefinitions",
	"Microsoft.Authorization/policySetDefinitions",
	"Microsoft.Authorization/policyAssignments",
	"Microsoft.Authorization/policyExemptions",
	"Microsoft.PolicyInsights/remediations",

	// Azure Portal
	"Microsoft.Portal/dashboards",

	// Azure Redis
	"Microsoft.Cache/redis/firewallRules",
	"Microsoft.Cache/redis/linkedServers",

	// Azure Registry
	"Microsoft.ContainerRegistry/registries/scopeMaps",
	"Microsoft.ContainerRegistry/registries/tokens",
	"Microsoft.ContainerRegistry/registries/webHooks",

	// Azure Sentinel
	"Microsoft.SecurityInsights/alertRules",

	// Azure Service Bus
	"Microsoft.ServiceBus/namespaces/authorizationRules",
	"Microsoft.ServiceBus/namespaces/disasterRecoveryConfigs",
	"Microsoft.ServiceBus/namespaces",
	"Microsoft.ServiceBus/namespaces/queues",
	"Microsoft.ServiceBus/namespaces/queues/authorizationRules",
	"Microsoft.ServiceBus/namespaces/topics/subscriptions",
	"Microsoft.ServiceBus/namespaces/topics/subscriptions/rules",
	"Microsoft.ServiceBus/namespaces/topics",
	"Microsoft.ServiceBus/namespaces/topics/authorizationRules",
	"Microsoft.Relay/namespaces/hybridConnections/authorizationRules",
	"Microsoft.Relay/namespaces/authorizationRules",

	// Azure Shared Image Gallery
	"Microsoft.Compute/galleries/images",
	"Microsoft.Compute/galleries",

	// Azure SignalR
	"Microsoft.SignalRService/signalR",
	"Microsoft.SignalRService/signalR/sharedPrivateLinkResources",

	// Azure Site Recovery
	"Microsoft.RecoveryServices/vaults/replicationFabrics/replicationProtectionContainers/replicationProtectionContainerMappings",

	// Azure SQL
	"Microsoft.Sql/servers/failoverGroups",
	"Microsoft.Sql/servers/firewallRules",
	"Microsoft.Sql/servers",
	"Microsoft.Sql/servers/virtualNetworkRules",

	"Microsoft.Sql/servers/databases/extendedAuditingSettings",
	"Microsoft.Sql/servers/databases/vulnerabilityAssessments/rules/baselines",
	"Microsoft.Sql/servers/jobAgents",
	"Microsoft.Sql/servers/jobAgents/credentials",
	"Microsoft.Sql/managedInstances/administrators",
	"Microsoft.Sql/managedInstances/securityAlertPolicies",
	"Microsoft.Sql/managedInstances/encryptionProtector",
	"Microsoft.Sql/managedInstances/vulnerabilityAssessments",
	"Microsoft.Sql/servers/outboundFirewallRules",
	"Microsoft.Sql/servers/dnsAliases",
	"Microsoft.Sql/servers/extendedAuditingSettings",
	"Microsoft.Sql/servers/devOpsAuditingSettings",
	"Microsoft.Sql/servers/securityAlertPolicies",
	"Microsoft.Sql/servers/encryptionProtector",
	"Microsoft.Sql/servers/vulnerabilityAssessments",

	// Azure Storage
	"Microsoft.Storage/storageAccounts/localUsers",
	"Microsoft.Storage/storageAccounts",
	"Microsoft.Storage/storageAccounts/inventoryPolicies",
	"Microsoft.StorageSync/storageSyncServices/syncGroups/cloudEndpoints",
	"Microsoft.StorageSync/storageSyncServices/syncGroups",

	// Azure Virtual Desktop
	"Microsoft.DesktopVirtualization/applicationGroups/applications",
	"Microsoft.DesktopVirtualization/applicationGroups",
	"Microsoft.DesktopVirtualization/workspaces",
	"Microsoft.DesktopVirtualization/hostPools",
	"Microsoft.DesktopVirtualization/hostPools/registrationInfo",

	// Azure Synapse Analytics
	"Microsoft.Synapse/workspaces/firewallRules",
	"Microsoft.Synapse/privateLinkHubs",

	// Azure Virtual Hub
	"Microsoft.Network/virtualHubs/hubRouteTables",
	"Microsoft.Network/virtualHubs/hubRouteTables/routes",

	// Azure Virtual Machines
	"Microsoft.Compute/virtualMachines/dataDisks",
	"Microsoft.Compute/virtualMachines/extensions",
	"Microsoft.Compute/virtualMachineScaleSets/extensions",
	"Microsoft.Compute/availabilitySets",
	"Microsoft.Compute/proximityPlacementGroups",
	"Microsoft.Compute/sshPublicKeys",
	"Microsoft.MarketplaceOrdering/agreements/offers/plans",

	// Azure WAN
	"Microsoft.Network/virtualHubs/hubVirtualNetworkConnections",
	"Microsoft.Network/virtualWans",
	"Microsoft.Network/vpnServerConfigurations",

	// Microsoft Defender for Cloud
	"Microsoft.Security/automations",
	"Microsoft.Security/serverVulnerabilityAssessments",
	"Microsoft.Security/assessmentMetadata",
	"Microsoft.Security/autoProvisioningSettings",
	"Microsoft.Security/automations",
	"Microsoft.Security/securityContacts",
	"Microsoft.Security/serverVulnerabilityAssessments",
	"Microsoft.Security/settings",
	"Microsoft.Security/workspaceSettings",
}

var UsageOnlyResources = []string{}
