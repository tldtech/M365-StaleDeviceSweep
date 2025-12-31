targetScope = 'subscription'

@description('Name of the resource group to create.')
param rgName string

@description('Azure Region the resource group will be created in.')
param rgLocation string = deployment().location

resource resourceGroup 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: rgName
  location: rgLocation
  tags: {
    environment: 'production'
  } // Add any additional tags as needed or comment out if not needed.
}
output resourceGroupId string = resourceGroup.id
output resourceGroupName string = resourceGroup.name
output resourceGroupLocation string = resourceGroup.location
output resourceGroupTags object = resourceGroup.tags

// To deploy this Bicep file, use the following Azure CLI command:
// az deployment sub create --location <location> --template-file azuredeploy.bicep --parameters rgName='<ReplaceWithYourDesiredResourceGroupName>'
