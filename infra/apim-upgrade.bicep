targetScope = 'resourceGroup'

param apimName string
param apiId string
param sourceRevision string
param revision string
@allowed([
  'prepare'
  'promote'
])
param stage string
param createRevision bool = false
param initializeImagePolicy bool = false
@secure()
param apiProperties object = {}
@secure()
param parentPolicy string = ''
@secure()
param imageOperationProperties object = {}

module upgrade 'modules/apim-upgrade.bicep' = {
  name: 'apim-image-upgrade-${uniqueString(apimName, apiId, revision, stage)}'
  params: {
    apimName: apimName
    apiId: apiId
    sourceRevision: sourceRevision
    revision: revision
    stage: stage
    createRevision: createRevision
    initializeImagePolicy: initializeImagePolicy
    apiProperties: apiProperties
    parentPolicy: parentPolicy
    imageOperationProperties: imageOperationProperties
  }
}
