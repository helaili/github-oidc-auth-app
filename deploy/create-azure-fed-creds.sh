# Expecting the following vaiables to be set:
# subscriptionId=xxxxxxxxxxxxxxxxxxx
# environment=production
# appRegistrationName=oidc-auth-app-prod
# federatedCrendentialName=oidc-auth-app-prod-creds
# federatedCrendentialDescription='Deploying to production'

resourceGroupName=oidc-auth-app
repository='helaili/github-oidc-auth-app'

echo "Login to Azure"
loginResult=$(az login)
echo $loginResult
tenantId=$(echo $loginResult | jq -r ".[].tenantId")

echo "Create the Azure Active Directory application"
appCreationResult=$(az ad app create --display-name $appRegistrationName)
echo $appCreationResult
clientId=$(echo $appCreationResult | jq -r ".appId")

echo "Create a service principal for the Azure Active Directory application."
spCreationResult=$(az ad sp create --id $clientId)
objectId=$(echo $spCreationResult | jq -r ".id")

echo "Create a new role assignment by subscription and object."
roleAssignementResult=$(az role assignment create --role Contributor --subscription $subscriptionId --assignee-object-id  $objectId --assignee-principal-type ServicePrincipal --scope /subscriptions/$subscriptionId/resourceGroups/$resourceGroupName)
echo $roleAssignementResult

echo "Add federated credentials"
subject='repo:'$repository':environment:'$environment
credentialTemplate='{"name": "", "issuer": "https://token.actions.githubusercontent.com", "subject": "", "description": "", "audiences": ["api://AzureADTokenExchange"]}'
# Load credential env var as JSON and substitute values with jq and return the result as an inline string
credential=$(echo $credentialTemplate | jq --compact-output --arg name $federatedCrendentialName --arg description "$federatedCrendentialDescription" --arg subject $subject '.name = $name | .subject = $subject | .description = $description')
echo $credential
echo $credential > credential.json
az ad app federated-credential create --id $clientId --parameters credential.json
rm credential.json


echo "Success. The AZURE_CLIENT_ID is $clientId"

