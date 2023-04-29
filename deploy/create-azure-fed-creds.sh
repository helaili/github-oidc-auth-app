# Expecting the following vaiables to be set:
# subscriptionId=xxxxxxxxxxxxxxxxxxx
# environment=production
# appRegistrationName=oidc-auth-app-prod
# federatedCrendentialName=oidc-auth-app-prod-creds
# federatedCrendentialDescription='Deploying to production'

resourceGroupName=oidc-auth-app
repository='helaili/github-oidc-auth-app'

# Interactive login to Azure
loginResult=$(az login)
tenantId=$(echo $loginResult | jq -r ".[].tenantId")

# Create the Azure Active Directory application.
appCreationResult=$(az ad app create --display-name $appRegistrationName)
clientId=$(echo $appCreationResult | jq -r ".appId")

# Create a service principal for the Azure Active Directory application.
spCreationResult=$(az ad sp create --id $clientId)
objectId=$(echo $spCreationResult | jq -r ".id")

# Create a new role assignment by subscription and object.
roleAssignementResult=$(az role assignment create --role Contributor --subscription $subscriptionId --assignee-object-id  $objectId --assignee-principal-type ServicePrincipal --scope /subscriptions/$subscriptionId/resourceGroups/$resourceGroupName)
principalId=$(echo $roleAssignementResult | jq -r ".principalId")

# Add federated credentials
subject='repo:'$repository':environment:'$environment
credentialTemplate='{"name": "", "issuer": "https://token.actions.githubusercontent.com", "subject": "", "description": "", "audiences": ["api://AzureADTokenExchange"]}'
# Load credential env var as JSON and substitute values with jq and return the result as an inline string
credential=$(echo $credentialTemplate | jq --compact-output --arg name $federatedCrendentialName --arg description $federatedCrendentialDescription --arg subject $subject '.name = $name | .subject = $subject | .description = $description')
fedCred=$(az ad app federated-credential create --id $clientId --parameters $credential)
echo $fedCred | jq -r ".id"