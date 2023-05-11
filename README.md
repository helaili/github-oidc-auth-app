[![Publish and Deploy](https://github.com/helaili/github-oidc-auth-app/actions/workflows/deploy.yml/badge.svg)](https://github.com/helaili/github-oidc-auth-app/actions/workflows/deploy.yml)

# github-oidc-auth-app

A GitHub App that generates a GitHub API scoped token from within an Actions workflow based on OIDC claims

# Overview
Oftentimes you need a GitHub Actions pipeline to use the GitHub API to perform some operations on another repository or organization. For example, you may want to get a container, or you may want to create a repository in a different organisation. In those cases, you need to use a GitHub API token that has the right scopes. The problem is that you cannot use the automatically provided GITHUB_TOKEN as it doesn't have enough permissions, and you don't want to use a personal access token because eithe. Those are tied to a specific humand user or to a machine account, and in both case it means generating, sharing, storing, renewing... a secret.

There is already a workaround for that with the action [peter-murray/workflow-application-token-action](https://github.com/peter-murray/workflow-application-token-action), which will deliver a short lived token that will provide access to a foreign resource on GitHub. This solution is great as there is no runtime involved, it is just the configuration of a new GitHub App, but it requires to share a private key as an Actions secret with every repository that needs to use it. You have now way to audit the usage, and a key rotation will be painful. Last, a new GitHub App will be needed whenever a different scope is needed, and you have a limit of 100 apps per organization. Having said that, again, this is still the easiest and fastest solution to the problem of granting access to a foreign resource on GitHub.

Now if none of the above solutions fit your needs, this project provides a new approach. It relies on the ability to get [an OpenID Connect (OIDC) token](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect) from with an Actions workflow. This token generated by GitHub contains claims (repo name, environment, actor, ref, event...) that can't be faked. Therefore we can safely pass this over to this GitHub App which will verify the claims and generate a scoped, short-lived token that can be used to access the GitHub API. This token will provide a set of permission based on a configuration file which will allow to differentiate access based on the claims. With one app deployment, a workflow in repo X can have `write` access to the content of the Foo repo, while a workflow in repo Y will have `admin` access to the Bar organisation.


# Architecture

```mermaid 
flowchart TB
  subgraph Repository in Orgnisation 0
    subgraph Workflow
        direction LR
        Action(GitHub-OIDC-Auth action)
        endpoint{{endpoint}}
        login{{login}}
        Action --> login
        Action --> endpoint
    end
    Workflow-->Action
  end

  App(GitHub-OIDC-Auth App)

  subgraph inst2 [Installation 2]
    direction TB
    Org2(Organisation 2)
    ConfigFile2[[Configuration file 2]]
    Repo2[(Repositories)]
    Config2(Org config)
    Org2-->ConfigFile2
    Org2-->Repo2
    Org2-->Config2
  end
  
  subgraph inst1 [Installation 1]
    direction TB
    Org1(Organisation 1)
    ConfigFile1[[Configuration file 1]]
    Repo1[(Repositories)]
    Config1(Org config)
    Org1-->ConfigFile1
    Org1-->Repo1
    Org1-->Config1
  end

  Workflow -- Request token --> App
  App -- Scoped Token  --> Workflow
  App-->inst1
  App-->inst2
```
  
# Configuration

Those are the environment variables that can be used to configure the app:

`PORT`: **Required**. The port the process will listen to

`PRIVATE_KEY`: **Required**. The private key of the GitHub App as base64 encoded string

`APP_ID`: **Required**. The ID of the GitHub App

`CONFIG_REPO`: **Optional**. The name of the repository where the configuration file is stored. Default to `.github-private`

`CONFIG_FILE`: **Optional**. The name of the configuration file. Default to `oidc_entitlements.yml`

# Installation

## Create a GitHub App 
Follow [the instructions](https://docs.github.com/en/apps/creating-github-apps/setting-up-a-github-app/creating-a-github-app) to create the GitHub App. Couple things to keep in mind while creating this app:
- You need to set permissions for this app. This permissions need to be the sum of permissions of all the scoped tokens you intend to generate. You might have to review this list of permissions if you want to add a new scope later on.
- There is no need to set a webhook, a setup URL or a callback URL. You have to provide a homepage URL, but it can be anything as it will not be used.
- If you are going to use this app beyond the organisation or account that owns the app, make sure to select the `Any account` option in the `Where can this GitHub App be installed?` section. In other words, if you are going to use the app to grant access to a repository in another organisation than the owner of the app, you need to select `Any account` and not `Only on this account`.
- Note the `App ID` of the app, you will need to provide later as an environment variable to the app runtime.
- Once the application created, generate a private key for this app. You can do that in the `General` section of the app settings. This key is highly confidential and will be provided as a base64 encoded string as an environment variable to the app runtime. You can use the following command to generate the base64 encoded string of the private key:

```bash
cat private-key.pem | base64
```

## Deploy the app
- Deploy the app as a runtime built with command `make build` or using [the docker container](https://github.com/helaili/github-oidc-auth-app/pkgs/container/github-oidc-auth-app).
- Configure the app with the environment variables described above. This variables are at minimum `PORT`, `PRIVATE_KEY` and `APP_ID`.
- You can test the app by hitting the `/ping` endpoint. You should get a `Ok` response.

## Install the app
- Install the app on each organisations that will need to be accessed by the workflows. You can do that by following [the instructions](https://docs.github.com/en/apps/maintaining-github-apps/installing-github-apps). Remember to select the repositories that will accessed by the app, including the one that will host the `oidc_entitlements.yml` configuration file.

## Create a configuration file
- Commit an `oidc_entitlements.yml` file in the `.github-private` repository (or whatever value you provided to the runtime with the  `CONFIG_REPO` and `CONFIG_FILE` environment variables) of each organisation that will need to be accessed by the workflows. The file should look like below. It is a basically an array of claims to match and the permissions to grant if the claim matches. The claims are the ones provided by the OIDC token.

```yaml
- workflow: My first worlflow
  repository: ziggy/stardust
  scopes:
    repositories: 
      - codespace-oddity
    permissions: 
      contents: write
      checks: write
      administration: read
- environment: production
  repository_owner: talkingheads
  repository_visibility: public
  scopes:
    repositories: 
      - codespace-oddity
    permissions: 
      contents: write
- repository_owner: talkingheads
  repository: talkingheads/road-to-nowhere
  scopes:
    repositories: 
      - starman
    permissions: 
      contents: read
      organization_administration: write
```
 
 If a set of claim matches several entries, the permissions will be the sum of the permissions of all the matching entries. For instance, a job targeting the `production` environment in a `public` repository named `talkingheads/road-to-nowhere` will get the following permissions:
 
 ```yaml
repositories: 
  - codespace-oddity
  - starman
permissions: 
  contents: write
  organization_administration: write
 ```

Remember that the app you created needs to have the permissions of all the different scoped tokens it will generate. Therefore, with the configuration above, the app  will need to have the following permissions:
```yaml
- contents: write
- checks: write
- administration: read
- organization_administration: write
```

The list of claims currently supported by this app is currently limited to the list below. See the [GitHub documentation](https://docs.github.com/en/enterprise-cloud@latest/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#configuring-the-oidc-trust-with-the-cloud) for more details about the meaning of these claims.
- actor
- actor_id
- aud
- base_ref
- environment
- event_name
- head_ref
- job_workflow_ref
- job_workflow_sha
- ref
- ref_type
- repository
- repository_id
- repository_owner
- repository_owner_id
- repository_visibility
- run_id
- run_number
- run_attempt
- runner_environment
- sub
- workflow
- workflow_ref
- workflow_sha


:rotating_light: **Important**: If you set loose claim filters in your configuration (like just `environment: production`), anyone with one of the login name and the URL of the app will be able to generate a token with the matching permission. Using such loose conditions means you need to treat these paramaters as secrets, but I would strongly advise to always include extra information that can not be faked such as the repository owner name.

See the the `properties of permissions` section [here](https://docs.github.com/en/enterprise-cloud@latest/rest/apps/apps?apiVersion=2022-11-28#create-a-scoped-access-token) to see the list of permissions and their values.


## Use the action
The companion action [`helaili/github-oidc-auth`](https://github.com/helaili/github-oidc-auth) will retrieve the scoped token. It needs two inputs:
- `endpoint`: this is the URL of the `/token` endpoint of the app you deployed above. It should look like `https://my-app.com/token`.
- `login`: this is the login name of the organisation or user that will be accessed with the scoped token. The app should have been installed on this account.


```yaml
should-work-with-action:
    ...
    permissions:
      id-token: write
    steps:
      - name: GetToken
        id: getToken
        uses: helaili/github-oidc-auth@main
        with:
          login: ${{ vars.login }}
          endpoint: ${{ vars.endpoint }}
      - name: Use the token from the environment
        uses: actions/github-script@v6
        with:
          github-token: ${{ env.SCOPED_TOKEN }}
        ...   
      - name: Use the token from the step output
        uses: actions/github-script@v6
        with:
          github-token: ${{ steps.getToken.outputs.scopedToken }}

        ...
```

# Giving it a try

You might to give this app and action a try without going through the hassle of creating a new GitHub app and deploying it somewhere. Make sense, so I created a sandbox for you. This is a sandbox, there is no SLA coming with this and as I am running it, it really means that you are trusting me with your GitHub token. I am not going to do anything bad with it, but you should not use this for anything serious. In order to limit any problem,  no organisation permission are granted to this app instance. The only repository permissions granted are:
- administration: `read`
- contents: `write`
- issues: `write`

In order to use this sandbox, you will need to:
- Create a file named `oidc_entitlements.yml` in the `.github-private` repository of your organisation as previously explained. 
- Install the app on your organisation by clicking [here](https://github.com/apps/oidc-auth-for-github-sandbox). Make sure you grant the app access to at least the `.github-private` repository and whichever other one within this organisation that you will want to access using the token. 
- Create a workflow that uses the action `helaili/github-oidc-auth` as shown below. 

```yaml
...
    steps:
      - name: Get the token
        id: getToken
        uses: helaili/github-oidc-auth@main
        with:
          login: < organisation or user login which you need access to >
          endpoint: https://oidc-auth-app-sandbox.whitefield-370b64fc.eastus.azurecontainerapps.io/token

      - name: Use the token from the output
        uses: actions/github-script@v6
        with:
          github-token: ${{ steps.getToken.outputs.scopedToken }}
          script: |
            github.rest.repos.get({
              owner: 'my-org',
              repo: 'my-repo'
            }).then((response) => {
              if(!response.data.full_name === 'my-org/my-repo') {
                // Victory!
              }
            }).catch((error) => {
              core.setFailed(`Failed to access repo. Error was ${error}`);
            })
```

# Credits

This app shamelessly reuses code from https://github.com/github/actions-oidc-gateway-example. Thanks to @steiza for the inspiration!