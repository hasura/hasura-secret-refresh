# Hasura Secrets Management Service

**Table of Contents**

- [Architecture](#architecture)
- [Deployment](#deployment)
- [Configuration](#configuration)
- Provider types:
  - [proxy_awsm_oauth](#proxy_awsm_oauth)
  - [file_aws_secrets_manager](#file_aws_secrets_manager)
    - [Secret Rotation](#secret-rotation)
  - [file_aws_iam_auth_rds](#file_aws_iam_auth_rds)
- [Actions/RS Configuration](#actionsrs-configuration)
- [Data Source Configuration](#data-source-configuration)
  
## Architecture
Hasura Secrets Management Service (Secrets Proxy) is deployed as a sidecar container in the same pod as the Hasura GraphQL Engine container (**Enterprise Edition only**).

The main job of the Secrets Proxy is to fetch relevant credentials from target secrets manager/auth provider; and make it available to Hasura for calls to user databases or downstream REST APIs (Actions) or Remote Schemas (GraphQL). Here it supports multiple providers to support various integrations with secret providers (e.g. AWS Secrets Manager).

There are 2 ways the Secrets Proxy injects the fetched credentials to Hasura: 
1. As a Forward Proxy to Hasura GraphQL Engine, where it adds the credentials in the request header before forwarding it. This works only for API based downstream requests (Actions and Remote Schemas)
2. As a Direct Credentials Injector to Hasura via a shared file mount. Here it makes the fetched credential available to Hasura container via a volume mount at a particular path. Hasura automatically refers to a fixed path file on the volume and is used to resolve credentials required for outgoing requests. This works best for Data sources like: Postgres, CockroachDB, Oracle, MysqlDB, MongoDB, Athena (all data connectors).

## Deployment
To configure the Secrets Proxy to run alongside Hasura in a K8s cluster, you can use this sample deployment manifest

```
apiVersion: apps/v1
kind: Deployment
metadata:
 labels:
   app: hasura
   hasuraService: custom
 name: hasura
spec:
 replicas: 1
 selector:
   matchLabels:
     app: hasura
 template:
   metadata:
     labels:
       app: hasura
   spec:
     serviceAccountName: secrets-management-proxy-service-account
     containers:
       - image: hasura/graphql-engine:v2.35.0-beta.1
         imagePullPolicy: IfNotPresent
         name: hasura
         env:
           - name: HASURA_GRAPHQL_DATABASE_URL
             value: postgres://username:password@hostname:port/dbname
           - name: HASURA_GRAPHQL_ADMIN_SECRET
             value: mysecretkey
           ## enable the console served by server
           - name: HASURA_GRAPHQL_ENABLE_CONSOLE
             value: "true"
           ## enable debugging mode. It is recommended to disable this in production
           - name: HASURA_GRAPHQL_DEV_MODE
             value: "true"
           - HASURA_DYNAMIC_DATA_SOURCE_ALLOWED_PATH_PREFIX
             value: /secrets
         ports:
           - name: http
             containerPort: 8080
             protocol: TCP
         livenessProbe:
           httpGet:
             path: /healthz
             port: http
         readinessProbe:
           httpGet:
             path: /healthz
             port: http
         resources: {}
         volumeMounts:
 	         - name: shared-secret-volume
           mountPath: /secret

       - image: hasura/secrets-management-proxy:v2.35.0-beta.1
         name: secrets-management-proxy
         imagePullPolicy: IfNotPresent
         volumeMounts:
           - name: secrets-management-proxy-configmap
             mountPath: /config.yaml
             subPath: config.yaml
           - name: shared-secret-volume
             mountPath: /secret

     volumes:
       - name: secrets-management-proxy-configmap
         configMap:
           name: secrets-management-proxy
           items:
             - key: config.yaml
               path: config.yaml
       - name: shared-secret-volume
         emptyDir: { }
```

This manifest is modified from the public documentation of deploying Hasura on k8s. This adds a 'secrets-management-proxy' container to run alongside `hasura` on port 5353.

### Notes
* Supported in hasura/graphql-engine:v2.35.0 or later.
* For Secrets Proxy use hasura/secrets-management-proxy:v2.35.0-beta.1 or later
* A new environment variable `HASURA_DYNAMIC_DATA_SOURCE_ALLOWED_PATH_PREFIX` needs to be set on the Hasura container. This needs to be same as where the shared volume is mounted. (in this e.g. /secrets)
* A Shared volume is set between Hasura and Secrets Proxy: `shared-secret-volume`. This is an emptyDir. These types of volumes are always empty on start, and get erased on pod destruction. Using this volume mount, fetched credentials are shared between the 2 containers.
* The manifest for Secrets Proxy container does not have containerPort defined. This is to make sure it's not accessible from outside of the pod.
* A ServiceAccount is set: `secrets-management-proxy-service-account`. This is to authorize with AWS Secrets Manager for credential fetching.
* A Configmap is set: `secrets-management-proxy-configmap`. This contains the configuration to be set for the Secrets Proxy.

The manifest can now be deployed using the command kubectl apply -f . You can ensure the service is up and running by checking the logs of the container
`kubectl logs -f hasura-<pod-id> -c secrets-management-proxy`

The secrets from file provider type should also be mounted to the specified location. We can check for that using
`kubectl exec -it <hasura_pod_id> -c secrets-management-proxy -- sh`
Once you are into the shell, try doing `cat secret/dbsecret.txt`. This should fetch you the templatised secret from your secret manager.

## Configuration
The Secrets Proxy requires a configuration file which contains configuration for secrets manager integration and other directives.

Sample configmap.yaml

```
apiVersion: v1
kind: ConfigMap
metadata:
 name: secrets-management-proxy
data:
 config.yaml: |
   actions_secret:
    type: "proxy_awssm_oauth"
    certificate_cache_ttl: 300
    certificate_region: "us-west-2"
    token_cache_ttl: 300
    token_cache_size: 10
    oauth_url: "https://0vmhwbsxti.execute-api.us-east-2.amazonaws.com/prod/oauth"
    jwt_claims_map: '{"iss":"sample_issuer", "sub":"sample_sub", "aud":"sample_aud"}'
    jwt_duration: 300
    http_retry_attempts: 3
    http_retry_min_wait: 3
    http_retry_max_wait: 10
     
   data_source_secret:
    type: "file_aws_secrets_manager"
    region: "us-west-2"
    refresh: 300
    secret_id: json_secret
    path: /secret/dbsecret.txt
    template: postgres://##secret.username##:##secret.password##@##secret.host##:##secret.port##/##secret.dbname##

  aws_iam_auth_rds:
    type: "file_aws_iam_auth_rds"
    region: "ap-south-1"
    db_name: "postgres"
    db_user: "karthikvt26_iam"
    db_host: "rds-hasura12a42cb.cdaicbsap2wa.ap-south-1.rds.amazonaws.com"
    db_port: 5432
    path: token_file
   
   log_config:
    level: "info"
```

The Secrets Proxy supports multiple mechanisms of fetching and injecting secrets for any number of use cases and integrations.

Each section of the configuration is backed by a type of provider. There are 3 types of providers currently supported: 
1. `proxy_awssm_oauth`
2. `file_aws_secrets_manager`
3. `file_aws_iam_auth_rds`

Any provider starting with `proxy_` is the type which acts as a forward proxy for credential injections to Actions and Remote Schemas.

Any provider starting with `file_` is the type which acts as a shared file mount based injector for integration with Data Sources.

The config file follows the following format

```
<config-name-for-an-integration-1>:
	type: proxy_awssm_oauth | file_aws_secrets_manager
	…<other provider_configs>
<config-name-for-an-integration-2>:
	type: proxy_awssm_oauth | file_aws_secrets_manager
	…<other provider_configs>
…
```

Any number of configurations can be set for various integrations with Actions, Remote Schemas and Data Sources.
E.g. For the same type file_aws_secrets_manager, there can be 2 config sections (named differently), to support 2 different databases (say Mongodb and OracleDB).

```
all_actions_prod_teamA:
	type: proxy_awssm_oauth
	certificate_cache_ttl: 300
    	certificate_region: "us-west-2"
    	token_cache_ttl: 300
    	token_cache_size: 10
    	oauth_url: "https://<region>.amazonaws.com/prod/oauth"
    	jwt_claims_map: '{"iss":"sample_issuer","sub":"sample_sub"}'

mongodb-prod-team-a:
	type: file_aws_secrets_manager
	region: "us-west-2"
    secret_id: my_mongodb
    path: /secret/MONGODB-TEAM-A-PROD
    template: mongodb://##secret.username##:##secret.password##@##secret.host##:##secret.port##/##secret.dbname##

mongodb-staging-team-b:
	type: file_aws_secrets_manager
	region: "us-west-1"
    secret_id: my_mongodb_team_b
    path: /secret/MONGODB-TEAM-B-STAGING
    template: mongodb://##secret.username##:##secret.password##@##secret.host##:##secret.port##/##secret.dbname##

oracledb-prod:
	type: file_aws_secrets_manager
	region: "us-west-2"
    secret_id: oracledb_prod
    path: /secret/ORACLE-PROD
    template: jdbc://##secret.username##:##secret.password##@##secret.host##:##secret.port##/##secret.dbname##
```

### proxy_awsm_oauth
`proxy_awssm_oauth` is a proxy type of provider. It implements the flow of fetching the client certificate from AWS secrets manager, creating JWT token and fetching the access token from an Oauth endpoint. The configuration parameters are:

* `type`: Must always be "proxy_awssm_oauth"
* `certificate_cache_ttl`: The certificate that is fetched from AWS secrets manager is cached. This parameter controls the TTL of that cache. It must be a number representing the number of seconds. eg. if the cache must be 5 minutes, the configuration would be certificate_cache_ttl: 300
* `certificate_region`: The AWS region in which the certificate is stored in the secrets manager. It must be a string representing a valid AWS region. eg: certificate_region: "us-east-2"
* `token_cache_ttl`: The token that is fetched from the OAuth service (IDAnywhere)  is cached. This parameter controls the TTL of that cache. It must be a number representing the number of seconds. eg. if the cache must be 5 minutes, the configuration would be token_cache_ttl: 300
* `token_cache_size`: A number representing the number of tokens that can be cached. If a new token is added to the cache when the cache is full, then the least recently used token would be evicted. eg: token_cache_size: 10
* `oauth_url`: The endpoint of the OAuth service which is used to fetch the access token. It must be a string representing a valid URL. eg: oauth_url: "http://my-oauth-service:8090/oauth"
* `jwt_claims_map`: The claims to be included in the JWT sent to the OAuth endpoint. It must be a string containing a valid JSON. The claims are included as such into the token payload. eg:   `jwt_claims_map: '{"iss":"sample_issuer", "sub":"sample_sub", "aud":"sample_aud"}'`. **Note**: The Secrets Proxy will add the exp claim at runtime (based on jwt_duration parameter set).
* `jwt_duration`: This is used to add the exp claim to the JWT sent to the OAuth endpoint. This must be a number representing the number of seconds from the time of creation for which the token is valid. eg. jwt_duration: 300
* `http_retry_attempts`: Requests to AWS Secrets Manager and to the OAuth endpoint are retried on recoverable failures. This parameter controls the maximum number of times a request must be retried after which it will be considered as failed. It must be a number. eg: http_retry_attempts: 3
* `http_retry_min_wait`:  Requests to AWS Secrets Manager and to the OAuth endpoint are retried on recoverable failures. This parameter controls the minimum amount of  time to wait before each retry. It must be a number representing the number of seconds eg: http_retry_min_wait: 3
* `http_retry_max_wait`: Requests to AWS Secrets Manager and to the OAuth endpoint are retried on recoverable failures. This parameter controls the maximum amount of time to wait before each retry. The wait time would never exceed ‘http_retry_max_wait’. It must be a number representing the number of seconds eg: http_retry_max_wait: 3

#### Retry configs
Requests to AWS Secrets Manager and to the OAuth endpoint are retried on recoverable failures. These retries are configured using 3 parameters http_retry_attempts, http_retry_min_wait and http_retry_max_wait. Here are some examples on how these parameters work together -

1. ‘http_retry_min_wait’ = 3, ‘http_retry_max_wait’ = 20 and ‘http_retry_attempts’ = 3
  - If the request fails, the first retry happens after 3 seconds which is the ‘http_retry_min_wait’ time
  - If it fails again, the next retry happens at 6 seconds (double the previous retry)
  - If it fails again, the next retry happens at 12 seconds (double the previous retry)
  - If it fails again, then the request is not retried as it was retried ‘http_retry_attempts’ times which was 3 in this case
2. ‘http_retry_min_wait’ = 3, ‘http_retry_max_wait’ = 10 and ‘http_retry_attempts’ = 4
  - If the request fails, the first retry happens after 3 seconds which is the ‘http_retry_min_wait’ time
  - If it fails again, the next retry happens at 6 seconds (double the previous retry)
  - If it fails again, the next retry happens at 10 seconds. This is because double of the previous retry time would be 12 seconds which exceeds ‘http_retry_max_wait’. The retry wait time would never exceed ‘http_retry_max_wait’.
  - If it fails again, it is tried again after 10 seconds which is ‘http_retry_max_wait’ time.
  - If it fails again, then the request is not retried as it was retried ‘http_retry_attempts’ times which was 4 in this case

### file_aws_secrets_manager
For the type file_aws_secrets_manager, secrets manager proxy service will try to fetch the credentials from AWS Secrets manager and will write to a file which is mounted on a shared volume between Hasura Data Plane and the Secrets proxy. This is to be used for AWS Secrets Manager based integration with Data Sources. The configuration parameters are:
* `type`: Must always be "file_aws_secrets_manager"
* `region`: AWS region where the secret is hosted on the secrets manager
* `refresh`: Refresh interval after which secrets management service should refetch the secret. E.g. 60 (seconds)
* `secret_id`: The identifier with which the secret is stored on AWS Secret Management. Note: This can be the ASE Secret ID, or the full ARN string for the secret.
* `path`: The file path where to which the secret will be stored. **Note**: The path should match the path specified in the shared volume mount. The filename should match the expected SECRET name by Hasura.
* `template`: The template of the secret which would be replaced by specific variables before writing to file. This field is optional if the raw secret value from AWS Secrets Manager needs to be used. [Click here](template/README.md) for details on the template format.

For example, 
If the secret in AWS Secret manager is defined as `{"username":"db_username","password":"secret_password","host":"127.0.0.1","port":"5432","dbname":"orders"}`
Then for setting the jdbc url as the database connection string that Hasura reads, the template value is defined as `jdbc://##secret.username##:##secret.password##@##secret.host##:##secret.port##/##secret.dbname##`
Hence, the final secret that is written on the shared file will be `jdbc://db_username:secret_password@127.0.0.1:5432/orders`

**Note**: If the template key is omitted, then the entire json from AWS secret manager will be written to the mounted file.

#### Secret Rotation
The provider `file_aws_secrets_manager` works in conjunction with the new feature of Dynamic Secrets From File, in Hasura. If the credentials are changed in the AWS Secrets Manager, following behavior is expected:
* The refresh parameter will make sure that max within the `<refresh>` time, the secret is re-fetched and updated in the local cache.
* When Hasura encounters an Auth error with a downstream database (say, due to old credentials), Hasura will re-read the credentials from the shared secret file and retry the request. If Secrets Proxy has already updated the secret as per the refresh policy, Hasura will pick up the new credential and retry the request.
* Since Secrets Proxy, has a refresh interval, the new secret pull may take time. In worst case scenario, the request to the database may fail till next refresh happens (e.g. 60 secs).

### file_aws_iam_auth_rds

#### Prerequisites

Following prerequisites are mandatory for RDS IAM Auth to work
1. RDS should be configured with `iamDatabaseAuthenticationEnabled` property
2. Grant IAM auth the required user and any other permission like tables/schema .... A new user can be created using the below

```
CREATE USER karthikvt26_iam;
GRANT rds_iam TO karthikvt26_iam
```

3. Create a policy on IAM to allow access to the database using `rds-db:connect`. Checkout AWS docs for more info

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "rds-db:connect"
            ],
            "Resource": [
                "arn:aws:rds-db:ap-south-1:489732355779:dbuser:db-GTYU6HCLKVIX3XQAMBT32WWDVR/karthikvt26_iam"
            ]
        }
    ]
}
```

4. Create a IAM role and attach the above policy to the same
5. Ensure hasura-secret-refresh can assume the above role via the service account/any other mechanism so that it can generate tokens (need infra folks to help verify)


This type connects to the RDS instance using the configuration set. The configuration would look like below
* type: "file_aws_iam_auth_rds"
* region: AWS region where Database instance is running
* db_name: Token will be generated for this database
* db_user: Database user
* db_host: Host of the database typically of the format: `rds-....ap-south-1.rds.amazonaws.com`
* db_port: Database Port configured to accept connections
* path: Path where token will be stored
* 

#### Example Config
```
.. other config

aws_iam_auth_rds:
  type: "file_aws_iam_auth_rds"
  region: "ap-south-1"
  db_name: "postgres"
  db_user: "karthikvt26_iam"
  db_host: "rds-hasura12a42cb.cdaicbsap2wa.ap-south-1.rds.amazonaws.com"
  db_port: 5432
  path: /home/karthikv/Work/hasura-dev/pgproxy/token_file

.. other config
```

#### Secret Rotation
Provider also supports token refresh at /refresh endpoint. Pass the file name to trigger a refresh

## Actions/RS Configuration
Once the Secrets Proxy is configured, Actions/RS needs to be set in a particular manner in Hasura in order to get the pass the relevant parameters for the integration.

**Note**: For integration with Actions/RS, only 1 provider is implemented as of now `proxy_awssm_oauth`. Make sure Secrets Proxy configuration has this provider setup.

1. Follow this [quick guide](https://hasura.io/docs/latest/actions/quickstart/) to set up a Hasura action. (Note, same steps to be taken for Remote Schema integration too).
2. The Action webhook handler/RS Endpoint needs to be always set to http://localhost:5353 where the Secrets proxy would be running as a sidecar. **Note**:
  * This should NOT be the Action/RS endpoint
  * Add to this endpoint, any path or query params that you want to pass directly to the downstream endpoint. E.g. If the service endpoint which processes action requests is ‘https://someapp.com/user/details?type=abc’ then the webhook URL for this action should be configured as ‘http://localhost:5353/user/details?type=abc’
3. Under “Headers” section please add the following headers along with their corresponding values as explained
* `X-Hasura-Forward-To`: Set this to the downstream service URL where the requests should eventually be processed (Action or RS endpoint). **Only scheme and host must be configured here.** E.g. http://someapp.com’. Any path parameters/query parameters must be configured in the action handler. eg. If the downstream service URL is http://someapp.com/data/users, then the `X-Hasura-Forward-To` header must have the value http://someapp.com and the action handler must be configured to http://localhost/data/users (assuming the proxy is running at localhost). The proxy upon receiving the request, will replace the scheme and host to get the URL http://someapp.com/data/users which is where the request will be forwarded to. **Do not configure any path parameters/query parameters in `X-Hasura-Forward-To` as that will be ignored**
* `X-Hasura-Secret-Header`: Value of this header in action will be the header with which the backend service will be called. This accepts a template of ##some_key##. The string surrounded by `##` will be replaced by the access token which we receive from the Secrets Provider (Token service in this case). Eg: `Authorisation: Bearer ##secret_key##` will be replaced with `Authorisation: Bearer abc_123_xyz` when calling downstream service assuming `abc_123_xyz` is the access token which was received from Token Service. [Click here](template/README.md) for details on the template format.
* `X-Hasura-Secret-Provider`: As per the Proxy Config example, This should be set to `all_action_prod_teamA` since this one is setup against the provider proxy_awssm_oauth in the Proxy ConfigMap.
* `X-Hasura-Certificate-Id`: The key with which the certificate is stored in AWS Secrets Manager. The fingerprint of this certificate will be included as ‘kid’ in the header of the JWT sent to the OAuth endpoint
* `X-Hasura-Oauth-Client-Id`: OAuth Client id
* `X-Hasura-Backend-Id`: Resource id to be passed in the OAuth request
* `X-Hasura-Private-Key-Id`: The key with which the RSA private key is stored in AWS Secrets Manager. This private key will be used to sign the JWT token sent to the OAuth endpoint.


Requests going through the action now will go through the Secrets Proxy ensuring the request headers have been transformed to pick up correct Authorization values in its header.

## Data Source Configuration
Hasura, starting from v2.35.0 supports a new way of injecting secrets: "Dynamic Secrets From File". This is similar to From Env Var configurations while setting up Data Sources in Hasura. The difference is that Dynamic Secrets From File picks the secrets from a local file instead of an environment variable. 

This works well with the `file_aws_secrets_manager` provider of the Secrets Proxy.

### Postgres and CockroachDB

* Make sure Hasura has this env var set in order for this feature to get enabled: `HASURA_DYNAMIC_DATA_SOURCE_ALLOWED_PATH_PREFIX=/secrets`
* While setting up Postgres or Cockroachdb connection string, now Hasura provides a new option called Dynamic URL. This value needs to be the exact file where the connection URL as a secret will be shared with Hasura by the Secrets Proxy on the shared volume. E.g. it can be: `MONGODB_TEAMCCB_PROD_URL`.
* Since the Secrets Proxy is set up with provider file_aws_secrets_manager, which has the path set as `/secrets/MONGODB_TEAMCCB_PROD_URL`, The connection string will be picked up, and the data source setup will be successful.

### Data Connectors (Oracle, MongoDB, MySQL, Athena and others)
* Make sure Hasura has this env var set in order for this feature to get enabled: `HASURA_DYNAMIC_DATA_SOURCE_ALLOWED_PATH_PREFIX=/secrets`
* While setting up the Data Connector connector, Go to **Advanced Settings**: 
  * Setup the relevant template to generate the expected format of the connection string metadata, E.g. if template requires `{"db_url": <Mongo DB URL>}`, then
    * Create a new template variable, say `mongodb_url`
    * Map it to correct file where mongo url as secret will be injected: `/secrets/MONGODB_TEAMCCB_PROD_URL` .This value needs to be the exact file where the connection URL as a secret will be shared with Hasura by the Secrets Proxy on the shared volume
    * Set template as `{"db_url": {{$vars.database_name}}}`

Since the Secrets Proxy is set up with provider `file_aws_secrets_manager`, which has the path set as `/secrets/MONGODB_TEAMCCB_PROD_URL`, The connection string will be picked up, and the data source setup will be successful.




