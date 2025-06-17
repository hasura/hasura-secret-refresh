# Azure Key Vault E2E Test Guide

## AI Agent Prompt

```
You are testing Azure Key Vault integration for Hasura Secrets Proxy.

TASK: Analyze this repository and generate comprehensive test scripts for Azure Key Vault integration that match the quality

STEPS:
1. Create testing workspace: `mkdir -p azure-test-run-$(date +%Y%m%d-%H%M%S)` and change the directory to this, and create all the other files in this directory
2. Find Azure implementation: `find .. -name "*azure*" -type f | grep -E "\.(go|yaml|md)$"`
3. Check configuration format: `cat ../examples/*.yaml | grep -A 10 -B 5 "azure"`
4. Ask user for Azure Key Vault name and authentication method (service-principal/managed-identity)
5. Generate 3 scripts in testing workspace that you created: comprehensive validation, Azure setup with real resources, integration testing. The script should show appropriate info message to the user on what is happening, and if we are using external service, be verbose but readable.
6. Guide user through complete testing process with validation against known working tests
7. Verify ALL aspects: compilation, unit tests, config validation, provider registration, dependencies, code structure, documentation, error handling, logging, security, Azure connectivity, HTTP/File providers, performance, caching

VALIDATION REQUIREMENTS:
- Code compilation and all unit tests
- Configuration validation with invalid config rejection
- Provider registration in main.go (proxy_azure_key_vault, file_azure_key_vault)
- Azure SDK dependencies (azidentity, azsecrets)
- Code structure validation (all required files exist)
- Documentation validation (README.md, examples, test plans)
- Error handling validation (proper error types and wrapping)
- Logging validation (Info, Error, Debug levels)
- Security validation (no secrets in logs, file permissions 0600)

AZURE SETUP REQUIREMENTS:
- Check Azure CLI login and subscription
- Handle existing vs new Service Principal creation
- Support both RBAC and access policy Key Vaults
- Create comprehensive test secrets (simple, connection string, JSON, API token)
- Update configuration with real credentials
- Verify setup with actual secret retrieval

INTEGRATION TEST REQUIREMENTS:
- Prerequisites check (binary, config, Azure CLI)
- Configuration parsing validation
- Service startup with proper port listening
- HTTP provider testing with ALL required headers:
  * X-Hasura-Forward-To: destination URL
  * X-Hasura-Secret-Provider: provider name from config
  * X-Hasura-Secret-Header: template like "Authorization: Bearer ##secret##"
  * X-Hasura-Secret-Name: secret name in Azure Key Vault
- File provider testing with permission checks (0600)
- Template substitution validation for JSON secrets
- Refresh endpoint testing
- Performance testing with cache timing (3 requests to measure cache effectiveness)
- Security validation (file permissions, no secrets in logs)
- Comprehensive log analysis

REQUIREMENTS:
- Create dedicated test directory: azure-test-run-YYYYMMDD-HHMMSS (timestamped)
- Generate all files in test directory (scripts, configs, credentials, logs)
- Use current configuration format from config.yaml and examples/
- CRITICAL: Use cross-platform commands (avoid 'timeout' - use sleep + kill instead)
- Test HTTP providers (Actions/Remote Schemas) and File providers (Data Sources)
- Verify template substitution, caching, file permissions (0600), no secret leaks
- Include proper error handling and cleanup procedures
- Support both Service Principal and Managed Identity authentication
- All generated files should be self-contained in the test directory

OUTPUT: Step-by-step guidance with generated scripts in dedicated test directory that provide equivalent testing coverage to manual tests.
```

## Success Criteria

Verify these work correctly:

### ✅ Implementation Validation (10 test categories)
- [ ] Code compilation and all unit tests pass
- [ ] Configuration validation with invalid config rejection
- [ ] Provider registration in main.go (constants and parseConfig)
- [ ] Azure SDK dependencies present and downloadable
- [ ] Code structure validation (all required files exist)
- [ ] Documentation validation (README.md, examples, test plans)
- [ ] Error handling validation (proper error types and wrapping)
- [ ] Logging validation (Info, Error, Debug levels implemented)
- [ ] Security validation (no secrets in logs, file permissions 0600)

### ✅ Azure Integration (comprehensive setup)
- [ ] Azure CLI login and subscription verification
- [ ] Service Principal creation with proper permissions
- [ ] Key Vault permissions (RBAC or access policies)
- [ ] Test secrets creation (simple, connection string, JSON, API token)
- [ ] Configuration file generation with real credentials
- [ ] Setup verification with actual secret retrieval

### ✅ HTTP Provider Testing (proxy_azure_key_vault)
- [ ] Service startup with port listening verification
- [ ] Secret retrieval from Azure Key Vault
- [ ] Template substitution in headers
- [ ] Secret injection verification in HTTP responses
- [ ] Error handling for missing headers/providers
- [ ] Caching functionality validation

### ✅ File Provider Testing (file_azure_key_vault)
- [ ] Secret files created with correct permissions (0600)
- [ ] Template substitution for JSON secrets (MongoDB connection string)
- [ ] Automatic refresh functionality
- [ ] Manual refresh via endpoint
- [ ] File content validation

### ✅ Performance & Security
- [ ] Cache timing tests (first request slow, subsequent fast)
- [ ] File permission security (0600 enforcement)
- [ ] Log security (no secrets visible in logs)
- [ ] Proper error handling and logging
- [ ] Memory usage and performance acceptable

### ✅ Cleanup & Maintenance
- [ ] Proper service shutdown
- [ ] Test file cleanup
- [ ] Azure resource cleanup (with user permission)
- [ ] Configuration restoration

## Troubleshooting Commands

```bash
# Azure authentication issues
az account show && az login
az keyvault secret list --vault-name "VAULT_NAME"
az role assignment list --assignee "CLIENT_ID"

# Service Principal issues
az ad sp show --id "CLIENT_ID"
az keyvault show --name "VAULT_NAME" --query properties.enableRbacAuthorization

# Application issues
go build -o hasura-secret-refresh
export CONFIG_PATH=/path/to/azure-configs  # Set config directory
./hasura-secret-refresh
curl -s "https://VAULT_NAME.vault.azure.net/"
lsof -i :5353  # Check if service is listening
unset CONFIG_PATH  # Reset when done

# HTTP Provider testing (all headers required)
curl -s -H "X-Hasura-Forward-To: https://httpbin.org/headers" \
       -H "X-Hasura-Secret-Provider: azure_test_http" \
       -H "X-Hasura-Secret-Header: Authorization: Bearer ##secret##" \
       -H "X-Hasura-Secret-Name: test-secret" \
       "http://localhost:5353/test"

# Configuration issues
go test ./provider/azure_key_vault/ -v
grep -r "azure_key_vault" main.go
cat examples/azure-key-vault-config.yaml

# Security validation
ls -la /tmp/test-*  # Check file permissions
grep -i "client_secret\|password" service.log  # Should return nothing
```

## Cleanup

```bash
# Stop service and remove test files
pkill hasura-secret-refresh
rm -f /tmp/test-* service.log ai-service.log
rm -f config-azure-ai-test.yaml azure-credentials.env

# Restore original configuration
git checkout HEAD -- config.yaml

# Remove Azure resources (optional) - ask the user for explicit permission before doing this
# az ad sp delete --id "CLIENT_ID"
# az keyvault secret delete --vault-name "VAULT_NAME" --name "test-secret"
# az keyvault secret delete --vault-name "VAULT_NAME" --name "test-connection-string"
# az keyvault secret delete --vault-name "VAULT_NAME" --name "test-json-secret"
# az keyvault secret delete --vault-name "VAULT_NAME" --name "test-api-token"
```

## CRITICAL FIXES NEEDED (Based on Real Execution)

### ✅ **Configuration Method (USING CONFIG_PATH)**
```bash
# RECOMMENDED (using CONFIG_PATH environment variable):
export CONFIG_PATH=/path/to/azure-test-configs
./hasura-secret-refresh

# ALTERNATIVE (default location):
cp config-azure-test.yaml config.yaml
./hasura-secret-refresh

# CLEANUP (reset environment variable when done):
unset CONFIG_PATH
```

### 🚨 **HTTP Provider Headers (CRITICAL)**
The guide must specify ALL required headers for HTTP testing:
```bash
curl -s -H "X-Hasura-Forward-To: https://httpbin.org/headers" \
       -H "X-Hasura-Secret-Provider: azure_test_http" \
       -H "X-Hasura-Secret-Header: Authorization: Bearer ##secret##" \
       -H "X-Hasura-Secret-Name: test-secret" \
       "http://localhost:5353/test"
```

### 🚨 **Cross-Platform Compatibility (CRITICAL)**
```bash
# WRONG (macOS doesn't have timeout):
timeout 10s ./hasura-secret-refresh

# CORRECT (cross-platform):
./hasura-secret-refresh &
PID=$!
sleep 3
kill $PID 2>/dev/null || true
```

### 🚨 **Config File Management (CRITICAL)**
```bash
# Always handle existing config.yaml files:
rm -f config.yaml  # Remove any existing config
cp config-azure-test.yaml config.yaml  # Use test config
```

## AI Prompt Improvements

Based on validation against manual tests, the AI prompt should:

1. **Be more specific about test categories**: Explicitly mention all 10 validation areas
2. **Include comprehensive Azure setup**: Service Principal creation, permissions, secret creation
3. **Add performance testing**: Cache timing measurements, not just functionality
4. **Emphasize security**: File permissions, log security, error handling
5. **Include cleanup procedures**: Proper resource cleanup and restoration
6. **CRITICAL: Include all HTTP headers**: Specify exact headers needed for HTTP provider testing
7. **CRITICAL: Use cross-platform commands**: Avoid macOS-specific commands like timeout
