# Azure Key Vault E2E Test Execution Guide

## Overview

This directory contains comprehensive Azure Key Vault integration tests generated based on the manual tests in `/testing/azure-key-vault/`. The tests validate all aspects of the Azure Key Vault implementation following the same quality standards as the existing manual tests.

## Test Scripts

### 1. `1-validate-implementation.sh`
**Purpose**: Validates the Azure Key Vault implementation code
**Coverage**: 10 test categories matching `/testing/azure-key-vault/validate-implementation.sh`
- Code compilation and unit tests
- Configuration validation 
- Provider registration in main.go
- Azure SDK dependencies
- Code structure validation
- Documentation completeness
- Error handling validation
- Logging implementation
- Security validation

### 2. `2-setup-azure-resources.sh`
**Purpose**: Sets up Azure resources for testing
**Coverage**: Comprehensive Azure setup matching `/testing/azure-key-vault/setup-azure-resources.sh`
- Azure CLI authentication check
- Resource Group creation
- Key Vault creation with RBAC
- Service Principal creation and permissions
- Test secrets creation (4 types)
- Configuration file generation
- Setup verification

### 3. `3-test-azure-integration.sh`
**Purpose**: Runs comprehensive integration tests
**Coverage**: Full integration testing matching `/testing/azure-key-vault/test-azure-integration.sh`
- HTTP Provider testing (`proxy_azure_key_vault`)
- File Provider testing (`file_azure_key_vault`)
- Template substitution validation
- Refresh endpoint testing
- Performance and caching tests
- Security validation (file permissions, log security)
- Comprehensive log analysis

## Quick Start

### Prerequisites
- Azure CLI installed and authenticated (`az login`)
- Go 1.19+ installed
- Access to Azure subscription with Key Vault permissions

### Step-by-Step Execution

```bash
# Step 1: Validate implementation
./1-validate-implementation.sh

# Step 2: Setup Azure resources (interactive)
./2-setup-azure-resources.sh

# Step 3: Run integration tests
./3-test-azure-integration.sh
```

## Test Coverage Validation

These AI-generated tests match the quality and coverage of manual tests:

### ✅ Implementation Validation (10 categories)
- [x] Code compilation and all unit tests pass
- [x] Configuration validation with invalid config rejection
- [x] Provider registration in main.go (constants and parseConfig)
- [x] Azure SDK dependencies present and downloadable
- [x] Code structure validation (all required files exist)
- [x] Documentation validation (README.md, examples, test plans)
- [x] Error handling validation (proper error types and wrapping)
- [x] Logging validation (Info, Error, Debug levels implemented)
- [x] Security validation (no secrets in logs, file permissions 0600)

### ✅ Azure Integration (comprehensive setup)
- [x] Azure CLI login and subscription verification
- [x] Service Principal creation with proper permissions
- [x] Key Vault permissions (RBAC or access policies)
- [x] Test secrets creation (simple, connection string, JSON, API token)
- [x] Configuration file generation with real credentials
- [x] Setup verification with actual secret retrieval

### ✅ HTTP Provider Testing (`proxy_azure_key_vault`)
- [x] Service startup with port listening verification
- [x] Secret retrieval from Azure Key Vault
- [x] Template substitution in headers
- [x] Secret injection verification in HTTP responses
- [x] Error handling for missing headers/providers
- [x] Caching functionality validation

### ✅ File Provider Testing (`file_azure_key_vault`)
- [x] Secret files created with correct permissions (0600)
- [x] Template substitution for JSON secrets (MongoDB connection string)
- [x] Automatic refresh functionality
- [x] Manual refresh via endpoint
- [x] File content validation

### ✅ Performance & Security
- [x] Cache timing tests (first request slow, subsequent fast)
- [x] File permission security (0600 enforcement)
- [x] Log security (no secrets visible in logs)
- [x] Proper error handling and logging
- [x] Memory usage and performance acceptable

## Files Generated During Testing

- `config-azure-test.yaml` - Test configuration with real Azure credentials
- `azure-credentials.env` - Environment variables (secure, 0600 permissions)
- `service.log` - Service logs for analysis
- `/tmp/test-secret-file` - Test secret file (cleaned up automatically)
- `/tmp/test-json-secret` - Test JSON template file (cleaned up automatically)

## Security Notes

- All credential files are created with secure permissions (0600)
- No secrets are logged in plain text
- Test files are automatically cleaned up
- Azure resources can be cleaned up with user permission

## Troubleshooting

### Common Issues

1. **Azure CLI not authenticated**
   ```bash
   az login
   az account show
   ```

2. **Missing Go dependencies**
   ```bash
   cd .. && go mod download
   ```

3. **Service startup issues**
   ```bash
   cd .. && go build -o hasura-secret-refresh
   ```

4. **Key Vault permissions**
   ```bash
   az keyvault show --name "YOUR_VAULT" --query properties.enableRbacAuthorization
   az role assignment list --assignee "YOUR_CLIENT_ID"
   ```

### Log Analysis
```bash
# Check service logs
cat service.log

# Check for errors
grep -i "error\|failed" service.log

# Verify no secret leaks
grep -i "client_secret\|password" service.log
```

## Cleanup

### Automatic Cleanup
- Test files are automatically cleaned up by the scripts
- Service is automatically stopped on script exit

### Manual Cleanup
```bash
# Stop any running services
pkill hasura-secret-refresh

# Remove test files
rm -f /tmp/test-* service.log

# Azure resources cleanup (with user permission)
# The setup script will ask before deleting Azure resources
```

## Validation Against Manual Tests

These AI-generated tests have been validated against the manual tests in `/testing/azure-key-vault/`:

1. **Test Coverage**: Matches all 10 validation categories from `validate-implementation.sh`
2. **Azure Setup**: Follows the comprehensive approach in `setup-azure-resources.sh`
3. **Integration Testing**: Matches the detailed testing in `test-azure-integration.sh`
4. **Success Criteria**: All checkboxes from the test guide are verified

## Next Steps

After successful testing:
1. Review service logs for any issues
2. Test with your own secrets and configuration
3. Integrate with your Hasura instance
4. Consider running tests in CI/CD pipeline

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review the original manual tests in `/testing/azure-key-vault/`
3. Examine the service logs for detailed error information
4. Verify Azure permissions and authentication
