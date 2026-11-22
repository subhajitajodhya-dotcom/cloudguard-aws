# Create a dashboard user and put them in a group (PowerShell).
#   .\scripts\create_user.ps1 -PoolId <user-pool-id> -Email <email> -Group admin
param(
  [Parameter(Mandatory)][string]$PoolId,
  [Parameter(Mandatory)][string]$Email,
  [Parameter(Mandatory)][ValidateSet("admin","viewer")][string]$Group
)
$secure = Read-Host "Password (12+ chars, upper, lower, number, symbol)" -AsSecureString
$pw = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
aws cognito-idp admin-create-user --user-pool-id $PoolId --username $Email `
  --user-attributes Name=email,Value=$Email Name=email_verified,Value=true --message-action SUPPRESS | Out-Null
aws cognito-idp admin-set-user-password --user-pool-id $PoolId --username $Email --password $pw --permanent
aws cognito-idp admin-add-user-to-group --user-pool-id $PoolId --username $Email --group-name $Group
Write-Host "Created $Email in group $Group"
