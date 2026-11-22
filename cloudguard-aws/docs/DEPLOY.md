# Deploy guide (Windows / PowerShell)

Do the steps in order. Total time: about 45 minutes.

## 0. Check tools
```powershell
aws sts get-caller-identity
terraform -version     # 1.6 or newer
python --version       # 3.10 or newer
docker --version
```

## 1. Bootstrap (once): state bucket + GitHub login role
```powershell
cd terraform\bootstrap
terraform init
terraform apply
```
Type `yes`. Note the two outputs: `state_bucket` and `github_deploy_role_arn`.
If your GitHub name is not `subhajitajodhya-dotcom`, add `-var github_repo=OWNER/REPO`.

## 2. Build the Lambda zip
```powershell
cd ..\..
python scripts\package.py
```

## 3. Deploy the main stack
```powershell
cd terraform
terraform init -backend-config="bucket=<state_bucket from step 1>"
terraform plan  -var-file=envs/dev.tfvars -var alert_email=<your email>
terraform apply -var-file=envs/dev.tfvars -var alert_email=<your email>
```
Note the outputs (`dashboard_url`, `user_pool_id`).
Open your email and click **Confirm subscription** from AWS.

## 4. Create your login
```powershell
cd ..
.\scripts\create_user.ps1 -PoolId <user_pool_id> -Email <your email> -Group admin
```

## 5. Use it
Open `dashboard_url`, sign in, click **Scan now**. Findings appear live. Click a finding for how to fix it.
Take screenshots into `screenshots/`.

## 6. GitHub
First tidy the Terraform files (CI checks formatting):
```powershell
terraform fmt -recursive terraform
```
Create the repo `cloudguard-aws` (public), upload all files, then in **Settings > Secrets and variables > Actions** add:
- `AWS_DEPLOY_ROLE_ARN` = `github_deploy_role_arn`
- `TF_STATE_BUCKET` = `state_bucket`
- `ALERT_EMAIL` = your email

Also create an Environment called `dev` (Settings > Environments). Every push to `main` runs CI; the Deploy workflow applies Terraform through OIDC.

## 7. Clean up (important)
```powershell
cd terraform
terraform destroy -var-file=envs/dev.tfvars -var alert_email=<your email>
cd bootstrap
terraform destroy
```
If you used an IAM access key for this, delete it in IAM afterwards.

## Troubleshooting
| Problem | Fix |
|---|---|
| `lambda.zip not found` | Run step 2 from the repo root |
| `NotAuthorizedException` on login | Wrong password, or user not created (step 4) |
| Dashboard says offline | Sign out and in again (token expires after 60 minutes) |
| Scan finishes with failed rules | Normal: the rule lacked a permission. See `errors` in `GET /scans` |
| Alarm email right after deploy | Harmless; alarms settle once metrics arrive |
