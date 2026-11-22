# ---- Lambda functions. One zip, several entry points. ----
locals {
  functions = {
    api = {
      handler = "app.api.handlers.handler"
      timeout = 15
      memory  = 256
      env = {
        ALLOWED_ROLE_ARNS = join(",", var.allowed_role_arns)
        SCAN_QUEUE_URL    = aws_sqs_queue.scan.url
      }
    }
    ws_authorizer = {
      handler = "app.api.ws.authorizer_handler"
      timeout = 10
      memory  = 256
      env = {
        COGNITO_ISSUER    = local.cognito_issuer
        COGNITO_CLIENT_ID = aws_cognito_user_pool_client.web.id
      }
    }
    ws_connect = {
      handler = "app.api.ws.connect_handler"
      timeout = 10
      memory  = 128
      env     = {}
    }
    ws_disconnect = {
      handler = "app.api.ws.disconnect_handler"
      timeout = 10
      memory  = 128
      env     = {}
    }
    ws_default = {
      handler = "app.api.ws.default_handler"
      timeout = 10
      memory  = 128
      env     = {}
    }
    worker = {
      handler = "app.api.worker.handler"
      timeout = 900
      memory  = 512
      env = {
        WS_ENDPOINT  = "https://${aws_apigatewayv2_api.ws.id}.execute-api.${var.region}.amazonaws.com/${local.ws_stage}"
        SFN_ARN      = aws_sfn_state_machine.alert.arn
        SCAN_REGIONS = join(",", var.scan_regions)
      }
    }
  }
}

resource "aws_cloudwatch_log_group" "fn" {
  for_each          = local.functions
  name              = "/aws/lambda/${local.name}-${each.key}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Every function has its OWN role, so each one only gets what it needs.
resource "aws_iam_role" "fn" {
  for_each           = local.functions
  name               = "cloudguard-${var.environment}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

data "aws_iam_policy_document" "logs" {
  for_each = local.functions
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.fn[each.key].arn}:*"]
  }
}

resource "aws_iam_role_policy" "logs" {
  for_each = local.functions
  name     = "logs"
  role     = aws_iam_role.fn[each.key].id
  policy   = data.aws_iam_policy_document.logs[each.key].json
}

# --- api: read/write the table, put jobs on the queue ---
data "aws_iam_policy_document" "api" {
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.main.arn]
  }
  statement {
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.scan.arn]
  }
}

resource "aws_iam_role_policy" "api" {
  name   = "api"
  role   = aws_iam_role.fn["api"].id
  policy = data.aws_iam_policy_document.api.json
}

# --- websocket connect/disconnect: only the connection items ---
data "aws_iam_policy_document" "ws_table" {
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.main.arn]
  }
}

resource "aws_iam_role_policy" "ws_connect" {
  name   = "table"
  role   = aws_iam_role.fn["ws_connect"].id
  policy = data.aws_iam_policy_document.ws_table.json
}

resource "aws_iam_role_policy" "ws_disconnect" {
  name   = "table"
  role   = aws_iam_role.fn["ws_disconnect"].id
  policy = data.aws_iam_policy_document.ws_table.json
}

# ws_authorizer needs no AWS permissions at all (it only checks a token).
# ws_default replies to the browser.
data "aws_iam_policy_document" "ws_reply" {
  statement {
    actions   = ["execute-api:ManageConnections"]
    resources = ["${aws_apigatewayv2_api.ws.execution_arn}/*"]
  }
}

resource "aws_iam_role_policy" "ws_default" {
  name   = "reply"
  role   = aws_iam_role.fn["ws_default"].id
  policy = data.aws_iam_policy_document.ws_reply.json
}

# --- worker: READ-ONLY scanning plus storing results ---
data "aws_iam_policy_document" "worker" {
  statement {
    sid = "ReadOnlyScan"
    actions = [
      "s3:ListAllMyBuckets", "s3:GetBucketPublicAccessBlock", "s3:GetBucketPolicy",
      "ec2:DescribeSecurityGroups", "ec2:DescribeSubnets",
      "iam:ListUsers", "iam:ListAccessKeys", "iam:ListAttachedUserPolicies",
      "iam:ListUserPolicies", "iam:ListMFADevices", "iam:GetLoginProfile",
      "iam:GetAccountSummary",
      "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "Table"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.main.arn]
  }
  statement {
    sid       = "Queue"
    actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    resources = [aws_sqs_queue.scan.arn]
  }
  statement {
    sid       = "PushToBrowsers"
    actions   = ["execute-api:ManageConnections"]
    resources = ["${aws_apigatewayv2_api.ws.execution_arn}/*"]
  }
  statement {
    sid       = "StartAlertWorkflow"
    actions   = ["states:StartExecution"]
    resources = [aws_sfn_state_machine.alert.arn]
  }
}

resource "aws_iam_role_policy" "worker" {
  name   = "worker"
  role   = aws_iam_role.fn["worker"].id
  policy = data.aws_iam_policy_document.worker.json
}

# Only added when you list roles from other accounts.
data "aws_iam_policy_document" "worker_assume" {
  count = length(var.allowed_role_arns) > 0 ? 1 : 0
  statement {
    actions   = ["sts:AssumeRole"]
    resources = var.allowed_role_arns
  }
}

resource "aws_iam_role_policy" "worker_assume" {
  count  = length(var.allowed_role_arns) > 0 ? 1 : 0
  name   = "assume-allowed-roles"
  role   = aws_iam_role.fn["worker"].id
  policy = data.aws_iam_policy_document.worker_assume[0].json
}

resource "aws_lambda_function" "fn" {
  for_each = local.functions

  function_name    = "${local.name}-${each.key}"
  role             = aws_iam_role.fn[each.key].arn
  runtime          = "python3.12"
  handler          = each.value.handler
  filename         = var.lambda_zip
  source_code_hash = filebase64sha256(var.lambda_zip)
  timeout          = each.value.timeout
  memory_size      = each.value.memory

  environment {
    variables = merge({ TABLE_NAME = aws_dynamodb_table.main.name }, each.value.env)
  }

  depends_on = [aws_cloudwatch_log_group.fn, aws_iam_role_policy.logs]
}

# SQS -> worker
resource "aws_lambda_event_source_mapping" "worker" {
  event_source_arn = aws_sqs_queue.scan.arn
  function_name    = aws_lambda_function.fn["worker"].arn
  batch_size       = 1
}

# Scheduled scans: EventBridge -> SQS (so scheduled and manual scans share one path)
resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.name}-schedule"
  schedule_expression = var.scan_schedule
  state               = var.schedule_enabled ? "ENABLED" : "DISABLED"
}

resource "aws_sqs_queue_policy" "scan" {
  queue_url = aws_sqs_queue.scan.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.scan.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.schedule.arn } }
    }]
  })
}

resource "aws_cloudwatch_event_target" "schedule" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "scan-queue"
  arn       = aws_sqs_queue.scan.arn
  input     = jsonencode({ source = "schedule" })
}
