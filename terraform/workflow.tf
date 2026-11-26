# ---- Step Functions: decide whether to email an alert after a scan ----
data "aws_iam_policy_document" "sfn_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "cloudguard-${var.environment}-sfn"
  assume_role_policy = data.aws_iam_policy_document.sfn_trust.json
}

data "aws_iam_policy_document" "sfn" {
  statement {
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "sfn" {
  name   = "publish-alert"
  role   = aws_iam_role.sfn.id
  policy = data.aws_iam_policy_document.sfn.json
}

resource "aws_sfn_state_machine" "alert" {
  name     = "${local.name}-alert"
  role_arn = aws_iam_role.sfn.arn

  definition = jsonencode({
    Comment = "After each scan: email only if there are NEW high or critical findings"
    StartAt = "AnyNewSeriousFindings"
    States = {
      AnyNewSeriousFindings = {
        Type = "Choice"
        Choices = [{
          Variable           = "$.new_high"
          NumericGreaterThan = 0
          Next               = "SendAlert"
        }]
        Default = "NothingToReport"
      }
      SendAlert = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn    = aws_sns_topic.alerts.arn
          Subject     = "CloudGuard: new serious findings"
          "Message.$" = "States.Format('Scan {} found {} new HIGH/CRITICAL findings. Security score: {}. Open findings: {}.', $.scan_id, $.new_high, $.score, $.open_total)"
        }
        End = true
      }
      NothingToReport = {
        Type = "Succeed"
      }
    }
  })
}
