# Step Functions state machine: Parse -> Choice(ai) -> [Enrich] -> Export.
# Spec §4.5.
#
# Standard (not Express) workflow: executions run for minutes on large scans,
# need durable per-execution history for audit, and are low-volume — every
# reason Express exists (sub-second, high-throughput, no history) is the
# opposite of this workload.
#
# §6 idempotency contract — a re-run of any stage is safe because:
#   * artifact keys are derived from jobId alone (jobs/<id>/findings.json,
#     jobs/<id>/report.xlsx), so a second write OVERWRITES; nothing appends or
#     suffixes, so a retry cannot produce a second, divergent report.
#   * job-status writes converge: DynamoJobStore puts the whole record, and the
#     stages are strictly sequential (one writer at a time), so last-write-wins
#     lands on the same state a first-time run would have reached.
# This is what makes the Retry blocks below safe to have at all.

locals {
  # Transient-only. A malformed scan file fails deterministically, and retrying
  # it three times just burns three times the money to reach the same failure —
  # so States.TaskFailed (which a StageFailed raise surfaces as) is deliberately
  # NOT in this list.
  retry = [{
    ErrorEquals = [
      "Lambda.ServiceException",
      "Lambda.AWSLambdaException",
      "Lambda.SdkClientException",
      "Lambda.TooManyRequestsException",
    ]
    IntervalSeconds = 2
    MaxAttempts     = 3
    BackoffRate     = 2.0
  }]

  # ResultPath keeps the original state input intact and files the error beside
  # it under `error`, so the marker function still sees jobId.
  catch = [{
    ErrorEquals = ["States.ALL"]
    ResultPath  = "$.error"
    Next        = "MarkError"
  }]

  definition = jsonencode({
    Comment = "STIG Condenser: parse scan results, optionally enrich, export the findings workbook."
    StartAt = "Parse"
    States = {
      Parse = {
        Type     = "Task"
        Resource = var.function_arns["parser"]
        # Pass the state input through unchanged: the handlers return their own
        # event, and the next state needs the same {jobId, inputFilenames,
        # aiEnabled} shape.
        OutputPath = "$"
        Retry      = local.retry
        Catch      = local.catch
        Next       = "AiEnabled"
      }

      AiEnabled = {
        Type = "Choice"
        Choices = [{
          Variable      = "$.aiEnabled"
          BooleanEquals = true
          Next          = "Enrich"
        }]
        Default = "Export"
      }

      Enrich = {
        Type       = "Task"
        Resource   = var.function_arns["enricher"]
        OutputPath = "$"
        Retry      = local.retry
        # Enrichment is optional by design: if it fails, the operator still gets
        # their findings workbook. So this Catch goes to Export, NOT to
        # MarkError — a Bedrock outage must not destroy a job whose parse
        # already succeeded. The failure is not silent: the enricher records
        # ai=failed, and the exporter settles the gate to `failed` if the
        # enricher died before it could.
        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.error"
          Next        = "Export"
        }]
        Next = "Export"
      }

      Export = {
        Type       = "Task"
        Resource   = var.function_arns["exporter"]
        OutputPath = "$"
        Retry      = local.retry
        Catch      = local.catch
        Next       = "Done"
      }

      # A hard Lambda kill (OOM, timeout) never reaches the stage's own error
      # path, so without this the job record would sit at `running` forever and
      # the operator would watch a progress bar that never moves.
      MarkError = {
        Type       = "Task"
        Resource   = var.function_arns["marker"]
        OutputPath = "$"
        Retry      = local.retry
        # If even the marker fails, fail loudly rather than reporting success.
        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.markerError"
          Next        = "Failed"
        }]
        Next = "Failed"
      }

      Failed = {
        Type  = "Fail"
        Error = "StigCondenserJobFailed"
        Cause = "A pipeline stage failed. The job record carries the operator-facing reason."
      }

      Done = {
        Type = "Succeed"
      }
    }
  })
}

# ---------------------------------------------------------------------------
# Execution role — may invoke exactly these functions, nothing else
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "execution" {
  #checkov:skip=CKV_AWS_356:The "*" below is on the log-DELIVERY actions, which AWS does not support resource-level permissions for. Every other statement is scoped to exact ARNs.
  statement {
    sid       = "InvokeStageFunctions"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = values(var.function_arns)
  }

  # The delivery half of logging does not support resource-level permissions;
  # AWS requires "*" on these. The log group itself is scoped below.
  statement {
    sid    = "DeliverExecutionLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "states" {
  name               = "${var.name_prefix}-states"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = merge(var.tags, { Name = "${var.name_prefix}-states" })
}

resource "aws_iam_role_policy" "states" {
  name   = "${var.name_prefix}-states"
  role   = aws_iam_role.states.id
  policy = data.aws_iam_policy_document.execution.json
}

# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "states" {
  name              = "/aws/vendedlogs/states/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.tags, { Name = "${var.name_prefix}-states" })
}

resource "aws_sfn_state_machine" "this" {
  #checkov:skip=CKV_AWS_284:X-Ray is off by design — it needs an extra interface endpoint (~$8/mo) in a VPC with no internet route, and the execution history already tells us which state failed.
  #checkov:skip=CKV_AWS_285:Execution history logging IS enabled below. The check wants level=ALL; ERROR is deliberate — ALL logs the state input, which carries CUI filenames, into CloudWatch.
  name     = var.name_prefix
  role_arn = aws_iam_role.states.arn
  type     = "STANDARD"

  definition = local.definition

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.states.arn}:*"
    include_execution_data = false # execution data carries CUI filenames
    level                  = "ERROR"
  }

  tracing_configuration {
    enabled = false
  }

  tags = merge(var.tags, { Name = var.name_prefix })
}
