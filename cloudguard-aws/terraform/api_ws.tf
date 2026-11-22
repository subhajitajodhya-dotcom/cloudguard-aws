# ---- WebSocket API: live updates in the dashboard ----
resource "aws_apigatewayv2_api" "ws" {
  name                       = "${local.name}-ws"
  protocol_type              = "WEBSOCKET"
  route_selection_expression = "$request.body.action"
}

# The browser connects with  wss://...?token=<JWT>. This function checks the token.
resource "aws_apigatewayv2_authorizer" "ws" {
  api_id           = aws_apigatewayv2_api.ws.id
  name             = "cognito-token"
  authorizer_type  = "REQUEST"
  authorizer_uri   = aws_lambda_function.fn["ws_authorizer"].invoke_arn
  identity_sources = ["route.request.querystring.token"]
}

locals {
  ws_routes = {
    "$connect"    = { fn = "ws_connect", auth = true }
    "$disconnect" = { fn = "ws_disconnect", auth = false }
    "$default"    = { fn = "ws_default", auth = false }
  }
}

resource "aws_apigatewayv2_integration" "ws" {
  for_each         = local.ws_routes
  api_id           = aws_apigatewayv2_api.ws.id
  integration_type = "AWS_PROXY"
  integration_uri  = aws_lambda_function.fn[each.value.fn].invoke_arn
}

resource "aws_apigatewayv2_route" "ws" {
  for_each           = local.ws_routes
  api_id             = aws_apigatewayv2_api.ws.id
  route_key          = each.key
  target             = "integrations/${aws_apigatewayv2_integration.ws[each.key].id}"
  authorization_type = each.value.auth ? "CUSTOM" : "NONE"
  authorizer_id      = each.value.auth ? aws_apigatewayv2_authorizer.ws.id : null
}

resource "aws_apigatewayv2_deployment" "ws" {
  api_id = aws_apigatewayv2_api.ws.id

  triggers = {
    redeploy = sha1(jsonencode([
      [for r in aws_apigatewayv2_route.ws : r.id],
      [for i in aws_apigatewayv2_integration.ws : i.id],
      aws_apigatewayv2_authorizer.ws.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_apigatewayv2_stage" "ws" {
  api_id        = aws_apigatewayv2_api.ws.id
  name          = local.ws_stage
  deployment_id = aws_apigatewayv2_deployment.ws.id

  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }
}

resource "aws_lambda_permission" "ws_routes" {
  for_each      = local.ws_routes
  statement_id  = "AllowWs-${replace(replace(each.key, "$", ""), "/", "")}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn[each.value.fn].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.ws.execution_arn}/*/${each.key}"
}

resource "aws_lambda_permission" "ws_authorizer" {
  statement_id  = "AllowWsAuthorizer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn["ws_authorizer"].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.ws.execution_arn}/authorizers/${aws_apigatewayv2_authorizer.ws.id}"
}
