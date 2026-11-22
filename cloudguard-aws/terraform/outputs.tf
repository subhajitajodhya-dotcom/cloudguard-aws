output "dashboard_url" {
  value = "https://${aws_cloudfront_distribution.site.domain_name}"
}

output "api_url" {
  value = aws_apigatewayv2_api.http.api_endpoint
}

output "websocket_url" {
  value = "wss://${aws_apigatewayv2_api.ws.id}.execute-api.${var.region}.amazonaws.com/${local.ws_stage}"
}

output "user_pool_id" {
  value = aws_cognito_user_pool.main.id
}

output "client_id" {
  value = aws_cognito_user_pool_client.web.id
}

output "scan_queue_url" {
  value = aws_sqs_queue.scan.url
}

output "dlq_url" {
  value = aws_sqs_queue.dlq.url
}
