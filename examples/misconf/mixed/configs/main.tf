
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_alb_listener" "my-alb-listener"{
    port     = "80"
    protocol = "HTTP"
}

resource "aws_db_security_group" "my-group" {

}

resource "azurerm_managed_disk" "source" {
    encryption_settings {
        enabled = var.enableEncryption
    }
}

resource "aws_api_gateway_domain_name" "missing_security_policy" {
}

resource "aws_api_gateway_domain_name" "empty_security_policy" {
    security_policy = ""
}

resource "aws_api_gateway_domain_name" "outdated_security_policy" {
    security_policy = "TLS_1_0"
}

resource "aws_api_gateway_domain_name" "valid_security_policy" {
    security_policy = "TLS_1_2"
}
