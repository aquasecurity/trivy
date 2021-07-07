resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"]
}

variable "enableEncryption" {
	default = false
}

resource "azurerm_managed_disk" "source" {
    encryption_settings {
        enabled = var.enableEncryption
    }
}
