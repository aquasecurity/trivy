package user.terraform.ID007

test_denied {
	msg := "ASG 'my_asg' desires too much capacity"
	deny[msg] with input as {
		"format_version": "0.1",
		"terraform_version": "0.12.6",
		"planned_values": {"root_module": {"resources": [{
			"address": "aws_autoscaling_group.my_asg",
			"mode": "managed",
			"type": "aws_autoscaling_group",
			"name": "my_asg",
			"provider_name": "aws",
			"schema_version": 0,
			"values": {
				"availability_zones": ["us-west-1a"],
				"desired_capacity": 20,
				"enabled_metrics": null,
				"force_delete": true,
				"health_check_grace_period": 300,
				"health_check_type": "ELB",
				"initial_lifecycle_hook": [],
				"launch_configuration": "my_web_config",
				"launch_template": [],
				"max_size": 5,
				"metrics_granularity": "1Minute",
			},
		}]}},
	}
}

test_allowed {
	r := deny with input as {"resource": {"aws_security_group_rule": {"sample": {
		"type": "ingress",
		"cidr_blocks": ["192.168.0.0/24"],
	}}}}

	count(r) == 0
}
