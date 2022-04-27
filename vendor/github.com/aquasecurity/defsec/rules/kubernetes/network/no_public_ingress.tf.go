package network

var terraformNoPublicIngressGoodExamples = []string{
	`
 resource "kubernetes_network_policy" "good_example" {
   metadata {
     name      = "terraform-example-network-policy"
     namespace = "default"
   }
 
   spec {
     pod_selector {
       match_expressions {
         key      = "name"
         operator = "In"
         values   = ["webfront", "api"]
       }
     }
 
     ingress {
       ports {
         port     = "http"
         protocol = "TCP"
       }
       ports {
         port     = "8125"
         protocol = "UDP"
       }
 
       from {
         ip_block {
           cidr = "10.0.0.0/16"
           except = [
             "10.0.0.0/24",
             "10.0.1.0/24",
           ]
         }
       }
     }
 
     egress {
       ports {
         port     = "http"
         protocol = "TCP"
       }
       ports {
         port     = "8125"
         protocol = "UDP"
       }
 
       to {
         ip_block {
           cidr = "0.0.0.0/0"
           except = [
             "10.0.0.0/24",
             "10.0.1.0/24",
           ]
         }
       }
     }
 
     policy_types = ["Ingress", "Egress"]
   }
 }
 `,
}

var terraformNoPublicIngressBadExamples = []string{
	`
 resource "kubernetes_network_policy" "bad_example" {
   metadata {
     name      = "terraform-example-network-policy"
     namespace = "default"
   }
 
   spec {
     pod_selector {
       match_expressions {
         key      = "name"
         operator = "In"
         values   = ["webfront", "api"]
       }
     }
 
     ingress {
       ports {
         port     = "http"
         protocol = "TCP"
       }
       ports {
         port     = "8125"
         protocol = "UDP"
       }
 
       from {
         ip_block {
           cidr = "0.0.0.0/0"
           except = [
             "10.0.0.0/24",
             "10.0.1.0/24",
           ]
         }
       }
     }
 
     egress {
       ports {
         port     = "http"
         protocol = "TCP"
       }
       ports {
         port     = "8125"
         protocol = "UDP"
       }
 
       to {
         ip_block {
           cidr = "0.0.0.0/0"
           except = [
             "10.0.0.0/24",
             "10.0.1.0/24",
           ]
         }
       }
     }
 
     policy_types = ["Ingress", "Egress"]
   }
 }
 `,
}

var terraformNoPublicIngressLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/network_policy#spec.ingress.from.ip_block.cidr`,
}

var terraformNoPublicIngressRemediationMarkdown = ``
