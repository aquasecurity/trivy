environment = "dev"

service "http" "web_proxy" {
  listen_addr = "0.0.0.0:8080"

  process "main" {
    command = ["/usr/local/bin/awesome-app", "server"]
  }

  process "mgmt" {
    command = ["/usr/local/bin/awesome-app", "mgmt"]
  }
}