terraform {
  required_providers {
    vsphere = {
      source  = "hashicorp/vsphere"
      version = "2.8.1"
    }
  }
}


// aother works
data "o" "b"{
    count = 1
    value = "Index ${count.index}"
}

data "b" "b" {
    count = 1
    value = data.o.b[0].value
}

data "c" "c" {
  count = 1
  value = data.b.b[0].value
}


# data "other" "base" {
#   count = 1
#   value = "Index 0"
#   # value = data.null_data_source.list[2].inputs.foo
# }
#
#
# data "aother" "ref" {
#   count = 1
#   value = data.other.base[0].value
# }
#
# data "other" "other" {
#   count = 1
#   value = data.aother.ref[0].value
# }
