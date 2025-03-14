data "null_data_source" "list" {
  count = 3
  inputs = {
    foo = "Index ${count.index}"
  }
}

data "null_data_source" "ref_list" {
  count = 1
  inputs = {
    foo = data.null_data_source.list[2].outputs.foo
  }
}