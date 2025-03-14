// The order of references and their alphabetical order is important.
// d -> b -> c

data "d" "foo"{
    count = 1
    value = "Index ${count.index}"
}

data "b" "foo" {
    count = 1
    value = data.d.foo[0].value
}

data "c" "cfoo" {
  count = 1
  value = data.b.foo[0].value
}




