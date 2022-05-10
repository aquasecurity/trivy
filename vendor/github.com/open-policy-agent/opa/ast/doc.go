// Copyright 2016 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

// Package ast declares Rego syntax tree types and also includes a parser and compiler for preparing policies for execution in the policy engine.
//
// Rego policies are defined using a relatively small set of types: modules, package and import declarations, rules, expressions, and terms. At their core, policies consist of rules that are defined by one or more expressions over documents available to the policy engine. The expressions are defined by intrinsic values (terms) such as strings, objects, variables, etc.
//
// Rego policies are typically defined in text files and then parsed and compiled by the policy engine at runtime. The parsing stage takes the text or string representation of the policy and converts it into an abstract syntax tree (AST) that consists of the types mentioned above. The AST is organized as follows:
//
//  Module
//   |
//   +--- Package (Reference)
//   |
//   +--- Imports
//   |     |
//   |     +--- Import (Term)
//   |
//   +--- Rules
//         |
//         +--- Rule
//               |
//               +--- Head
//               |     |
//               |     +--- Name (Variable)
//               |     |
//               |     +--- Key (Term)
//               |     |
//               |     +--- Value (Term)
//               |
//               +--- Body
//                     |
//                     +--- Expression (Term | Terms | Variable Declaration)
//
// At query time, the policy engine expects policies to have been compiled. The compilation stage takes one or more modules and compiles them into a format that the policy engine supports.
package ast
