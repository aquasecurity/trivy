%{
package expression
%}

%union{
    token Token
    expr  Expression
}

%type<expr> license
%type<expr> simple
%type<expr> plus
%type<expr> compound
%token<token> IDENT OR AND WITH

%left OR
%left AND
%right WITH
%right '+'

%%

license
    : compound
    {
        $$ = $1
        if l, ok := yylex.(*Lexer); ok{
                l.result = $$
        }
    }

simple
    : IDENT
    {
        $$ = SimpleExpr{License: $1.literal}
    }
    | simple IDENT /* e.g. Public Domain */
    {
        $$ = SimpleExpr{License: $1.String() + " " + $2.literal}
    }

plus
    : simple '+'
    {
        $$ = SimpleExpr{License: $1.String(), HasPlus: true}
    }

compound
    : simple {
        $$ = $1
    }
    | plus {
        $$ = $1
    }
    | compound AND compound /* compound-expression "AND" compound-expression */
    {
        $$ = CompoundExpr{left: $1, conjunction: $2, right: $3}
    }
    | compound OR compound /* compound-expression "OR" compound-expression */
    {
        $$ = CompoundExpr{left: $1, conjunction: $2, right: $3}
    }
    | compound WITH compound /* simple-expression "WITH" license-exception-id */
    {
        $$ = CompoundExpr{left: $1, conjunction: $2, right: $3}
    }
    | '(' compound ')'
    {
        $$ = $2
    }


%%