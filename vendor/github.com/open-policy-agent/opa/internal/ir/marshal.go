package ir

import (
	"encoding/json"
	"reflect"
)

func (a *Block) MarshalJSON() ([]byte, error) {
	var result typedBlock
	result.Stmts = make([]typedStmt, len(a.Stmts))
	for i := range a.Stmts {
		tpe := reflect.Indirect(reflect.ValueOf(a.Stmts[i])).Type().Name()
		result.Stmts[i] = typedStmt{
			Type: tpe,
			Stmt: a.Stmts[i],
		}
	}
	return json.Marshal(result)
}

func (a *Block) UnmarshalJSON(bs []byte) error {
	var typed rawTypedBlock
	if err := json.Unmarshal(bs, &typed); err != nil {
		return err
	}
	a.Stmts = make([]Stmt, len(typed.Stmts))
	for i := range typed.Stmts {
		var err error
		a.Stmts[i], err = typed.Stmts[i].Unmarshal()
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *Operand) MarshalJSON() ([]byte, error) {
	var result typedOperand
	result.Value = a.Value
	result.Type = a.Value.typeHint()
	return json.Marshal(result)
}

func (a *Operand) UnmarshalJSON(bs []byte) error {
	var typed rawTypedOperand
	if err := json.Unmarshal(bs, &typed); err != nil {
		return err
	}
	x := valFactories[typed.Type]()
	if err := json.Unmarshal(typed.Value, &x); err != nil {
		return err
	}
	a.Value = x
	return nil
}

type typedBlock struct {
	Stmts []typedStmt `json:"stmts"`
}

type typedStmt struct {
	Type string `json:"type"`
	Stmt Stmt   `json:"stmt"`
}

type rawTypedBlock struct {
	Stmts []rawTypedStmt `json:"stmts"`
}

type rawTypedStmt struct {
	Type string          `json:"type"`
	Stmt json.RawMessage `json:"stmt"`
}

func (raw rawTypedStmt) Unmarshal() (Stmt, error) {
	x := stmtFactories[raw.Type]()
	if err := json.Unmarshal(raw.Stmt, &x); err != nil {
		return nil, err
	}
	return x, nil
}

type rawTypedOperand struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type typedOperand struct {
	Type  string `json:"type"`
	Value Val    `json:"value"`
}

var stmtFactories = map[string]func() Stmt{
	"ReturnLocalStmt":      func() Stmt { return &ReturnLocalStmt{} },
	"CallStmt":             func() Stmt { return &CallStmt{} },
	"CallDynamicStmt":      func() Stmt { return &CallDynamicStmt{} },
	"BlockStmt":            func() Stmt { return &BlockStmt{} },
	"BreakStmt":            func() Stmt { return &BreakStmt{} },
	"DotStmt":              func() Stmt { return &DotStmt{} },
	"LenStmt":              func() Stmt { return &LenStmt{} },
	"ScanStmt":             func() Stmt { return &ScanStmt{} },
	"NotStmt":              func() Stmt { return &NotStmt{} },
	"AssignIntStmt":        func() Stmt { return &AssignIntStmt{} },
	"AssignVarStmt":        func() Stmt { return &AssignVarStmt{} },
	"AssignVarOnceStmt":    func() Stmt { return &AssignVarOnceStmt{} },
	"ResetLocalStmt":       func() Stmt { return &ResetLocalStmt{} },
	"MakeNullStmt":         func() Stmt { return &MakeNullStmt{} },
	"MakeNumberIntStmt":    func() Stmt { return &MakeNumberIntStmt{} },
	"MakeNumberRefStmt":    func() Stmt { return &MakeNumberRefStmt{} },
	"MakeArrayStmt":        func() Stmt { return &MakeArrayStmt{} },
	"MakeObjectStmt":       func() Stmt { return &MakeObjectStmt{} },
	"MakeSetStmt":          func() Stmt { return &MakeSetStmt{} },
	"EqualStmt":            func() Stmt { return &EqualStmt{} },
	"NotEqualStmt":         func() Stmt { return &NotEqualStmt{} },
	"IsArrayStmt":          func() Stmt { return &IsArrayStmt{} },
	"IsObjectStmt":         func() Stmt { return &IsObjectStmt{} },
	"IsDefinedStmt":        func() Stmt { return &IsDefinedStmt{} },
	"IsUndefinedStmt":      func() Stmt { return &IsUndefinedStmt{} },
	"ArrayAppendStmt":      func() Stmt { return &ArrayAppendStmt{} },
	"ObjectInsertStmt":     func() Stmt { return &ObjectInsertStmt{} },
	"ObjectInsertOnceStmt": func() Stmt { return &ObjectInsertOnceStmt{} },
	"ObjectMergeStmt":      func() Stmt { return &ObjectMergeStmt{} },
	"SetAddStmt":           func() Stmt { return &SetAddStmt{} },
	"WithStmt":             func() Stmt { return &WithStmt{} },
	"NopStmt":              func() Stmt { return &NopStmt{} },
	"ResultSetAddStmt":     func() Stmt { return &ResultSetAddStmt{} },
}

var valFactories = map[string]func() Val{
	"bool":         func() Val { var x Bool; return &x },
	"string_index": func() Val { var x StringIndex; return &x },
	"local":        func() Val { var x Local; return &x },
}
