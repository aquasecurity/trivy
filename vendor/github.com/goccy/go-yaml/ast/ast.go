package ast

import (
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml/token"
	"golang.org/x/xerrors"
)

var (
	ErrInvalidTokenType  = xerrors.New("invalid token type")
	ErrInvalidAnchorName = xerrors.New("invalid anchor name")
	ErrInvalidAliasName  = xerrors.New("invalid alias name")
)

// NodeType type identifier of node
type NodeType int

const (
	// UnknownNodeType type identifier for default
	UnknownNodeType NodeType = iota
	// DocumentType type identifier for document node
	DocumentType
	// NullType type identifier for null node
	NullType
	// BoolType type identifier for boolean node
	BoolType
	// IntegerType type identifier for integer node
	IntegerType
	// FloatType type identifier for float node
	FloatType
	// InfinityType type identifier for infinity node
	InfinityType
	// NanType type identifier for nan node
	NanType
	// StringType type identifier for string node
	StringType
	// MergeKeyType type identifier for merge key node
	MergeKeyType
	// LiteralType type identifier for literal node
	LiteralType
	// MappingType type identifier for mapping node
	MappingType
	// MappingKeyType type identifier for mapping key node
	MappingKeyType
	// MappingValueType type identifier for mapping value node
	MappingValueType
	// SequenceType type identifier for sequence node
	SequenceType
	// AnchorType type identifier for anchor node
	AnchorType
	// AliasType type identifier for alias node
	AliasType
	// DirectiveType type identifier for directive node
	DirectiveType
	// TagType type identifier for tag node
	TagType
	// CommentType type identifier for comment node
	CommentType
)

// String node type identifier to text
func (t NodeType) String() string {
	switch t {
	case UnknownNodeType:
		return "UnknownNode"
	case DocumentType:
		return "Document"
	case NullType:
		return "Null"
	case BoolType:
		return "Bool"
	case IntegerType:
		return "Integer"
	case FloatType:
		return "Float"
	case InfinityType:
		return "Infinity"
	case NanType:
		return "Nan"
	case StringType:
		return "String"
	case MergeKeyType:
		return "MergeKey"
	case LiteralType:
		return "Literal"
	case MappingType:
		return "Mapping"
	case MappingKeyType:
		return "MappingKey"
	case MappingValueType:
		return "MappingValue"
	case SequenceType:
		return "Sequence"
	case AnchorType:
		return "Anchor"
	case AliasType:
		return "Alias"
	case DirectiveType:
		return "Directive"
	case TagType:
		return "Tag"
	case CommentType:
		return "Comment"
	}
	return ""
}

// Node type of node
type Node interface {
	io.Reader
	// String node to text
	String() string
	// GetToken returns token instance
	GetToken() *token.Token
	// Type returns type of node
	Type() NodeType
	// AddColumn add column number to child nodes recursively
	AddColumn(int)
	// SetComment set comment token to node
	SetComment(*token.Token) error
	// Comment returns comment token instance
	GetComment() *token.Token
	// already read length
	readLen() int
	// append read length
	addReadLen(int)
}

// ScalarNode type for scalar node
type ScalarNode interface {
	Node
	GetValue() interface{}
}

type BaseNode struct {
	Comment *token.Token
	read    int
}

func (n *BaseNode) readLen() int {
	return n.read
}

func (n *BaseNode) addReadLen(len int) {
	n.read += len
}

// GetComment returns comment token instance
func (n *BaseNode) GetComment() *token.Token {
	return n.Comment
}

// SetComment set comment token
func (n *BaseNode) SetComment(tk *token.Token) error {
	if tk.Type != token.CommentType {
		return ErrInvalidTokenType
	}
	n.Comment = tk
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func readNode(p []byte, node Node) (int, error) {
	s := node.String()
	readLen := node.readLen()
	remain := len(s) - readLen
	if remain == 0 {
		return 0, io.EOF
	}
	size := min(remain, len(p))
	for idx, b := range s[readLen : readLen+size] {
		p[idx] = byte(b)
	}
	node.addReadLen(size)
	return size, nil
}

// Null create node for null value
func Null(tk *token.Token) Node {
	return &NullNode{
		BaseNode: &BaseNode{},
		Token:    tk,
	}
}

// Bool create node for boolean value
func Bool(tk *token.Token) Node {
	b, _ := strconv.ParseBool(tk.Value)
	return &BoolNode{
		BaseNode: &BaseNode{},
		Token:    tk,
		Value:    b,
	}
}

// Integer create node for integer value
func Integer(tk *token.Token) Node {
	value := removeUnderScoreFromNumber(tk.Value)
	switch tk.Type {
	case token.BinaryIntegerType:
		// skip two characters because binary token starts with '0b'
		skipCharacterNum := 2
		negativePrefix := ""
		if value[0] == '-' {
			skipCharacterNum++
			negativePrefix = "-"
		}
		if len(negativePrefix) > 0 {
			i, _ := strconv.ParseInt(negativePrefix+value[skipCharacterNum:], 2, 64)
			return &IntegerNode{
				BaseNode: &BaseNode{},
				Token:    tk,
				Value:    i,
			}
		}
		i, _ := strconv.ParseUint(negativePrefix+value[skipCharacterNum:], 2, 64)
		return &IntegerNode{
			BaseNode: &BaseNode{},
			Token:    tk,
			Value:    i,
		}
	case token.OctetIntegerType:
		// octet token starts with '0o' or '-0o' or '0' or '-0'
		skipCharacterNum := 1
		negativePrefix := ""
		if value[0] == '-' {
			skipCharacterNum++
			if value[2] == 'o' {
				skipCharacterNum++
			}
			negativePrefix = "-"
		} else {
			if value[1] == 'o' {
				skipCharacterNum++
			}
		}
		if len(negativePrefix) > 0 {
			i, _ := strconv.ParseInt(negativePrefix+value[skipCharacterNum:], 8, 64)
			return &IntegerNode{
				BaseNode: &BaseNode{},
				Token:    tk,
				Value:    i,
			}
		}
		i, _ := strconv.ParseUint(value[skipCharacterNum:], 8, 64)
		return &IntegerNode{
			BaseNode: &BaseNode{},
			Token:    tk,
			Value:    i,
		}
	case token.HexIntegerType:
		// hex token starts with '0x' or '-0x'
		skipCharacterNum := 2
		negativePrefix := ""
		if value[0] == '-' {
			skipCharacterNum++
			negativePrefix = "-"
		}
		if len(negativePrefix) > 0 {
			i, _ := strconv.ParseInt(negativePrefix+value[skipCharacterNum:], 16, 64)
			return &IntegerNode{
				BaseNode: &BaseNode{},
				Token:    tk,
				Value:    i,
			}
		}
		i, _ := strconv.ParseUint(value[skipCharacterNum:], 16, 64)
		return &IntegerNode{
			BaseNode: &BaseNode{},
			Token:    tk,
			Value:    i,
		}
	}
	if value[0] == '-' || value[0] == '+' {
		i, _ := strconv.ParseInt(value, 10, 64)
		return &IntegerNode{
			BaseNode: &BaseNode{},
			Token:    tk,
			Value:    i,
		}
	}
	i, _ := strconv.ParseUint(value, 10, 64)
	return &IntegerNode{
		BaseNode: &BaseNode{},
		Token:    tk,
		Value:    i,
	}
}

// Float create node for float value
func Float(tk *token.Token) Node {
	f, _ := strconv.ParseFloat(removeUnderScoreFromNumber(tk.Value), 64)
	return &FloatNode{
		BaseNode: &BaseNode{},
		Token:    tk,
		Value:    f,
	}
}

// Infinity create node for .inf or -.inf value
func Infinity(tk *token.Token) *InfinityNode {
	node := &InfinityNode{
		BaseNode: &BaseNode{},
		Token:    tk,
	}
	switch tk.Value {
	case ".inf", ".Inf", ".INF":
		node.Value = math.Inf(0)
	case "-.inf", "-.Inf", "-.INF":
		node.Value = math.Inf(-1)
	}
	return node
}

// Nan create node for .nan value
func Nan(tk *token.Token) *NanNode {
	return &NanNode{
		BaseNode: &BaseNode{},
		Token:    tk,
	}
}

// String create node for string value
func String(tk *token.Token) *StringNode {
	return &StringNode{
		BaseNode: &BaseNode{},
		Token:    tk,
		Value:    tk.Value,
	}
}

// Comment create node for comment
func Comment(tk *token.Token) *CommentNode {
	return &CommentNode{
		BaseNode: &BaseNode{Comment: tk},
	}
}

// MergeKey create node for merge key ( << )
func MergeKey(tk *token.Token) *MergeKeyNode {
	return &MergeKeyNode{
		BaseNode: &BaseNode{},
		Token:    tk,
	}
}

// Mapping create node for map
func Mapping(tk *token.Token, isFlowStyle bool, values ...*MappingValueNode) *MappingNode {
	node := &MappingNode{
		BaseNode:    &BaseNode{},
		Start:       tk,
		IsFlowStyle: isFlowStyle,
		Values:      []*MappingValueNode{},
	}
	node.Values = append(node.Values, values...)
	return node
}

// MappingValue create node for mapping value
func MappingValue(tk *token.Token, key Node, value Node) *MappingValueNode {
	return &MappingValueNode{
		BaseNode: &BaseNode{},
		Start:    tk,
		Key:      key,
		Value:    value,
	}
}

// MappingKey create node for map key ( '?' ).
func MappingKey(tk *token.Token) *MappingKeyNode {
	return &MappingKeyNode{
		BaseNode: &BaseNode{},
		Start:    tk,
	}
}

// Sequence create node for sequence
func Sequence(tk *token.Token, isFlowStyle bool) *SequenceNode {
	return &SequenceNode{
		BaseNode:    &BaseNode{},
		Start:       tk,
		IsFlowStyle: isFlowStyle,
		Values:      []Node{},
	}
}

func Anchor(tk *token.Token) *AnchorNode {
	return &AnchorNode{
		BaseNode: &BaseNode{},
		Start:    tk,
	}
}

func Alias(tk *token.Token) *AliasNode {
	return &AliasNode{
		BaseNode: &BaseNode{},
		Start:    tk,
	}
}

func Document(tk *token.Token, body Node) *DocumentNode {
	return &DocumentNode{
		BaseNode: &BaseNode{},
		Start:    tk,
		Body:     body,
	}
}

func Directive(tk *token.Token) *DirectiveNode {
	return &DirectiveNode{
		BaseNode: &BaseNode{},
		Start:    tk,
	}
}

func Literal(tk *token.Token) *LiteralNode {
	return &LiteralNode{
		BaseNode: &BaseNode{},
		Start:    tk,
	}
}

func Tag(tk *token.Token) *TagNode {
	return &TagNode{
		BaseNode: &BaseNode{},
		Start:    tk,
	}
}

// File contains all documents in YAML file
type File struct {
	Name string
	Docs []*DocumentNode
}

// Read implements (io.Reader).Read
func (f *File) Read(p []byte) (int, error) {
	for _, doc := range f.Docs {
		n, err := doc.Read(p)
		if err == io.EOF {
			continue
		}
		return n, nil
	}
	return 0, io.EOF
}

// String all documents to text
func (f *File) String() string {
	docs := []string{}
	for _, doc := range f.Docs {
		docs = append(docs, doc.String())
	}
	return strings.Join(docs, "\n")
}

// DocumentNode type of Document
type DocumentNode struct {
	*BaseNode
	Start *token.Token // position of DocumentHeader ( `---` )
	End   *token.Token // position of DocumentEnd ( `...` )
	Body  Node
}

// Read implements (io.Reader).Read
func (d *DocumentNode) Read(p []byte) (int, error) {
	return readNode(p, d)
}

// Type returns DocumentNodeType
func (d *DocumentNode) Type() NodeType { return DocumentType }

// GetToken returns token instance
func (d *DocumentNode) GetToken() *token.Token {
	return d.Body.GetToken()
}

// AddColumn add column number to child nodes recursively
func (d *DocumentNode) AddColumn(col int) {
	if d.Body != nil {
		d.Body.AddColumn(col)
	}
}

// String document to text
func (d *DocumentNode) String() string {
	doc := []string{}
	if d.Start != nil {
		doc = append(doc, d.Start.Value)
	}
	doc = append(doc, d.Body.String())
	if d.End != nil {
		doc = append(doc, d.End.Value)
	}
	return strings.Join(doc, "\n")
}

func removeUnderScoreFromNumber(num string) string {
	return strings.ReplaceAll(num, "_", "")
}

// NullNode type of null node
type NullNode struct {
	*BaseNode
	Comment *token.Token // position of Comment ( `#comment` )
	Token   *token.Token
}

// Read implements (io.Reader).Read
func (n *NullNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns NullType
func (n *NullNode) Type() NodeType { return NullType }

// GetToken returns token instance
func (n *NullNode) GetToken() *token.Token {
	return n.Token
}

// AddColumn add column number to child nodes recursively
func (n *NullNode) AddColumn(col int) {
	n.Token.AddColumn(col)
}

// SetComment set comment token
func (n *NullNode) SetComment(tk *token.Token) error {
	if tk.Type != token.CommentType {
		return ErrInvalidTokenType
	}
	n.Comment = tk
	return nil
}

// GetValue returns nil value
func (n *NullNode) GetValue() interface{} {
	return nil
}

// String returns `null` text
func (n *NullNode) String() string {
	return "null"
}

// IntegerNode type of integer node
type IntegerNode struct {
	*BaseNode
	Token *token.Token
	Value interface{} // int64 or uint64 value
}

// Read implements (io.Reader).Read
func (n *IntegerNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns IntegerType
func (n *IntegerNode) Type() NodeType { return IntegerType }

// GetToken returns token instance
func (n *IntegerNode) GetToken() *token.Token {
	return n.Token
}

// AddColumn add column number to child nodes recursively
func (n *IntegerNode) AddColumn(col int) {
	n.Token.AddColumn(col)
}

// GetValue returns int64 value
func (n *IntegerNode) GetValue() interface{} {
	return n.Value
}

// String int64 to text
func (n *IntegerNode) String() string {
	return n.Token.Value
}

// FloatNode type of float node
type FloatNode struct {
	*BaseNode
	Token     *token.Token
	Precision int
	Value     float64
}

// Read implements (io.Reader).Read
func (n *FloatNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns FloatType
func (n *FloatNode) Type() NodeType { return FloatType }

// GetToken returns token instance
func (n *FloatNode) GetToken() *token.Token {
	return n.Token
}

// AddColumn add column number to child nodes recursively
func (n *FloatNode) AddColumn(col int) {
	n.Token.AddColumn(col)
}

// GetValue returns float64 value
func (n *FloatNode) GetValue() interface{} {
	return n.Value
}

// String float64 to text
func (n *FloatNode) String() string {
	return n.Token.Value
}

// StringNode type of string node
type StringNode struct {
	*BaseNode
	Token *token.Token
	Value string
}

// Read implements (io.Reader).Read
func (n *StringNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns StringType
func (n *StringNode) Type() NodeType { return StringType }

// GetToken returns token instance
func (n *StringNode) GetToken() *token.Token {
	return n.Token
}

// AddColumn add column number to child nodes recursively
func (n *StringNode) AddColumn(col int) {
	n.Token.AddColumn(col)
}

// GetValue returns string value
func (n *StringNode) GetValue() interface{} {
	return n.Value
}

// String string value to text with quote or literal header if required
func (n *StringNode) String() string {
	switch n.Token.Type {
	case token.SingleQuoteType:
		return fmt.Sprintf(`'%s'`, n.Value)
	case token.DoubleQuoteType:
		return strconv.Quote(n.Value)
	}

	lbc := token.DetectLineBreakCharacter(n.Value)
	if strings.Contains(n.Value, lbc) {
		// This block assumes that the line breaks in this inside scalar content and the Outside scalar content are the same.
		// It works mostly, but inconsistencies occur if line break characters are mixed.
		header := token.LiteralBlockHeader(n.Value)
		space := strings.Repeat(" ", n.Token.Position.Column-1)
		values := []string{}
		for _, v := range strings.Split(n.Value, lbc) {
			values = append(values, fmt.Sprintf("%s  %s", space, v))
		}
		block := strings.TrimSuffix(strings.TrimSuffix(strings.Join(values, lbc), fmt.Sprintf("%s  %s", lbc, space)), fmt.Sprintf("  %s", space))
		return fmt.Sprintf("%s%s%s", header, lbc, block)
	} else if len(n.Value) > 0 && (n.Value[0] == '{' || n.Value[0] == '[') {
		return fmt.Sprintf(`'%s'`, n.Value)
	}
	return n.Value
}

// LiteralNode type of literal node
type LiteralNode struct {
	*BaseNode
	Start *token.Token
	Value *StringNode
}

// Read implements (io.Reader).Read
func (n *LiteralNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns LiteralType
func (n *LiteralNode) Type() NodeType { return LiteralType }

// GetToken returns token instance
func (n *LiteralNode) GetToken() *token.Token {
	return n.Start
}

// AddColumn add column number to child nodes recursively
func (n *LiteralNode) AddColumn(col int) {
	n.Start.AddColumn(col)
	if n.Value != nil {
		n.Value.AddColumn(col)
	}
}

// GetValue returns string value
func (n *LiteralNode) GetValue() interface{} {
	return n.String()
}

// String literal to text
func (n *LiteralNode) String() string {
	origin := n.Value.GetToken().Origin
	return fmt.Sprintf("%s\n%s", n.Start.Value, strings.TrimRight(strings.TrimRight(origin, " "), "\n"))
}

// MergeKeyNode type of merge key node
type MergeKeyNode struct {
	*BaseNode
	Token *token.Token
}

// Read implements (io.Reader).Read
func (n *MergeKeyNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns MergeKeyType
func (n *MergeKeyNode) Type() NodeType { return MergeKeyType }

// GetToken returns token instance
func (n *MergeKeyNode) GetToken() *token.Token {
	return n.Token
}

// GetValue returns '<<' value
func (n *MergeKeyNode) GetValue() interface{} {
	return n.Token.Value
}

// String returns '<<' value
func (n *MergeKeyNode) String() string {
	return n.Token.Value
}

// AddColumn add column number to child nodes recursively
func (n *MergeKeyNode) AddColumn(col int) {
	n.Token.AddColumn(col)
}

// BoolNode type of boolean node
type BoolNode struct {
	*BaseNode
	Token *token.Token
	Value bool
}

// Read implements (io.Reader).Read
func (n *BoolNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns BoolType
func (n *BoolNode) Type() NodeType { return BoolType }

// GetToken returns token instance
func (n *BoolNode) GetToken() *token.Token {
	return n.Token
}

// AddColumn add column number to child nodes recursively
func (n *BoolNode) AddColumn(col int) {
	n.Token.AddColumn(col)
}

// GetValue returns boolean value
func (n *BoolNode) GetValue() interface{} {
	return n.Value
}

// String boolean to text
func (n *BoolNode) String() string {
	return n.Token.Value
}

// InfinityNode type of infinity node
type InfinityNode struct {
	*BaseNode
	Token *token.Token
	Value float64
}

// Read implements (io.Reader).Read
func (n *InfinityNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns InfinityType
func (n *InfinityNode) Type() NodeType { return InfinityType }

// GetToken returns token instance
func (n *InfinityNode) GetToken() *token.Token {
	return n.Token
}

// AddColumn add column number to child nodes recursively
func (n *InfinityNode) AddColumn(col int) {
	n.Token.AddColumn(col)
}

// GetValue returns math.Inf(0) or math.Inf(-1)
func (n *InfinityNode) GetValue() interface{} {
	return n.Value
}

// String infinity to text
func (n *InfinityNode) String() string {
	return n.Token.Value
}

// NanNode type of nan node
type NanNode struct {
	*BaseNode
	Token *token.Token
}

// Read implements (io.Reader).Read
func (n *NanNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns NanType
func (n *NanNode) Type() NodeType { return NanType }

// GetToken returns token instance
func (n *NanNode) GetToken() *token.Token {
	return n.Token
}

// AddColumn add column number to child nodes recursively
func (n *NanNode) AddColumn(col int) {
	n.Token.AddColumn(col)
}

// GetValue returns math.NaN()
func (n *NanNode) GetValue() interface{} {
	return math.NaN()
}

// String returns .nan
func (n *NanNode) String() string {
	return n.Token.Value
}

// MapNode interface of MappingValueNode / MappingNode
type MapNode interface {
	MapRange() *MapNodeIter
}

// MapNodeIter is an iterator for ranging over a MapNode
type MapNodeIter struct {
	values []*MappingValueNode
	idx    int
}

const (
	startRangeIndex = -1
)

// Next advances the map iterator and reports whether there is another entry.
// It returns false when the iterator is exhausted.
func (m *MapNodeIter) Next() bool {
	m.idx++
	next := m.idx < len(m.values)
	return next
}

// Key returns the key of the iterator's current map node entry.
func (m *MapNodeIter) Key() Node {
	return m.values[m.idx].Key
}

// Value returns the value of the iterator's current map node entry.
func (m *MapNodeIter) Value() Node {
	return m.values[m.idx].Value
}

// MappingNode type of mapping node
type MappingNode struct {
	*BaseNode
	Start       *token.Token
	End         *token.Token
	IsFlowStyle bool
	Values      []*MappingValueNode
}

func (n *MappingNode) startPos() *token.Position {
	if len(n.Values) == 0 {
		return n.Start.Position
	}
	return n.Values[0].Key.GetToken().Position
}

// Merge merge key/value of map.
func (n *MappingNode) Merge(target *MappingNode) {
	keyToMapValueMap := map[string]*MappingValueNode{}
	for _, value := range n.Values {
		key := value.Key.String()
		keyToMapValueMap[key] = value
	}
	column := n.startPos().Column - target.startPos().Column
	target.AddColumn(column)
	for _, value := range target.Values {
		mapValue, exists := keyToMapValueMap[value.Key.String()]
		if exists {
			mapValue.Value = value.Value
		} else {
			n.Values = append(n.Values, value)
		}
	}
}

// Read implements (io.Reader).Read
func (n *MappingNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns MappingType
func (n *MappingNode) Type() NodeType { return MappingType }

// GetToken returns token instance
func (n *MappingNode) GetToken() *token.Token {
	return n.Start
}

// AddColumn add column number to child nodes recursively
func (n *MappingNode) AddColumn(col int) {
	n.Start.AddColumn(col)
	n.End.AddColumn(col)
	for _, value := range n.Values {
		value.AddColumn(col)
	}
}

func (n *MappingNode) flowStyleString() string {
	if len(n.Values) == 0 {
		return "{}"
	}
	values := []string{}
	for _, value := range n.Values {
		values = append(values, strings.TrimLeft(value.String(), " "))
	}
	return fmt.Sprintf("{%s}", strings.Join(values, ", "))
}

func (n *MappingNode) blockStyleString() string {
	if len(n.Values) == 0 {
		return "{}"
	}
	values := []string{}
	for _, value := range n.Values {
		values = append(values, value.String())
	}
	return strings.Join(values, "\n")
}

// String mapping values to text
func (n *MappingNode) String() string {
	if n.IsFlowStyle || len(n.Values) == 0 {
		return n.flowStyleString()
	}
	return n.blockStyleString()
}

// MapRange implements MapNode protocol
func (n *MappingNode) MapRange() *MapNodeIter {
	return &MapNodeIter{
		idx:    startRangeIndex,
		values: n.Values,
	}
}

// MappingKeyNode type of tag node
type MappingKeyNode struct {
	*BaseNode
	Start *token.Token
	Value Node
}

// Read implements (io.Reader).Read
func (n *MappingKeyNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns MappingKeyType
func (n *MappingKeyNode) Type() NodeType { return MappingKeyType }

// GetToken returns token instance
func (n *MappingKeyNode) GetToken() *token.Token {
	return n.Start
}

// AddColumn add column number to child nodes recursively
func (n *MappingKeyNode) AddColumn(col int) {
	n.Start.AddColumn(col)
	if n.Value != nil {
		n.Value.AddColumn(col)
	}
}

// String tag to text
func (n *MappingKeyNode) String() string {
	return fmt.Sprintf("%s %s", n.Start.Value, n.Value.String())
}

// MappingValueNode type of mapping value
type MappingValueNode struct {
	*BaseNode
	Start *token.Token
	Key   Node
	Value Node
}

// Replace replace value node.
func (n *MappingValueNode) Replace(value Node) error {
	column := n.Value.GetToken().Position.Column - value.GetToken().Position.Column
	value.AddColumn(column)
	n.Value = value
	return nil
}

// Read implements (io.Reader).Read
func (n *MappingValueNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns MappingValueType
func (n *MappingValueNode) Type() NodeType { return MappingValueType }

// GetToken returns token instance
func (n *MappingValueNode) GetToken() *token.Token {
	return n.Start
}

// AddColumn add column number to child nodes recursively
func (n *MappingValueNode) AddColumn(col int) {
	n.Start.AddColumn(col)
	if n.Key != nil {
		n.Key.AddColumn(col)
	}
	if n.Value != nil {
		n.Value.AddColumn(col)
	}
}

// String mapping value to text
func (n *MappingValueNode) String() string {
	space := strings.Repeat(" ", n.Key.GetToken().Position.Column-1)
	keyIndentLevel := n.Key.GetToken().Position.IndentLevel
	valueIndentLevel := n.Value.GetToken().Position.IndentLevel
	if _, ok := n.Value.(ScalarNode); ok {
		return fmt.Sprintf("%s%s: %s", space, n.Key.String(), n.Value.String())
	} else if keyIndentLevel < valueIndentLevel {
		return fmt.Sprintf("%s%s:\n%s", space, n.Key.String(), n.Value.String())
	} else if m, ok := n.Value.(*MappingNode); ok && (m.IsFlowStyle || len(m.Values) == 0) {
		return fmt.Sprintf("%s%s: %s", space, n.Key.String(), n.Value.String())
	} else if s, ok := n.Value.(*SequenceNode); ok && (s.IsFlowStyle || len(s.Values) == 0) {
		return fmt.Sprintf("%s%s: %s", space, n.Key.String(), n.Value.String())
	} else if _, ok := n.Value.(*AnchorNode); ok {
		return fmt.Sprintf("%s%s: %s", space, n.Key.String(), n.Value.String())
	} else if _, ok := n.Value.(*AliasNode); ok {
		return fmt.Sprintf("%s%s: %s", space, n.Key.String(), n.Value.String())
	}
	return fmt.Sprintf("%s%s:\n%s", space, n.Key.String(), n.Value.String())
}

// MapRange implements MapNode protocol
func (n *MappingValueNode) MapRange() *MapNodeIter {
	return &MapNodeIter{
		idx:    startRangeIndex,
		values: []*MappingValueNode{n},
	}
}

// ArrayNode interface of SequenceNode
type ArrayNode interface {
	ArrayRange() *ArrayNodeIter
}

// ArrayNodeIter is an iterator for ranging over a ArrayNode
type ArrayNodeIter struct {
	values []Node
	idx    int
}

// Next advances the array iterator and reports whether there is another entry.
// It returns false when the iterator is exhausted.
func (m *ArrayNodeIter) Next() bool {
	m.idx++
	next := m.idx < len(m.values)
	return next
}

// Value returns the value of the iterator's current array entry.
func (m *ArrayNodeIter) Value() Node {
	return m.values[m.idx]
}

// Len returns length of array
func (m *ArrayNodeIter) Len() int {
	return len(m.values)
}

// SequenceNode type of sequence node
type SequenceNode struct {
	*BaseNode
	Start       *token.Token
	End         *token.Token
	IsFlowStyle bool
	Values      []Node
}

// Replace replace value node.
func (n *SequenceNode) Replace(idx int, value Node) error {
	if len(n.Values) <= idx {
		return xerrors.Errorf(
			"invalid index for sequence: sequence length is %d, but specified %d index",
			len(n.Values), idx,
		)
	}
	column := n.Values[idx].GetToken().Position.Column - value.GetToken().Position.Column
	value.AddColumn(column)
	n.Values[idx] = value
	return nil
}

// Merge merge sequence value.
func (n *SequenceNode) Merge(target *SequenceNode) {
	column := n.Start.Position.Column - target.Start.Position.Column
	target.AddColumn(column)
	for _, value := range target.Values {
		n.Values = append(n.Values, value)
	}
}

// Read implements (io.Reader).Read
func (n *SequenceNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns SequenceType
func (n *SequenceNode) Type() NodeType { return SequenceType }

// GetToken returns token instance
func (n *SequenceNode) GetToken() *token.Token {
	return n.Start
}

// AddColumn add column number to child nodes recursively
func (n *SequenceNode) AddColumn(col int) {
	n.Start.AddColumn(col)
	n.End.AddColumn(col)
	for _, value := range n.Values {
		value.AddColumn(col)
	}
}

func (n *SequenceNode) flowStyleString() string {
	values := []string{}
	for _, value := range n.Values {
		values = append(values, value.String())
	}
	return fmt.Sprintf("[%s]", strings.Join(values, ", "))
}

func (n *SequenceNode) blockStyleString() string {
	space := strings.Repeat(" ", n.Start.Position.Column-1)
	values := []string{}
	for _, value := range n.Values {
		valueStr := value.String()
		splittedValues := strings.Split(valueStr, "\n")
		trimmedFirstValue := strings.TrimLeft(splittedValues[0], " ")
		diffLength := len(splittedValues[0]) - len(trimmedFirstValue)
		newValues := []string{trimmedFirstValue}
		for i := 1; i < len(splittedValues); i++ {
			if len(splittedValues[i]) <= diffLength {
				// this line is \n or white space only
				newValues = append(newValues, "")
				continue
			}
			trimmed := splittedValues[i][diffLength:]
			newValues = append(newValues, fmt.Sprintf("%s  %s", space, trimmed))
		}
		newValue := strings.Join(newValues, "\n")
		values = append(values, fmt.Sprintf("%s- %s", space, newValue))
	}
	return strings.Join(values, "\n")
}

// String sequence to text
func (n *SequenceNode) String() string {
	if n.IsFlowStyle || len(n.Values) == 0 {
		return n.flowStyleString()
	}
	return n.blockStyleString()
}

// ArrayRange implements ArrayNode protocol
func (n *SequenceNode) ArrayRange() *ArrayNodeIter {
	return &ArrayNodeIter{
		idx:    startRangeIndex,
		values: n.Values,
	}
}

// AnchorNode type of anchor node
type AnchorNode struct {
	*BaseNode
	Start *token.Token
	Name  Node
	Value Node
}

func (n *AnchorNode) SetName(name string) error {
	if n.Name == nil {
		return ErrInvalidAnchorName
	}
	s, ok := n.Name.(*StringNode)
	if !ok {
		return ErrInvalidAnchorName
	}
	s.Value = name
	return nil
}

// Read implements (io.Reader).Read
func (n *AnchorNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns AnchorType
func (n *AnchorNode) Type() NodeType { return AnchorType }

// GetToken returns token instance
func (n *AnchorNode) GetToken() *token.Token {
	return n.Start
}

// AddColumn add column number to child nodes recursively
func (n *AnchorNode) AddColumn(col int) {
	n.Start.AddColumn(col)
	if n.Name != nil {
		n.Name.AddColumn(col)
	}
	if n.Value != nil {
		n.Value.AddColumn(col)
	}
}

// String anchor to text
func (n *AnchorNode) String() string {
	value := n.Value.String()
	if len(strings.Split(value, "\n")) > 1 {
		return fmt.Sprintf("&%s\n%s", n.Name.String(), value)
	} else if s, ok := n.Value.(*SequenceNode); ok && !s.IsFlowStyle {
		return fmt.Sprintf("&%s\n%s", n.Name.String(), value)
	} else if m, ok := n.Value.(*MappingNode); ok && !m.IsFlowStyle {
		return fmt.Sprintf("&%s\n%s", n.Name.String(), value)
	}
	return fmt.Sprintf("&%s %s", n.Name.String(), value)
}

// AliasNode type of alias node
type AliasNode struct {
	*BaseNode
	Start *token.Token
	Value Node
}

func (n *AliasNode) SetName(name string) error {
	if n.Value == nil {
		return ErrInvalidAliasName
	}
	s, ok := n.Value.(*StringNode)
	if !ok {
		return ErrInvalidAliasName
	}
	s.Value = name
	return nil
}

// Read implements (io.Reader).Read
func (n *AliasNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns AliasType
func (n *AliasNode) Type() NodeType { return AliasType }

// GetToken returns token instance
func (n *AliasNode) GetToken() *token.Token {
	return n.Start
}

// AddColumn add column number to child nodes recursively
func (n *AliasNode) AddColumn(col int) {
	n.Start.AddColumn(col)
	if n.Value != nil {
		n.Value.AddColumn(col)
	}
}

// String alias to text
func (n *AliasNode) String() string {
	return fmt.Sprintf("*%s", n.Value.String())
}

// DirectiveNode type of directive node
type DirectiveNode struct {
	*BaseNode
	Start *token.Token
	Value Node
}

// Read implements (io.Reader).Read
func (n *DirectiveNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns DirectiveType
func (n *DirectiveNode) Type() NodeType { return DirectiveType }

// GetToken returns token instance
func (n *DirectiveNode) GetToken() *token.Token {
	return n.Start
}

// AddColumn add column number to child nodes recursively
func (n *DirectiveNode) AddColumn(col int) {
	if n.Value != nil {
		n.Value.AddColumn(col)
	}
}

// String directive to text
func (n *DirectiveNode) String() string {
	return fmt.Sprintf("%s%s", n.Start.Value, n.Value.String())
}

// TagNode type of tag node
type TagNode struct {
	*BaseNode
	Start *token.Token
	Value Node
}

// Read implements (io.Reader).Read
func (n *TagNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns TagType
func (n *TagNode) Type() NodeType { return TagType }

// GetToken returns token instance
func (n *TagNode) GetToken() *token.Token {
	return n.Start
}

// AddColumn add column number to child nodes recursively
func (n *TagNode) AddColumn(col int) {
	n.Start.AddColumn(col)
	if n.Value != nil {
		n.Value.AddColumn(col)
	}
}

// String tag to text
func (n *TagNode) String() string {
	return fmt.Sprintf("%s %s", n.Start.Value, n.Value.String())
}

// CommentNode type of comment node
type CommentNode struct {
	*BaseNode
}

// Read implements (io.Reader).Read
func (n *CommentNode) Read(p []byte) (int, error) {
	return readNode(p, n)
}

// Type returns TagType
func (n *CommentNode) Type() NodeType { return CommentType }

// GetToken returns token instance
func (n *CommentNode) GetToken() *token.Token { return n.Comment }

// AddColumn add column number to child nodes recursively
func (n *CommentNode) AddColumn(col int) {
	n.Comment.AddColumn(col)
}

// String comment to text
func (n *CommentNode) String() string {
	return n.Comment.Value
}

// Visitor has Visit method that is invokded for each node encountered by Walk.
// If the result visitor w is not nil, Walk visits each of the children of node with the visitor w,
// followed by a call of w.Visit(nil).
type Visitor interface {
	Visit(Node) Visitor
}

// Walk traverses an AST in depth-first order: It starts by calling v.Visit(node); node must not be nil.
// If the visitor w returned by v.Visit(node) is not nil,
// Walk is invoked recursively with visitor w for each of the non-nil children of node,
// followed by a call of w.Visit(nil).
func Walk(v Visitor, node Node) {
	if v = v.Visit(node); v == nil {
		return
	}

	switch n := node.(type) {
	case *CommentNode:
	case *NullNode:
	case *IntegerNode:
	case *FloatNode:
	case *StringNode:
	case *MergeKeyNode:
	case *BoolNode:
	case *InfinityNode:
	case *NanNode:
	case *LiteralNode:
		Walk(v, n.Value)
	case *DirectiveNode:
		Walk(v, n.Value)
	case *TagNode:
		Walk(v, n.Value)
	case *DocumentNode:
		Walk(v, n.Body)
	case *MappingNode:
		for _, value := range n.Values {
			Walk(v, value)
		}
	case *MappingKeyNode:
		Walk(v, n.Value)
	case *MappingValueNode:
		Walk(v, n.Key)
		Walk(v, n.Value)
	case *SequenceNode:
		for _, value := range n.Values {
			Walk(v, value)
		}
	case *AnchorNode:
		Walk(v, n.Name)
		Walk(v, n.Value)
	case *AliasNode:
		Walk(v, n.Value)
	}
}

type filterWalker struct {
	typ     NodeType
	results []Node
}

func (v *filterWalker) Visit(n Node) Visitor {
	if v.typ == n.Type() {
		v.results = append(v.results, n)
	}
	return v
}

// Filter returns a list of nodes that match the given type.
func Filter(typ NodeType, node Node) []Node {
	walker := &filterWalker{typ: typ}
	Walk(walker, node)
	return walker.results
}

// FilterFile returns a list of nodes that match the given type.
func FilterFile(typ NodeType, file *File) []Node {
	results := []Node{}
	for _, doc := range file.Docs {
		walker := &filterWalker{typ: typ}
		Walk(walker, doc)
		results = append(results, walker.results...)
	}
	return results
}

type ErrInvalidMergeType struct {
	dst Node
	src Node
}

func (e *ErrInvalidMergeType) Error() string {
	return fmt.Sprintf("cannot merge %s into %s", e.src.Type(), e.dst.Type())
}

// Merge merge document, map, sequence node.
func Merge(dst Node, src Node) error {
	if doc, ok := src.(*DocumentNode); ok {
		src = doc.Body
	}
	err := &ErrInvalidMergeType{dst: dst, src: src}
	switch dst.Type() {
	case DocumentType:
		node := dst.(*DocumentNode)
		return Merge(node.Body, src)
	case MappingType:
		node := dst.(*MappingNode)
		target, ok := src.(*MappingNode)
		if !ok {
			return err
		}
		node.Merge(target)
		return nil
	case SequenceType:
		node := dst.(*SequenceNode)
		target, ok := src.(*SequenceNode)
		if !ok {
			return err
		}
		node.Merge(target)
		return nil
	}
	return err
}
