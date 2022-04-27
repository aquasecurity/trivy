package version

import (
	"fmt"
	"strconv"
	"strings"
)

var (
	Qualifiers          = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}
	Aliases             = map[string]string{"ga": "", "final": "", "release": "", "cr": "rc"}
	ReleaseVersionIndex = fmt.Sprint(indexOf("", Qualifiers))
)

type Version struct {
	Value string
	Items ListItem
}

func NewVersion(v string) (Version, error) {
	return Version{
		Value: v,
		Items: parseVersion(v),
	}, nil
}

func (v1 Version) String() string {
	return v1.Value
}

func (v1 Version) Compare(v2 Version) int {
	return v1.Items.Compare(v2.Items)
}

func (v1 Version) Equal(v2 Version) bool {
	return v1.Compare(v2) == 0
}

func (v1 Version) GreaterThan(v2 Version) bool {
	return v1.Compare(v2) > 0
}

func (v1 Version) LessThan(v2 Version) bool {
	return v1.Compare(v2) < 0
}

func (v1 Version) GreaterThanOrEqual(v2 Version) bool {
	return v1.Compare(v2) >= 0
}

func (v1 Version) LessThanOrEqual(v2 Version) bool {
	return v1.Compare(v2) <= 0
}

type Item interface {
	Compare(v2 Item) int
	isNull() bool
}

func parseItem(isDigit bool, item string) Item {
	if isDigit {
		i, _ := strconv.Atoi(item)
		return IntItem(i)
	}
	return newStringItem(item, false)
}

type IntItem int

func (item1 IntItem) Compare(item2 Item) int {
	if item2 == nil {
		if item1 == 0 {
			return 0
		}
		return 1 // 1.0 == 1, 1.1 > 1
	}

	switch t := item2.(type) {
	case IntItem:
		return compareInt(int(item1), int(t))
	case StringItem:
		return 1 // 1.1 > 1-sp
	case ListItem:
		return 1 // 1.1 > 1-1
	}
	return 0
}

func (item1 IntItem) isNull() bool {
	return item1 == 0
}

type StringItem string

func newStringItem(value string, followedByDigit bool) StringItem {
	if followedByDigit {
		switch value {
		case "a":
			return "alpha"
		case "b":
			return "beta"
		case "m":
			return "milestone"
		}
	}

	v, ok := Aliases[value]
	if ok {
		return StringItem(v)
	}
	return StringItem(value)
}

func (item1 StringItem) Compare(item2 Item) int {
	if item2 == nil {
		// 1-rc < 1, 1-ga > 1
		return strings.Compare(item1.comparableQualifier(), ReleaseVersionIndex)
	}

	switch v := item2.(type) {
	case IntItem:
		return -1
	case StringItem:
		return strings.Compare(item1.comparableQualifier(), v.comparableQualifier())
	case ListItem:
		return -1 // 1.any < 1-1
	}
	return 0
}

func (item1 StringItem) isNull() bool {
	return item1 == ""
}

func (item1 StringItem) comparableQualifier() string {
	index := indexOf(string(item1), Qualifiers)
	if index == -1 {
		return fmt.Sprintf("%d-%s", len(Qualifiers), item1)
	}
	return fmt.Sprint(index)
}

func indexOf(s string, sa []string) int {
	for i, q := range sa {
		if q == s {
			return i
		}
	}
	return -1
}

type ListItem []Item

func (items1 ListItem) Compare(item2 Item) int {
	if item2 == nil {
		if len(items1) == 0 {
			return 0 // 1-0 = 1- (normalize) = 1
		}
		// Compare the entire list of items with null - not just the first one, MNG-6964
		for _, item := range items1 {
			if result := item.Compare(nil); result != 0 {
				return result
			}
		}
		return 0
	}

	switch v := item2.(type) {
	case IntItem:
		return -1 // 1-1 < 1.0.x
	case StringItem:
		return 1 // 1-1 > 1-sp
	case ListItem:
		iter := zip(items1, v)
		for tuple := iter(); tuple != nil; tuple = iter() {
			l, r := tuple[0], tuple[1]

			var result int
			if l == nil {
				// if this is shorter, then invert the compare and mul with -1
				result = -1 * r.Compare(l)
			} else {
				result = l.Compare(r)
			}
			if result != 0 {
				return result
			}
		}
		return 0
	}
	return 0
}

func (items1 ListItem) isNull() bool {
	return len(items1) == 0
}

func (items1 ListItem) normalize() ListItem {
	ret := items1
	for i := len(items1) - 1; i >= 0; i-- {
		lastItem := items1[i]
		if lastItem.isNull() {
			ret = ret[:i]
		} else if _, ok := lastItem.(ListItem); !ok {
			break
		}
	}
	return ret
}

func zip(a, b ListItem) func() []Item {
	i := 0
	return func() []Item {
		var item1, item2 Item
		if i < len(a) {
			item1 = a[i]
		}
		if i < len(b) {
			item2 = b[i]
		}
		if item1 == nil && item2 == nil {
			return nil
		}
		i++
		return []Item{item1, item2}
	}
}

// parseVersion is normalize version string.
func parseVersion(v string) ListItem {
	stack := new(ListItemStack)
	var list ListItem

	isDigit := false
	startIndex := 0
	str := strings.ToLower(v)
	sa := strings.Split(str, "")
	for i, c := range sa {
		if c == "." {
			if i == startIndex {
				list = append(list, IntItem(0))
			} else {
				list = append(list, parseItem(isDigit, str[startIndex:i]))
			}
			startIndex = i + 1
		} else if c == "-" {
			if i == startIndex {
				list = append(list, IntItem(0))
			} else {
				list = append(list, parseItem(isDigit, str[startIndex:i]))
			}
			startIndex = i + 1

			stack.Push(list)
			list = ListItem{}

		} else if _, err := strconv.Atoi(c); err == nil {
			if !isDigit && i > startIndex {
				list = append(list, newStringItem(str[startIndex:i], true))
				startIndex = i

				stack.Push(list)
				list = ListItem{}
			}

			isDigit = true
		} else {
			if isDigit && i > startIndex {
				list = append(list, parseItem(true, str[startIndex:i]))
				startIndex = i

				stack.Push(list)
				list = ListItem{}
			}
			isDigit = false
		}
	}
	if len(v) > startIndex {
		list = append(list, parseItem(isDigit, str[startIndex:]))
		stack.Push(list)
	}

	if stack.IsEmpty() {
		stack.Push(list)
	}

	ret := stack.Pop().normalize()
	for !stack.IsEmpty() {
		ret = append(stack.Pop().normalize(), ret)
	}
	return ret
}

func compareInt(a, b int) int {
	if a == b {
		return 0
	} else if a > b {
		return 1
	}
	return -1
}
