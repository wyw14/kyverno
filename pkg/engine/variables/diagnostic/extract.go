package diagnostic

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/engine/variables/regex"
)

// token is one {{ ... }} occurrence inside a string leaf.
type token struct {
	// expr is the trimmed JMESPath expression, shallow '-' marker stripped.
	expr string
	// shallow marks the {{- ... }} shallow substitution form.
	shallow bool
	// whole reports that the token occupies the whole leaf string, in which case
	// the engine keeps the resolved value's native JSON type.
	whole bool
}

// occurrence is a string leaf (or map key) containing one or more variables.
type occurrence struct {
	pointer string
	leaf    string
	tokens  []token
	// scopes are the foreach scopes enclosing the leaf, outermost first.
	scopes []*scope
}

// scope represents one foreach array entry that binds elements.
type scope struct {
	pointer string
	depth   int
	list    string
	raw     map[string]interface{}
	parent  *scope
	// children are the nested foreach entries declared inside this scope.
	children []*scope
}

// extraction holds every variable occurrence and foreach scope found in a rule.
type extraction struct {
	occurrences []occurrence
	roots       []*scope
	// entryNames contains every context entry name declared by the rule, at any
	// foreach depth.
	entryNames map[string]struct{}
}

// extractVariables walks the untyped rule document and records every variable
// occurrence, together with the foreach scopes that enclose it.
func extractVariables(ruleMap map[string]interface{}) *extraction {
	e := &extraction{entryNames: map[string]struct{}{}}
	e.collectEntryNames(ruleMap["context"])
	e.walk(ruleMap, "", nil)
	sort.Slice(e.roots, func(i, j int) bool {
		return e.roots[i].pointer < e.roots[j].pointer
	})
	return e
}

func (e *extraction) addOccurrence(pointer, leaf string, tokens []token, scopes []*scope) {
	e.occurrences = append(e.occurrences, occurrence{
		pointer: pointer,
		leaf:    leaf,
		tokens:  tokens,
		scopes:  append([]*scope{}, scopes...),
	})
}

func (e *extraction) collectEntryNames(raw interface{}) {
	entries, ok := raw.([]interface{})
	if !ok {
		return
	}
	for _, entry := range entries {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := entryMap["name"].(string); ok && name != "" {
			e.entryNames[name] = struct{}{}
		}
	}
}

func (e *extraction) walk(node interface{}, pointer string, scopes []*scope) {
	switch typed := node.(type) {
	case map[string]interface{}:
		for key, value := range typed {
			if key == "context" {
				e.collectEntryNames(value)
			}
			keyPointer := pointer + "/" + escapePointerToken(key)
			if keyTokens := extractTokens(key); len(keyTokens) > 0 {
				// Map keys are always stringified when substituted.
				for i := range keyTokens {
					keyTokens[i].whole = false
				}
				e.addOccurrence(keyPointer, key, keyTokens, scopes)
			}
			if key == "foreach" {
				if array, ok := value.([]interface{}); ok {
					for i, child := range array {
						if childMap, ok := child.(map[string]interface{}); ok {
							e.walkScope(childMap, pointer+"/foreach/"+strconv.Itoa(i), scopes)
						}
					}
					continue
				}
			}
			e.walk(value, keyPointer, scopes)
		}
	case []interface{}:
		for i, child := range typed {
			e.walk(child, pointer+"/"+strconv.Itoa(i), scopes)
		}
	case string:
		if tokens := extractTokens(typed); len(tokens) > 0 {
			e.addOccurrence(pointer, typed, tokens, scopes)
		}
	}
}

// walkScope walks one foreach entry. list, order, context and preconditions are
// evaluated with the outer element bindings; pattern, deny, patches and nested foreach
// declarations are evaluated with this scope's element bound.
func (e *extraction) walkScope(node map[string]interface{}, pointer string, parents []*scope) {
	list, _ := node["list"].(string)
	s := &scope{
		pointer: pointer,
		depth:   len(parents),
		list:    list,
		raw:     node,
	}
	if len(parents) > 0 {
		s.parent = parents[len(parents)-1]
		s.parent.children = append(s.parent.children, s)
	} else {
		e.roots = append(e.roots, s)
	}
	extended := append(append([]*scope{}, parents...), s)
	for key, value := range node {
		keyPointer := pointer + "/" + escapePointerToken(key)
		if key == "context" {
			e.collectEntryNames(value)
		}
		switch key {
		case "list", "order", "context", "preconditions":
			// these fields are evaluated before the element is bound.
			e.walk(value, keyPointer, parents)
		case "foreach":
			// nested foreach arrays bind an additional element and therefore open a
			// new scope; they must not be traversed as plain arrays.
			if array, ok := value.([]interface{}); ok {
				for i, child := range array {
					if childMap, ok := child.(map[string]interface{}); ok {
						e.walkScope(childMap, keyPointer+"/"+strconv.Itoa(i), extended)
					}
				}
			} else {
				e.walk(value, keyPointer, extended)
			}
		default:
			e.walk(value, keyPointer, extended)
		}
	}
}

// extractTokens parses every {{ ... }} occurrence in a leaf. It mirrors the engine's
// variable regex, including the single leading capture character (x{{...}}) and the
// {{- ... }} shallow marker.
func extractTokens(leaf string) []token {
	matches := regex.RegexVariables.FindAllStringSubmatchIndex(leaf, -1)
	if len(matches) == 0 {
		return nil
	}
	tokens := make([]token, 0, len(matches))
	for _, match := range matches {
		// The regex has two groups: a possible leading character and the {{ ... }}
		// token. Submatch indices 4:6 delimit the token.
		if len(match) < 6 {
			continue
		}
		raw := leaf[match[4]:match[5]]
		tok := token{
			whole: len(matches) == 1 && strings.TrimSpace(leaf) == raw,
		}
		inner := strings.TrimSpace(raw[2 : len(raw)-2])
		if strings.HasPrefix(inner, "-") {
			tok.shallow = true
			inner = strings.TrimSpace(inner[1:])
		}
		tok.expr = inner
		tokens = append(tokens, tok)
	}
	return tokens
}

func escapePointerToken(token string) string {
	return strings.ReplaceAll(token, "/", `\/`)
}

var elementRootRegex = regexp.MustCompile(`^element(Index)?\d*$`)

// classifySource attributes an expression to a value source.
func classifySource(expr string, entryNames map[string]struct{}) (VariableSource, string) {
	root, second := expressionRoots(expr)
	switch {
	case root == "request":
		if second == "object" || second == "oldObject" {
			return SourceResource, ""
		}
		return SourceRequest, ""
	case root == "target":
		return SourceTarget, ""
	case root == "image" || root == "images":
		return SourceImages, ""
	case root == "serviceAccountName" || root == "serviceAccountNamespace":
		return SourceServiceAccount, ""
	case elementRootRegex.MatchString(root):
		return SourceForEachElement, ""
	}
	if root != "" {
		if _, ok := entryNames[root]; ok {
			return SourceContextEntry, root
		}
	}
	if root == "" || strings.Contains(expr, "(") {
		return SourceFunction, ""
	}
	return SourceUnknown, ""
}

// expressionRoots returns the first and second dotted identifiers of an expression,
// unquoting quoted identifiers such as "my-map".data.
func expressionRoots(expr string) (string, string) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return "", ""
	}
	if trimmed[0] == '{' {
		return "", ""
	}
	first, rest := readIdentifier(trimmed)
	if first == "" {
		return "", ""
	}
	rest = strings.TrimLeft(rest, " ")
	if strings.HasPrefix(rest, ".") {
		second, _ := readIdentifier(rest[1:])
		return first, second
	}
	return first, ""
}

func readIdentifier(s string) (string, string) {
	if s == "" {
		return "", ""
	}
	if s[0] == '"' {
		end := strings.Index(s[1:], "\"")
		if end < 0 {
			return "", ""
		}
		return s[1 : end+1], s[end+2:]
	}
	end := 0
	for end < len(s) {
		r := rune(s[end])
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			end++
			continue
		}
		break
	}
	return s[:end], s[end:]
}

// contextEntriesFromRaw converts the untyped "context" array found in a foreach scope
// back into typed context entries so it can be fed to the regular context loader.
func contextEntriesFromRaw(raw interface{}) ([]kyvernov1.ContextEntry, error) {
	if raw == nil {
		return nil, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var entries []kyvernov1.ContextEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}
