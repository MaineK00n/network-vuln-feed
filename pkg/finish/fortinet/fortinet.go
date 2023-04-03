package fortinet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
)

func Finish(advisoryPath string) (string, error) {
	f, err := os.Open(advisoryPath)
	if err != nil {
		return "", errors.Wrapf(err, "open %s", advisoryPath)
	}
	defer f.Close()

	var a Advisory
	if err := json.NewDecoder(f).Decode(&a); err != nil {
		return "", errors.Wrap(err, "decode json")
	}

	for i, v := range a.Vulnerabilities {
		for j, d := range v.Definitions {
			for k, c := range d.Configurations {
				if err := fillExpression(&c); err != nil {
					return "", errors.Wrap(err, "fill expression")
				}
				d.Configurations[k] = c
			}
			v.Definitions[j] = d
		}
		a.Vulnerabilities[i] = v
	}

	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(a); err != nil {
		return "", errors.Wrap(err, "encode json")
	}

	return buf.String(), nil
}

func fillExpression(c *Configurations) error {
	for i, n := range c.Nodes {
		p, expr, ok := strings.Cut(n.Description, ":")
		if !ok {
			return errors.Errorf("%q is unexpected format. expected format: %q", n.Description, "<Product>: (<expression> <version>)")
		}

		if strings.HasPrefix(n.CPE, "cpe:2.3:h") {
			if expr == " (<expression> <version>)" {
				return errors.New("not fill expression")
			}
		} else {
			var ops []string
			if n.Affected.Eqaul != nil && *n.Affected.Eqaul != "" {
				ops = append(ops, fmt.Sprintf("equal %s", *n.Affected.Eqaul))
			}
			if n.Affected.GreaterThan != nil && *n.Affected.GreaterThan != "" {
				ops = append(ops, fmt.Sprintf("greater than %s", *n.Affected.GreaterThan))
			}
			if n.Affected.GreaterEqaul != nil && *n.Affected.GreaterEqaul != "" {
				ops = append(ops, fmt.Sprintf("greater equal %s", *n.Affected.GreaterEqaul))
			}
			if n.Affected.LessThan != nil && *n.Affected.LessThan != "" {
				ops = append(ops, fmt.Sprintf("less than %s", *n.Affected.LessThan))
			}
			if n.Affected.LessEqual != nil && *n.Affected.LessEqual != "" {
				ops = append(ops, fmt.Sprintf("less equal %s", *n.Affected.LessEqual))
			}
			if len(n.FixedIn) > 0 {
				ops = append(ops, fmt.Sprintf("fixed in [%s]", strings.Join(n.FixedIn, ", ")))
			}
			n.Description = strings.TrimSpace(fmt.Sprintf("%s: %s", p, strings.Join(ops, ", ")))
		}

		c.Nodes[i] = n
	}

	if c.Children != nil {
		if err := fillExpression(c.Children); err != nil {
			return errors.Wrap(err, "recursive fill expression")
		}
	}

	return nil
}
