package eop

type FilteringField struct {
	Key              string
	Value            string
	ValueExplanation string
	Explanation      string
}

func (field *FilteringField) TableRow() []string {
	val := field.Value
	if field.ValueExplanation != "" {
		val += " (" + field.ValueExplanation + ")"
	}
	return []string{field.Key, val, field.Explanation}
}
