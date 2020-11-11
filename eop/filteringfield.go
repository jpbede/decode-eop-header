package eop

type FilteringField struct {
	Header           string
	Key              string
	Value            string
	ValueExplanation string
	Explanation      string
}

func (field *FilteringField) TableRow() []string {
	if field.ValueExplanation != "" {
		return []string{field.Header, field.Key, field.Explanation, field.Value, field.ValueExplanation}
	}
	return []string{field.Header, field.Key, field.Explanation, field.Value, ""}
}
