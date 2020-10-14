package eop

import (
	"strings"
)

func (parser *Parser) ParseMicrosoftAntiSpam() {
	fieldsMeanings := map[string]string{
		"bcl": "Bulk Confidence Level. A higher BCL indicates a bulk mail message is more likely to generate complaints",
	}

	header := parser.envelope.GetHeader("X-Microsoft-Antispam")
	fieldString := strings.Split(header, ";")
	fields := make(map[string]string, len(fieldString))
	for _, e := range fieldString {
		parts := strings.Split(e, ":")
		if len(parts) > 1 {
			fields[parts[0]] = parts[1]
		}
	}

	for key, value := range fields {
		if fieldsMeanings[strings.ToLower(key)] != "" {
			parser.Fields = append(parser.Fields, &FilteringField{
				Key:         key,
				Value:       value,
				Explanation: fieldsMeanings[strings.ToLower(key)],
			})
		}
	}
}
