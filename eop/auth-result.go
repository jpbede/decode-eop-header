package eop

import (
	"strings"
)

func (parser *Parser) ParseAuthenticationResult() {
	header := parser.envelope.GetHeader("Authentication-Results")
	parts := strings.Split(header, "=")
	fields := make(map[string]string)

	stopwords := []string{"spf", "dkim", "dmarc", "action", "smtp.mailfrom",
		"header.d", "header.from", "compauth", "action", "reason"}

	// TODO: I don't like this

	// match parts
	for ip, part := range parts {
		for _, stopword := range stopwords {
			if strings.Contains(part, stopword) {
				fields[stopword] = parts[ip+1]
			}
		}
	}

	// now remove stop words from parts
	for key, value := range fields {
		for _, stopword := range stopwords {
			if strings.Contains(value, stopword) {
				fields[key] = strings.TrimSpace(strings.Split(value, stopword)[0])
			}
		}
	}

	for key, value := range fields {
		var valueExlpain string
		if key == "reason" {
			valueExlpain = parser.ExplainAuthResultReason(value)
		}

		parser.Fields = append(parser.Fields, &FilteringField{
			Header:           "Auth-Result",
			Key:              key,
			Value:            value,
			Explanation:      parser.ExplainAuthResultKey(key),
			ValueExplanation: valueExlpain,
		})
	}
}

func (parser *Parser) ExplainAuthResultKey(key string) string {
	switch strings.TrimSpace(key) {
	case "spf":
		return "Describes the results of the SPF check for the message"
	case "dmarc":
		return "Describes the results of the DMARC check for the message"
	case "header.from":
		return "The domain of the 5322.From address"
	case "header.d":
		return "Domain identified in the DKIM signature if any. This is the domain that's queried for the public key"
	case "action":
		return "Indicates the action taken by the spam filter based on the results of the DMARC check"
	case "compauth":
		return "Composite authentication result. Used by Microsoft 365 to combine multiple types of authentication"
	case "dkim":
		return "Describes the results of the DKIM check for the message"
	case "reason":
		return "The reason the composite authentication passed or failed"
	case "smtp.mailfrom":
		return "The domain of the 5321.MailFrom address"
	default:
		return ""
	}
}

func (parser *Parser) ExplainAuthResultReason(reason string) string {
	switch strings.TrimSpace(reason) {
	case "000":
		return "The message failed explicit authentication (compauth=fail)."
	case "001":
		return "The message failed implicit authentication"
	case "002":
		return "Organization has a policy for the sender/domain pair that is explicitly prohibited from sending spoofed email"
	case "010":
		return "The message failed DMARC with an action of reject or quarantine but it is a organization's accepted-domain"
	default:
		return ""
	}
}
