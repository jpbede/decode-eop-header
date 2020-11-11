package eop

import (
	"strings"
)

func (parser *Parser) ParseAntiSpamReport() {
	antiSpamEplain := map[string]string{
		"ctry": "Source country as determined by the connecting IP address",
		"cat":  "Category of protection policy",
		"cip":  "Connecting IP",
		"h":    "HELO/EHLO string",
		"ipv":  "IP reputation status",
		"lang": "Language of message",
		"ptr":  "PTR of connecting IP",
		"scl":  "Spam confidence level. A higher value indicates the message is more likely to be spam.",
		"sfty": "Message was identified as phishing. Field contains more information about reason",
		"sfv":  "Filtering result",
		"pcl":  "Phishing Confidence Level",
		//"sfs": "Rules that where matched while filtering",
	}

	header := parser.envelope.GetHeader("X-Forefront-Antispam-Report")
	fieldString := strings.Split(header, ";")
	fields := make(map[string]string, len(fieldString))
	for _, e := range fieldString {
		parts := strings.Split(e, ":")
		if len(parts) > 1 {
			fields[parts[0]] = parts[1]
		}
	}

	for key, value := range fields {
		if antiSpamEplain[strings.ToLower(key)] != "" {
			var valueExplain string
			switch key {
			case "CAT":
				valueExplain = parser.ExplainAntiSpamReportCategory(value)
			case "IPV":
				if value == "NLI" {
					valueExplain = "no ip reputation data found"
				} else if value == "CAL" {
					valueExplain = "IP on allow list"
				}
			case "SCL":
				valueExplain = parser.ExplainSCL(value)
			case "SFV":
				valueExplain = parser.ExplainSFV(value)
			}
			parser.Fields = append(parser.Fields, &FilteringField{
				Header:           "Antispam-Report",
				Key:              key,
				Value:            value,
				Explanation:      antiSpamEplain[strings.ToLower(key)],
				ValueExplanation: valueExplain,
			})
		}
	}
}

func (parser *Parser) ExplainAntiSpamReportCategory(cat string) string {
	cats := map[string]string{
		"bulk":   "Mail classified as bulk",
		"dimp":   "",
		"gimp":   "",
		"hphsh":  "High confidence phishing",
		"hphish": "High confidence phishing",
		"hspm":   "High confidence of spam",
		"malw":   "Malware detected",
		"phsh":   "Pishing link detected",
		"spm":    "Mail classified as spam",
		"spoof":  "Mail classified as spoofing",
		"uimp":   "",
		"amp":    "",
		"sap":    "",
		"ospm":   "Outbound spam detected",
	}

	if cats[strings.ToLower(cat)] != "" {
		return cats[strings.ToLower(cat)]
	}
	return ""
}

func (parser *Parser) ExplainSCL(scl string) string {
	switch strings.TrimSpace(scl) {
	case "-1":
		return "message skipped spam filtering"
	case "0", "1":
		return "message was not spam"
	case "5", "6":
		return "marked as spam"
	case "9":
		return "marked as high confidence spam"
	default:
		return ""
	}
}

func (parser *Parser) ExplainSFV(sfv string) string {
	switch strings.ToLower(strings.TrimSpace(sfv)) {
	case "blk":
		return "filtering skipped, sender is on user's Blocked Senders list"
	case "nspm":
		return "filtering marked as non-spam. Mail was delivered"
	case "sfe":
		return "filtering skipped, sender is on user's Safe Senders list"
	case "ska":
		return "filtering skipped, sender is on allowed senders list or allowed domains list"
	case "skb":
		return "filtering skipped, sender is on blocked senders list or blocked domains list"
	case "ski":
		return "filtering skipped for unknown reason"
	case "skn":
		return "marked as non-spam prior to being processed by spam filtering"
	case "skq":
		return "message was released from the quarantine"
	case "sks":
		return "message was marked as spam prior to being processed by spam filtering"
	case "spm":
		return "message was marked as spam by spam filtering"
	default:
		return ""
	}
}
