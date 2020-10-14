package eop

import (
	"strings"
)

func (parser *EOPParser) ParseAntiSpamReport() {
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
			switch key {
			case "CAT":
				value = parser.ExplainAntiSpamReportCategory(value)
			case "IPV":
				if value == "NLI" {
					value += " (no ip reputation data found)"
				} else if value == "CAL" {
					value += " (IP on allow list)"
				}
			case "SCL":
				value = parser.ExplainSCL(value)
			case "SFV":
				value = parser.ExplainSFV(value)
			}

			parser.table.Append([]string{key, value, antiSpamEplain[strings.ToLower(key)]})
		}
	}
}

func (parser *EOPParser) ExplainAntiSpamReportCategory(cat string) string {
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
		cat += " (" + cats[strings.ToLower(cat)] + ")"
	}
	return cat
}

func (parser *EOPParser) ExplainSCL(scl string) string {
	scl = strings.TrimSpace(scl)
	switch scl {
	case "-1":
		scl += " (message skipped spam filtering)"
	case "0":
		scl += " (message was not spam)"
	case "1":
		scl += " (message was not spam)"
	case "5":
		scl += " (marked as spam)"
	case "6":
		scl += " (marked as spam)"
	case "9":
		scl += " (marked as high confidence spam)"
	}
	return scl
}

func (parser *EOPParser) ExplainSFV(sfv string) string {
	sfv = strings.TrimSpace(sfv)
	switch strings.ToLower(strings.TrimSpace(sfv)) {
	case "blk":
		sfv += " (filtering skipped, sender is on user's Blocked Senders list)"
	case "nspm":
		sfv += " (filtering marked as non-spam. Mail was delivered)"
	case "sfe":
		sfv += " (filtering skipped, sender is on user's Safe Senders list)"
	case "ska":
		sfv += " (filtering skipped, sender is on allowed senders list or allowed domains list)"
	case "skb":
		sfv += " (filtering skipped, sender is on blocked senders list or blocked domains list)"
	case "ski":
		sfv += " (filtering skipped for unknown reason)"
	case "skn":
		sfv += " (marked as non-spam prior to being processed by spam filtering)"
	case "skq":
		sfv += " (message was released from the quarantine)"
	case "sks":
		sfv += " (message was marked as spam prior to being processed by spam filtering)"
	case "spm":
		sfv += " (message was marked as spam by spam filtering)"
	}
	return sfv
}
