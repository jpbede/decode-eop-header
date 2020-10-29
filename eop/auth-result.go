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
  for ip, part := range parts{
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
}
