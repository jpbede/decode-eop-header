package eop

import (
	"github.com/jhillyerd/enmime"
	"github.com/olekukonko/tablewriter"
	"os"
)

type EOPParser struct {
	envelope *enmime.Envelope
	table    *tablewriter.Table
}

func NewParserWithEnvelop(env *enmime.Envelope) *EOPParser {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Field", "Value", "Meaning"})
	table.SetRowSeparator("-")
	table.SetRowLine(true)

	return &EOPParser{
		envelope: env,
		table:    table,
	}
}

func (parser *EOPParser) ParseAndRender() {
	parser.ParseAntiSpamReport()
	parser.ParseMicrosoftAntiSpam()
	parser.ParseAuthenticationResult()
	parser.Render()
}

func (parser *EOPParser) Render() {
	parser.table.Render()
}
