package eop

import (
	"github.com/jhillyerd/enmime"
	"github.com/olekukonko/tablewriter"
	"os"
)

type Parser struct {
	envelope *enmime.Envelope
	table    *tablewriter.Table

	Fields []*FilteringField
}

func NewParserWithEnvelop(env *enmime.Envelope) *Parser {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Field", "Value", "Meaning"})
	table.SetRowSeparator("-")
	table.SetRowLine(true)

	return &Parser{
		envelope: env,
		table:    table,
	}
}

func (parser *Parser) ParseAndRender() {
	parser.ParseAntiSpamReport()
	parser.ParseMicrosoftAntiSpam()
	parser.ParseAuthenticationResult()
	parser.Render()
}

func (parser *Parser) Render() {
	for _, field := range parser.Fields {
		parser.table.Append(field.TableRow())
	}
	parser.table.Render()
}
