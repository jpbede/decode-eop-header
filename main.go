package main

import (
	"bytes"
	"github.com/jhillyerd/enmime"
	"github.com/jpbede/decode-eop-header/eop"
	"io/ioutil"
)

func main() {
	rawMail, _ := ioutil.ReadFile("./unnamed_attachment_1 (13).eml")

	br := bytes.NewReader(rawMail)
	env, _ := enmime.ReadEnvelope(br)

	parser := eop.NewParserWithEnvelop(env)
	parser.ParseAndRender()
}
