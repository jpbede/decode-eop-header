package main

import (
	"bytes"
	"fmt"
	"github.com/jhillyerd/enmime"
	"github.com/jpbede/eop-header/eop"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"io/ioutil"
	"os"
)

var (
	version = "dev"
)

func main() {
	app := &cli.App{
		Name:    "eop-header",
		Usage:   "Decodes Microsoft's Exchange Online Protection header into a nice view",
		Version: version,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "file",
				Aliases:  []string{"f"},
				Required: true,
				Usage:    "Path to EML file",
			},
			&cli.IntFlag{
				Name:    "tableWidth",
				Aliases: []string{"t"},
				Value:   80,
				Usage:   "Width of the result table",
			},
		},
		Action: func(c *cli.Context) error {
			if c.Bool("version") {
				fmt.Print(version)
				return nil
			}

			rawMail, _ := ioutil.ReadFile(c.String("file"))

			br := bytes.NewReader(rawMail)
			env, _ := enmime.ReadEnvelope(br)

			parser := eop.NewParserWithEnvelop(env)
			parser.ParseAndRender(c.Int("tableWidth"))

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
