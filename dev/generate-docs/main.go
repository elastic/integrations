package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type generateOptions struct {
	packages string
	packagesSourceDir string
}

func (o *generateOptions) validate() error {
	_, err := os.Stat(o.packagesSourceDir)
	if err != nil {
		return errors.Wrapf(err, "stat file failed (path: %s)", o.packagesSourceDir)
	}
	return nil
}

func (o *generateOptions) selectedPackages() []string {
	var selected []string
	p := strings.TrimSpace(o.packages)
	if len(p) > 0 {
		selected = strings.Split(p, ",")
	}
	return selected
}

func main() {
	var options generateOptions
	flag.StringVar(&options.packages, "packages", "", "Packages selected for generating docs")
	flag.StringVar(&options.packagesSourceDir, "sourceDir", "./packages", "Path to the packages directory")
	flag.Parse()

	err := options.validate()
	if err != nil {
		log.Fatal(errors.Wrap(err, "command options validation failed"))
	}

	err = generateDocs(options)
	if err != nil {
		log.Fatal(errors.Wrap(err, "generating docs failed"))
	}
}

func generateDocs(options generateOptions) error {
	packages, err := listPackages(options)
	if err != nil {
		return errors.Wrap(err, "listing packages failed")
	}

	for _, packageName := range packages {
		err = renderReadme(options, packageName)
		if err != nil {
			return errors.Wrapf(err, "rendering README file failed (packageName: %s)", packageName)
		}
	}
	return nil
}