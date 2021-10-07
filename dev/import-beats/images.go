// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/pkg/errors"

	"github.com/elastic/package-registry/packages"
)

var (
	imageRe            = regexp.MustCompile(`image::[^\[]+`)
	imageTitleReplacer = strings.NewReplacer("_", " ", "-", " ", "/", "")
)

type imageContent struct {
	source string
}

type imageContentArray []imageContent

func createImages(beatDocsPath, modulePath string) (imageContentArray, error) {
	var images []imageContent

	moduleDocsPath := path.Join(modulePath, "_meta", "docs.asciidoc")
	moduleDocsFile, err := ioutil.ReadFile(moduleDocsPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "reading module docs file failed (path: %s)", moduleDocsPath)
	} else if os.IsNotExist(err) {
		log.Printf("\tNo docs found (path: %s), skipped", moduleDocsPath)
	} else {
		log.Printf("\tDocs found (path: %s)", moduleDocsPath)
		images = append(images, extractImages(beatDocsPath, moduleDocsFile)...)
	}

	dataStreamDirs, err := ioutil.ReadDir(modulePath)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot read module directory %s", modulePath)
	}

	for _, dataStreamDir := range dataStreamDirs {
		if !dataStreamDir.IsDir() {
			continue
		}
		dataStreamName := dataStreamDir.Name()

		if dataStreamName == "_meta" {
			continue
		}

		log.Printf("\t%s: data stream found", dataStreamName)

		dataStreamDocsPath := path.Join(modulePath, dataStreamName, "_meta", "docs.asciidoc")
		dataStreamDocsFile, err := ioutil.ReadFile(dataStreamDocsPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, errors.Wrapf(err, "reading data stream docs file failed (path: %s)", dataStreamDocsPath)
		} else if os.IsNotExist(err) {
			log.Printf("\t%s: no docs found (path: %s), skipped", dataStreamName, dataStreamDocsPath)
			continue
		}

		log.Printf("\t%s: docs found (path: %s)", dataStreamName, dataStreamDocsPath)
		images = append(images, extractImages(beatDocsPath, dataStreamDocsFile)...)
	}

	return images, nil
}

func extractImages(beatDocsPath string, docsFile []byte) []imageContent {
	matches := imageRe.FindAll(docsFile, -1)

	var contents []imageContent
	for _, match := range matches {
		contents = append(contents, imageContent{
			source: path.Join(beatDocsPath, string(match[7:])), // skip: image::
		})
	}
	return contents
}

func (images imageContentArray) toManifestImages() ([]packages.Image, error) {
	var imgs []packages.Image
	for _, image := range images {
		i := strings.LastIndex(image.source, "/")
		sourceFileName := image.source[i:]

		imageSize, err := readImageSize(image.source)
		if err != nil {
			return nil, errors.Wrapf(err, "reading image size failed")
		}

		imageType, err := extractImageType(image.source)
		if err != nil {
			return nil, errors.Wrapf(err, "extracting image type failed")
		}

		imgs = append(imgs, packages.Image{
			Src:   path.Join("/img", sourceFileName),
			Title: toImageTitle(sourceFileName),
			Size:  imageSize,
			Type:  imageType,
		})
	}
	return imgs, nil
}

func toImageTitle(fileName string) string {
	i := strings.LastIndex(fileName, ".")
	return imageTitleReplacer.Replace(fileName[:i])
}

func readImageSize(imagePath string) (string, error) {
	f, err := os.Open(imagePath)
	if err != nil {
		return "", errors.Wrapf(err, "opening image failed (path: %s)", imagePath)
	}
	defer f.Close()

	var img image.Config
	if strings.HasSuffix(imagePath, ".svg") {
		img, err = SvgDecodeConfig(f)
	} else {
		img, _, err = image.DecodeConfig(f)
	}
	if err != nil {
		return "", errors.Wrapf(err, "opening image failed (path: %s)", imagePath)
	}
	return fmt.Sprintf("%dx%d", img.Width, img.Height), nil
}

func extractImageType(imagePath string) (string, error) {
	if strings.HasSuffix(imagePath, ".png") {
		return "image/png", nil
	} else if strings.HasSuffix(imagePath, ".jpg") {
		return "image/jpg", nil
	} else if strings.HasSuffix(imagePath, ".svg") {
		return "image/svg+xml", nil
	}
	return "", fmt.Errorf("unknown image type (path: %s)", imagePath)
}
