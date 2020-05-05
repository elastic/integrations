// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"encoding/xml"
	"image"
	"io"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type svgFile struct {
	Width  string `xml:"width,attr"`
	Height string `xml:"height,attr"`

	ViewBox string `xml:"viewBox,attr"`
}

func SvgDecodeConfig(r io.Reader) (image.Config, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return image.Config{}, errors.Wrapf(err, "reading SVG file failed")
	}

	var svgFile svgFile
	err = xml.Unmarshal(data, &svgFile)
	if err != nil {
		return image.Config{}, errors.Wrapf(err, "unmarshalling SVG file failed")
	}

	var width, height float64
	if svgFile.Width != "" && svgFile.Height != "" {
		width, err = svgParseToPixels(svgFile.Width)
		if err != nil {
			return image.Config{}, errors.Wrapf(err, "parsing width failed (value: %s)", svgFile.Width)
		}

		height, err = svgParseToPixels(svgFile.Height)
		if err != nil {
			return image.Config{}, errors.Wrapf(err, "parsing width failed (value: %s)", svgFile.Width)
		}
	}

	if width > 0 && height > 0 {
		return image.Config{
			Width:  int(width),
			Height: int(height),
		}, nil
	}

	dims := strings.Split(svgFile.ViewBox, " ")
	var dimX, dimY string
	if len(dims) == 2 {
		dimX = dims[0]
		dimY = dims[1]
	} else if len(dims) == 4 {
		dimX = dims[2]
		dimY = dims[3]
	}
	width, err = strconv.ParseFloat(dimX, 32)
	if err != nil {
		return image.Config{}, errors.Wrapf(err, "parsing viewBox failed (value: %s)", svgFile.ViewBox)
	}

	height, err = strconv.ParseFloat(dimY, 32)
	if err != nil {
		return image.Config{}, errors.Wrapf(err, "parsing viewBox failed (value: %s)", svgFile.ViewBox)
	}

	return image.Config{
		Width:  int(width),
		Height: int(height),
	}, nil
}

func svgParseToPixels(value string) (float64, error) {
	v, err := strconv.ParseFloat(value, 32)
	if err != nil {
		var unit string
		var scale float64
		if strings.Contains(value, "pt") {
			unit = "pt"
			scale = 4.0 / 3
		} else if strings.Contains(value, "mm") {
			unit = "mm"
			scale = 3.77
		}

		value = strings.ReplaceAll(value, unit, "")
		v, err = strconv.ParseFloat(value, 32)
		if err != nil {
			return -1, errors.Wrapf(err, "parsing width failed (value: %s)", value)
		}
		v = v * scale
	}
	return v, nil
}
