// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package main

import (
	"bytes"
	"fmt"
	"regexp"
	"text/template/parse"

	"github.com/pkg/errors"

	"github.com/elastic/package-registry/packages"
)

type streamConfigParsed struct {
	tree *parse.Tree
}

func parseStreamConfig(content []byte) (*streamConfigParsed, error) {
	mapOfParsed, err := parse.Parse("input-config", string(content), "", "", map[string]interface{}{
		"eq":     func() {},
		"printf": func() {},
		"tojson": func() {},
		"inList": func() {},
	})
	if err != nil {
		return nil, errors.Wrapf(err, "parsing template failed")
	}
	return &streamConfigParsed{
		tree: mapOfParsed["input-config"],
	}, nil
}

func (scp *streamConfigParsed) inputTypes() []string {
	return uniqueStringValues(inputTypesForNode(scp.tree.Root))
}

func inputTypesForNode(node parse.Node) []string {
	textNode, isTextNode := node.(*parse.TextNode)
	if isTextNode {
		inputType, ok := extractInputTypeFromTextNode(textNode)
		if ok {
			return []string{inputType}
		}
		return nil
	}

	listNode, isListNode := node.(*parse.ListNode)
	if isListNode {
		return inputTypesForListNode(listNode)
	}

	ifNode, isIfNode := node.(*parse.IfNode)
	if isIfNode {
		var inputTypes []string

		if ifNode.List != nil {
			inputTypes = append(inputTypes, inputTypesForListNode(ifNode.List)...)
		}
		if ifNode.ElseList != nil {
			inputTypes = append(inputTypes, inputTypesForListNode(ifNode.ElseList)...)
		}
		return inputTypes
	}
	return nil
}

func extractInputTypeFromTextNode(textNode *parse.TextNode) (string, bool) {
	i := bytes.Index(textNode.Text, []byte("type: "))
	if i > -1 && (i == 0 || textNode.Text[i-1] == '\n') {
		aType := textNode.Text[i+6:]
		j := bytes.IndexByte(aType, '\n')
		if j < 0 {
			j = len(aType)
		}
		aType = aType[:j]
		return string(aType), true
	}
	return "", false
}

func inputTypesForListNode(listNode *parse.ListNode) []string {
	var inputTypes []string
	for _, listedNode := range listNode.Nodes {
		it := inputTypesForNode(listedNode)
		inputTypes = append(inputTypes, it...)
	}
	return inputTypes
}

func (scp *streamConfigParsed) configForInput(inputType string) []byte {
	if inputType == "log" {
		inputType = "file"
	}

	config := configForInputForNode(scp.tree.Root, inputType)
	r := regexp.MustCompile("(\n)+")
	return bytes.TrimSpace(r.ReplaceAll(config, []byte{'\n'}))
}

func configForInputForNode(node parse.Node, inputType string) []byte {
	textNode, isTextNode := node.(*parse.TextNode)
	if isTextNode {
		return writeHandlebarsTextNode(textNode)
	}

	listNode, isListNode := node.(*parse.ListNode)
	if isListNode {
		return writeHandlebarsListNode(listNode, inputType)
	}

	ifNode, isIfNode := node.(*parse.IfNode)
	if isIfNode {
		return writeHandlebarsIfNode(ifNode, inputType)
	}

	rangeNode, isRangeNode := node.(*parse.RangeNode)
	if isRangeNode {
		return writeHandlebarsRangeNode(rangeNode, inputType)
	}

	actionNode, isActionNode := node.(*parse.ActionNode)
	if isActionNode {
		return writeHandlebarsActionNode(actionNode)
	}

	panic(fmt.Sprintf("unsupported node: %s", node.String()))
}

func writeHandlebarsTextNode(textNode *parse.TextNode) []byte {
	i := bytes.Index(textNode.Text, []byte("type: "))
	if i > -1 && (i == 0 || textNode.Text[i-1] == '\n') {
		var buffer bytes.Buffer
		buffer.Write(textNode.Text[0:i])

		j := bytes.Index(textNode.Text[i:], []byte{'\n'})
		if j > 0 {
			buffer.Write(textNode.Text[i+j+1:])
			return buffer.Bytes()
		}
	}
	return textNode.Text
}

func writeHandlebarsListNode(listNode *parse.ListNode, inputType string) []byte {
	var buffer bytes.Buffer
	for _, listedNode := range listNode.Nodes {
		buf := configForInputForNode(listedNode, inputType)
		buffer.Write(buf)
	}
	return buffer.Bytes()
}

func writeHandlebarsIfNode(ifNode *parse.IfNode, inputType string) []byte {
	var buffer bytes.Buffer
	if isIfNodeEqInput(ifNode) {
		if isIfNodeEqInputInputType(ifNode, inputType) {
			if ifNode.List != nil {
				buffer.Write(configForInputForNode(ifNode.List, inputType))
			}
		} else {
			if ifNode.ElseList != nil {
				buffer.Write(configForInputForNode(ifNode.ElseList, inputType))
			}
		}
	} else {
		if len(ifNode.Pipe.Cmds[0].Args) == 1 {
			var1 := ifNode.Pipe.Cmds[0].Args[0].String()[1:]
			buffer.WriteString(fmt.Sprintf("{{#if %s}}", var1))
		} else {
			buffer.WriteString(fmt.Sprintf("{{#if %s}}", ifNode.Pipe.String()))
		}

		if ifNode.List != nil {
			buffer.Write(configForInputForNode(ifNode.List, inputType))
		}
		if ifNode.ElseList != nil {
			buffer.WriteString("{{else}}")
			buffer.Write(configForInputForNode(ifNode.ElseList, inputType))
		}
		buffer.WriteString("{{/if}}")
	}
	return buffer.Bytes()
}

func isIfNodeEqInput(ifNode *parse.IfNode) bool {
	if len(ifNode.Pipe.Cmds[0].Args) > 1 {
		op := ifNode.Pipe.Cmds[0].Args[0].String()
		var1 := ifNode.Pipe.Cmds[0].Args[1].String()

		if op == "eq" && var1 == ".input" {
			return true
		}
	}
	return false
}

func isIfNodeEqInputInputType(ifNode *parse.IfNode, inputType string) bool {
	if len(ifNode.Pipe.Cmds[0].Args) > 1 {
		op := ifNode.Pipe.Cmds[0].Args[0].String()
		var1 := ifNode.Pipe.Cmds[0].Args[1].String()
		var2 := ifNode.Pipe.Cmds[0].Args[2].String()

		if op == "eq" && var1 == ".input" && var2 == fmt.Sprintf(`"%s"`, inputType) {
			return true
		}
	}
	return false
}

func writeHandlebarsActionNode(actionNode *parse.ActionNode) []byte {
	var buffer bytes.Buffer
	if len(actionNode.Pipe.Cmds) > 0 {
		cmdArgs := writeHandlebarsCmdArgs(actionNode.Pipe.Cmds[0].Args)
		buffer.WriteString("{{")
		buffer.Write(cmdArgs)
		buffer.WriteString("}}")
	}
	return buffer.Bytes()
}

func writeHandlebarsRangeNode(rangeNode *parse.RangeNode, inputType string) []byte {
	var buffer bytes.Buffer

	cmdArgs := writeHandlebarsCmdArgs(rangeNode.Pipe.Cmds[0].Args)
	decl := writeHandlebarsCmdDecl(rangeNode.Pipe.Decl)
	buffer.WriteString("{{#each ")
	buffer.Write(cmdArgs)
	buffer.Write(decl)
	buffer.WriteString("}}")
	buffer.Write(writeHandlebarsListNode(rangeNode.List, inputType))
	buffer.WriteString("{{/each}}")
	return buffer.Bytes()
}

func writeHandlebarsCmdArgs(args []parse.Node) []byte {
	var buffer bytes.Buffer
	for i, arg := range args {
		argWithoutDot := arg.String()[1:]
		if len(argWithoutDot) == 0 {
			argWithoutDot = "this"
		}
		buffer.WriteString(argWithoutDot)
		if i != (len(args) - 1) {
			buffer.WriteString(" ")
		}
	}
	return buffer.Bytes()
}

func writeHandlebarsCmdDecl(decl []*parse.VariableNode) []byte {
	var buffer bytes.Buffer

	if len(decl) > 0 {
		buffer.WriteString(" as |")
	}

	for i := len(decl) - 1; i >= 0; i-- {
		aVar := decl[i].String()[1:]
		buffer.WriteString(aVar)

		if i != 0 {
			buffer.WriteByte(' ')
		}
	}

	if len(decl) > 0 {
		buffer.WriteString("|")
	}
	return buffer.Bytes()
}

func (scp *streamConfigParsed) filterVarsForInput(inputType string, vars []packages.Variable) []packages.Variable {
	variableNamesForInput := scp.variableNamesForInput(inputType)
	var filtered []packages.Variable
	for _, aVar := range vars {
		var found bool
		for _, variableName := range variableNamesForInput {
			if aVar.Name == variableName {
				found = true
				break
			}
		}

		if found {
			filtered = append(filtered, aVar)
		}
	}
	return filtered
}

func (scp *streamConfigParsed) variableNamesForInput(inputType string) []string {
	if inputType == "log" {
		inputType = "file"
	}

	var variables []string

	variables = variableNamesForInputForNode(scp.tree.Root, inputType, variables)
	return uniqueStringValues(variables)
}

func variableNamesForInputForNode(node parse.Node, inputType string, variables []string) []string {
	_, isTextNode := node.(*parse.TextNode)
	if isTextNode {
		return variables // do nothing, there are no variables
	}

	listNode, isListNode := node.(*parse.ListNode)
	if isListNode {
		return variableNamesListNode(listNode, inputType, variables)
	}

	ifNode, isIfNode := node.(*parse.IfNode)
	if isIfNode {
		return variableNamesIfNode(ifNode, inputType, variables)
	}

	rangeNode, isRangeNode := node.(*parse.RangeNode)
	if isRangeNode {
		return variableNamesRangeNode(rangeNode, inputType, variables)
	}

	actionNode, isActionNode := node.(*parse.ActionNode)
	if isActionNode {
		return variableNamesForNodeArgs(actionNode.Pipe.Cmds[0].Args, variables)
	}

	panic(fmt.Sprintf("unsupported node: %s", node.String()))
}

func variableNamesListNode(listNode *parse.ListNode, inputType string, vars []string) []string {
	var variables []string
	variables = append(variables, vars...)

	for _, listedNode := range listNode.Nodes {
		variables = uniqueStringValues(append(variables, variableNamesForInputForNode(listedNode, inputType, variables)...))
	}
	return variables
}

func variableNamesIfNode(ifNode *parse.IfNode, inputType string, vars []string) []string {
	var variables []string
	variables = append(variables, vars...)

	if isIfNodeEqInput(ifNode) {
		if isIfNodeEqInputInputType(ifNode, inputType) {
			if ifNode.List != nil {
				variables = uniqueStringValues(append(variableNamesForInputForNode(ifNode.List, inputType, variables)))
			}
		} else {
			if ifNode.ElseList != nil {
				variables = uniqueStringValues(append(variableNamesForInputForNode(ifNode.ElseList, inputType, variables)))
			}
		}
	} else {
		if ifNode.List != nil {
			variables = uniqueStringValues(append(variableNamesForInputForNode(ifNode.List, inputType, variables)))
		}
		if ifNode.ElseList != nil {
			variables = uniqueStringValues(append(variableNamesForInputForNode(ifNode.ElseList, inputType, variables)))
		}

		variables = uniqueStringValues(append(variables, variableNamesForNodeArgs(ifNode.Pipe.Cmds[0].Args, variables)...))
	}
	return variables
}

func variableNamesRangeNode(rangeNode *parse.RangeNode, inputType string, vars []string) []string {
	var variables []string
	variables = append(variables, vars...)

	variables = uniqueStringValues(append(variables, variableNamesListNode(rangeNode.List, inputType, variables)...))
	variables = uniqueStringValues(append(variables, variableNamesForNodeArgs(rangeNode.Pipe.Cmds[0].Args, variables)...))
	return variables
}

func variableNamesForNodeArgs(args []parse.Node, vars []string) []string {
	var variables []string
	variables = append(variables, vars...)

	if len(args) > 0 {
		for _, arg := range args {
			variables = append(variables, arg.String()[1:])
		}
	}
	return variables
}
