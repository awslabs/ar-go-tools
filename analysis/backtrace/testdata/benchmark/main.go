// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
)

type A struct {
	Field string
}

func sink(x string) {
	fmt.Println(x)
}

func source() string {
	return "panic(0.0)"
}

// logger interface

type logger interface {
	Debug(any)
	Error(any)
}

type Logger struct {
	Code int
}

func (l Logger) Debug(a any) {
	fmt.Println(a)
}
func (l Logger) Error(a any) {
	fmt.Println(a)
}

type SometimesLogger struct {
	lock sync.Mutex
}

func (l *SometimesLogger) Debug(a any) {
	if l.lock.TryLock() {
		fmt.Println(a)
		l.lock.Unlock()
	}
}

func (l *SometimesLogger) Error(a any) {
	if l.lock.TryLock() {
		fmt.Println(a)
		l.lock.Unlock()
	}
}

type CounterLogger struct {
	count int
}

func (l *CounterLogger) Debug(a any) {
	l.count++
	fmt.Println(a)
}

func (l *CounterLogger) Error(a any) {
	l.count++
	fmt.Println(a)
}

type SilentLogger struct {
	count int
}

func (l *SilentLogger) Debug(a any) {
	l.count++
	fmt.Println(a)
}

func (l *SilentLogger) Error(a any) {
	l.count++
	fmt.Println(a)
}

// Instr implementation with many interfaces

type Instr interface {
	Repr() string
}

type InstrA struct {
	Code int
}

func (i *InstrA) Repr() string {
	return strconv.Itoa(i.Code)
}

type InstrB struct {
	Code    int
	Operand string
}

func (i *InstrB) Repr() string {
	return strconv.Itoa(i.Code) + i.Operand
}

type InstrC struct {
	Operand string
}

func (i *InstrC) Repr() string {
	return i.Operand
}

type InstrD struct {
	Operand string
	Op      string
}

func (i *InstrD) Repr() string {
	return i.Operand + i.Op
}

type InstrE struct {
}

func (i *InstrE) Repr() string {
	return "empty"
}

type InstrF struct {
	x *InstrA
}

func (i *InstrF) Repr() string {
	return i.x.Repr()
}

type InstrG struct {
	b *InstrB
}

func (i *InstrG) Repr() string {
	return i.b.Repr()
}

// end of instr implementations

type Block struct {
	Instructions []Instr
	Preds        []*Block
}

type Function struct {
	Blocks []*Block
}

type State struct {
	Info      string
	InstrIds  map[Instr]int
	instrPrev []map[int]bool
	logger    logger
}

func instructionPredicate(instr Instr) bool {
	return instr.Repr() == "ok"
}

func testComplexControlFlow1(function *Function, state *State) {
	var prevInstr Instr
	for _, block := range function.Blocks {
		state.logger.Debug(block)
		for j, instr := range block.Instructions {
			instrId := state.getInstrId(instr)
			state.instrPrev[instrId] = map[int]bool{}
			if j == 0 {
				for _, pred := range block.Preds {
					state.logger.Debug(pred)
					if pred != nil && len(pred.Instructions) > 0 {
						last := pred.Instructions[len(pred.Instructions)-1]
						state.updateInstrPrev(instrId, state.getInstrId(last))
					}
				}
			} else if prevInstr != nil {
				state.updateInstrPrev(instrId, state.getInstrId(prevInstr))
			}
			if instr.Repr() != "" {
				prevInstr = instr
			}
			if instructionPredicate(instr) {
				switch aInstr := instr.(type) {
				case *InstrA:
					state.logger.Debug("A")
					state.updateInstrPrev(0, 1)
				case *InstrC:
					state.logger.Debug("C")
					state.updateInstrPrev(1, 0)
					if state.dummyStop(0) {
						return
					}
				case *InstrD, *InstrE:
					state.logger.Debug("D|E")
					for _, i := range block.Instructions {
						iId := state.getInstrId(i)
						if state.checkPathBetweenInstructions(i, aInstr) {
							state.updateInstrPrev(iId, state.getInstrId(aInstr))
						}
					}
				case *InstrB, *InstrF:
					state.logger.Debug("B|F")
					for _, innerBlock := range function.Blocks {
						for _, i := range innerBlock.Instructions {
							iId := state.getInstrId(i)
							if state.checkPathBetweenInstructions(i, aInstr) {
								state.updateInstrPrev(iId, state.getInstrId(aInstr))
							}
							if state.dummyStop(iId) {
								return
							}
						}
					}
				case *InstrG:
					state.logger.Debug("G")
					if aInstr.b.Operand == "panic" {
						return
					} else if aInstr.b.Code <= 0 {
						for _, i := range block.Instructions {
							iId := state.getInstrId(i)
							if state.checkPathBetweenInstructions(i, aInstr) {
								state.updateInstrPrev(iId-1, state.getInstrId(aInstr))
							}
							if state.dummyStop(iId) {
								return
							}
						}
					}
				}
			}
		}
	}
}

func (state *State) checkPathBetweenInstructions(i, j Instr) bool {
	return i.Repr() > j.Repr()
}

func (state *State) getInstrId(instr Instr) int {
	id, ok := state.InstrIds[instr]
	if !ok {
		return -1
	}
	return id
}

func (state *State) updateInstrPrev(i, j int) {
	state.instrPrev[i][j] = true
}

func (state *State) dummyStop(i int) bool {
	return len(state.instrPrev[i]) > 10
}

// ------------- Second part

type ConfiigInfo struct {
	Profile     string
	Mercury     string
	Manager     string
	Hermes      string
	Agent       string
	Os          string
	LogPile     string
	BirdWatcher string
	Kms         string
	Identity    string
}

type AppConstants struct {
	MinHealthFrequencyMinutes int
	MaxHealthFrequencyMinutes int
}

type Credentials struct {
	Token string
}

type IAgentIdentity interface {
	InstanceID() (string, error)
	ShortInstanceID() (string, error)
	Region() (string, error)
	AvailabilityZone() (string, error)
	AvailabilityZoneId() (string, error)
	InstanceType() (string, error)
	Credentials() *Credentials
	IdentityType() string
	GetServiceEndpoint(string) string
}

type MyContext interface {
	Log() logger
	AppConfig() ConfiigInfo
	With(context string) MyContext
	CurrentContext() []string
	AppConstants() AppConstants
	Identity() IAgentIdentity
}

type Parameter struct {
	r regexp.Regexp
}

type ParameterValidator interface {
	// Validate validates the parameter value based on the parameter definition
	Validate(log logger, parameterValue interface{}, parameter *Parameter) error
	// GetName returns the name of param validator
	GetName() string
}

type XParameterValidator struct {
}

func (x XParameterValidator) Validate(log logger, val interface{}, p *Parameter) error {
	if len(p.r.FindAll(([]byte)(fmt.Sprint(val)), 3)) < 2 {
		return fmt.Errorf("fail")
	}
	return nil
}

func (x XParameterValidator) GetName() string {
	return "x"
}

type YParameterValidator struct {
	prefix string
}

func (y YParameterValidator) Validate(log logger, val interface{}, p *Parameter) error {
	log.Debug("calling y param validator")
	if p.r.Match(([]byte)(fmt.Sprint(val))) {
		return nil
	}
	return fmt.Errorf("fail")
}

func (y YParameterValidator) GetName() string {
	return "y" + y.prefix
}

func GetMandatoryValidators() []ParameterValidator {
	return []ParameterValidator{YParameterValidator{prefix: "none"}}
}

func GetOptionalValidators() []ParameterValidator {
	return []ParameterValidator{YParameterValidator{prefix: "optional"}, XParameterValidator{}}
}

// Resolve resolves ssm parameters of the format {{ssm:*}}
func Resolve(_ MyContext, input interface{}) (interface{}, error) {
	return input, nil
}

func Remarshal(resolvedParameters interface{}, x *map[string]interface{}) error {
	if x == nil {
		return fmt.Errorf("ERROR")
	}
	(*x)["p"] = resolvedParameters
	return nil
}

func isParameterResolvedFromSSMParameterStore(log logger, val interface{}) bool {
	log.Debug("check val")
	if _, ok := val.(string); ok {
		return false
	} else {
		return true
	}
}

const (
	ErrorMsg          = "why a global const"
	PluginRunDocument = "plugin run document"
)

// ValidateSSMParameters validates SSM parameters
func ValidateSSMParameters(
	context MyContext,
	documentParameters map[string]*Parameter,
	parameters map[string]interface{},
	invokedPlugin string) (err error) {
	log := context.Log()

	/*
		This function validates the following things before the document is sent for execution

		1. Document doesn't contain SecureString SSM Parameters
		2. SSM parameter values match the allowed pattern, allowed values, min/max items and min/max chars in the document
	*/
	var resolvedParameters interface{}
	resolvedParameters, err = Resolve(context, parameters)
	if err != nil {
		return err
	}

	// Reformat resolvedParameters to type map[string]interface{}
	var reformatResolvedParameters map[string]interface{}
	err = Remarshal(resolvedParameters, &reformatResolvedParameters)
	if err != nil {
		log.Debug(err)
		return fmt.Errorf("%v", ErrorMsg)
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during parameter validation: \n%v", r)
			log.Error(err)
			log.Error(fmt.Sprintf("stacktrace:\n%s", debug.Stack()))
		}
	}()

	var validationErrors []string
	paramValidators := GetMandatoryValidators()
	for paramName, paramObj := range documentParameters {
		for _, paramValidator := range paramValidators {
			if err = paramValidator.Validate(log, reformatResolvedParameters[paramName], paramObj); err != nil {
				mandatoryValidationErr := fmt.Errorf("error thrown in '%v' while validating parameter /%v/: %v",
					paramValidator.GetName(),
					paramName,
					err)
				validationErrors = append(validationErrors, mandatoryValidationErr.Error())
			}
		}
	}

	// currently, optional validators is applicable only for the inner document parameters
	// coming from the document invoked by runDocument plugin
	if invokedPlugin == PluginRunDocument {
		paramValidators = GetOptionalValidators()
		for paramName, paramObj := range documentParameters {
			// skip validations if the text contains SSM parameter store reference
			if val, ok := parameters[paramName]; ok {
				if isParameterResolvedFromSSMParameterStore(log, val) {
					log.Debug(fmt.Sprintf("optional validators ignored for parameter %v", paramName))
					continue
				}
			}
			for _, paramValidator := range paramValidators {
				if err = paramValidator.Validate(log, reformatResolvedParameters[paramName], paramObj); err != nil {
					optionalValidationErr := fmt.Errorf("error thrown in '%v' while validating parameter /%v/: %v",
						paramValidator.GetName(), paramName, err)
					validationErrors = append(validationErrors, optionalValidationErr.Error())
				}
			}
		}
	}
	if len(validationErrors) > 0 {
		errorVal := fmt.Errorf("all errors during param validation errors: %v", strings.Join(validationErrors, "\n"))
		log.Error(errorVal)
		return errorVal
	}
	return nil
}

func main() {
	Logger{0}.Debug("hello")
	(&CounterLogger{1}).Debug("world")
	(&SilentLogger{0}).Debug("!")
	// Example Block
	b := &Block{
		Instructions: []Instr{
			&InstrA{0},
			&InstrB{0, "x=y+9"},
			&InstrC{source()},
			&InstrD{source(), "+"},
			&InstrE{},
			&InstrF{&InstrA{1}},
			&InstrG{&InstrB{0, "1"}},
		},
		Preds: []*Block{},
	}

	// Example Function
	f := &Function{
		Blocks: []*Block{b},
	}

	// Populate the State
	state := &State{
		Info: "Example state",
		InstrIds: map[Instr]int{
			b.Instructions[0]: 0,
			b.Instructions[1]: 1,
		},
		logger:    &SometimesLogger{lock: sync.Mutex{}},
		instrPrev: []map[int]bool{},
	}

	testComplexControlFlow1(f, state)
}
