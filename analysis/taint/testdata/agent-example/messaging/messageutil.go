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

package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path"
	"path/filepath"
	"strings"

	. "github.com/awslabs/ar-go-tools/analysis/taint/testdata/agent-example/datastructs"
)

type Content struct {
	content string
}

// Search stub
func (c Content) Search() string {
	return c.content
}

// Set stub
func (c Content) Set(s string, v string) (string, error) {
	c.content += s + v
	if len(c.content) > 10 {
		return c.content, nil
	} else {
		return "", fmt.Errorf("dummy")
	}
}

// InitializeDocState is a method to obtain the state of the document.
// This method calls into ParseDocument to obtain the InstancePluginInformation
func InitializeDocState(
	_ context.Context,
	documentType string,
	docContent *DocumentContent,
	docInfo DocumentInfo,
	parserInfo DocumentParserInfo,
	_ map[string]interface{}) (docState DocumentState, err error) {

	docState.SchemaVersion = docContent.SchemaVersion
	docState.DocumentType = documentType
	docState.DocumentInformation = docInfo
	docState.IOConfig = docContent.Description

	pluginInfo := []string{"example", parserInfo.DocumentId}
	if err != nil {
		return
	}
	docState.InstancePluginsInformation = pluginInfo
	return docState, nil
}

// ParseSendCommandMessage parses send command message
func ParseSendCommandMessage(context context.Context, msg InstanceMessage, messagesOrchestrationRootDir string, upstreamService string) (*DocumentState, error) {
	logger := log.Default()
	commandID, _ := GetCommandID(msg.MessageId)

	logger.Printf("Processing send command message: %v\n", msg.MessageId)
	logger.Printf("Processing send command payload: %v\n", msg.Payload)

	// parse message to retrieve parameters
	var parsedMessage SendCommandPayload
	err := json.Unmarshal([]byte(msg.Payload), &parsedMessage)
	if err != nil {
		errorMsg := fmt.Errorf("encountered error while parsing input - internal error %v", err)
		return nil, errorMsg
	}

	// adapt plugin configuration format from MDS to plugin expected format
	s3KeyPrefix := path.Join(parsedMessage.OutputS3KeyPrefix, parsedMessage.CommandID, msg.Destination)

	cloudWatchConfig, err := generateCloudWatchConfigFromPayload(context, parsedMessage)
	if err != nil {
		logger.Printf("encountered error while generating cloudWatch config from send command payload, err: %s", err)
	}

	messageOrchestrationDirectory := filepath.Join(messagesOrchestrationRootDir, commandID)

	documentType := "SendCommand"
	documentInfo := NewDocumentInfo(msg, parsedMessage)
	parserInfo := DocumentParserInfo{
		OrchestrationDir: messageOrchestrationDirectory,
		S3Bucket:         parsedMessage.OutputS3BucketName,
		S3Prefix:         s3KeyPrefix,
		MessageId:        documentInfo.MessageID,
		DocumentId:       documentInfo.DocumentID,
		CloudWatchConfig: cloudWatchConfig,
	}

	docContent := &DocumentContent{
		SchemaVersion: parsedMessage.DocumentContent.SchemaVersion,
		Description:   parsedMessage.DocumentContent.Description,
		RuntimeConfig: parsedMessage.DocumentContent.RuntimeConfig,
		MainSteps:     parsedMessage.DocumentContent.MainSteps,
		Parameters:    parsedMessage.DocumentContent.Parameters}

	//Data format persisted in Current Folder is defined by the struct - CommandState
	docState, err := InitializeDocState(context, documentType, docContent, documentInfo, parserInfo, parsedMessage.Parameters)
	if err != nil {
		return nil, err
	}
	docState.UpstreamServiceName = upstreamService
	parsedMessageContent, _ := json.Marshal(parsedMessage)

	var parsedContentJson Content

	if err = json.Unmarshal(parsedMessageContent, &parsedContentJson); err != nil {
		logger.Printf("Parsed message is in the wrong json format. Error is ", err)
	}

	obj := parsedContentJson.Search()
	if obj != "{}" {
		stripConfig := strings.Replace(strings.Replace(strings.Replace(obj, "\\t", "", -1), "\\n", "", -1), "\\", "", -1)
		stripConfig = strings.TrimSuffix(strings.TrimPrefix(stripConfig, "\""), "\"")

		finalLogConfig := fmt.Sprintf(stripConfig)

		if _, err = parsedContentJson.Set(finalLogConfig, "parameters"); err != nil {
			logger.Printf("Error occurred when setting properties with scrubbed credentials - ", err)
		}
		if _, err = parsedContentJson.Set(finalLogConfig, "cloudWatch"); err != nil {
			logger.Printf("Error occurred when setting properties with scrubbed credentials - ", err)
		}
		logger.Print("ParsedMessage is ", parsedContentJson)
	} else {
		//For plugins that are not aws:cloudwatch
		logger.Print("ParsedMessage is ", parsedMessageContent)
	}

	return &docState, nil
}

func generateCloudWatchConfigFromPayload(_ context.Context, parsedMessage SendCommandPayload) (string, error) {
	return "example" + parsedMessage.CloudWatchLogGroupName, nil
}
