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

package datastructs

import (
	"fmt"
	"regexp"
	"strings"
)

// DocumentState represents information relevant to a command that gets executed by agent
type DocumentState struct {
	DocumentInformation        DocumentInfo
	DocumentType               string
	SchemaVersion              string
	InstancePluginsInformation []string
	CancelInformation          string
	IOConfig                   string
	UpstreamServiceName        string
}

type InstanceMessage struct {
	CreatedDate string
	Destination string
	MessageId   string
	Payload     string
	Topic       string
}

// DocumentContent object which represents ssm document content.
type DocumentContent struct {
	SchemaVersion string             `json:"schemaVersion" yaml:"schemaVersion"`
	Description   string             `json:"description" yaml:"description"`
	RuntimeConfig map[string]*string `json:"runtimeConfig" yaml:"runtimeConfig"`
	MainSteps     []*string          `json:"mainSteps" yaml:"mainSteps"`
	Parameters    map[string]*string `json:"parameters" yaml:"parameters"`

	// InvokedPlugin field is set when document is invoked from any other plugin.
	// Currently, InvokedPlugin is set only in runDocument Plugin
	InvokedPlugin string
}

// DocumentParserInfo represents the parsed information from the request
type DocumentParserInfo struct {
	OrchestrationDir  string
	S3Bucket          string
	S3Prefix          string
	MessageId         string
	DocumentId        string
	DefaultWorkingDir string
	CloudWatchConfig  string
}

// SendCommandPayload parallels the structure of a send command MDS message payload.
type SendCommandPayload struct {
	Parameters              map[string]interface{} `json:"Parameters"`
	DocumentContent         DocumentContent        `json:"DocumentContent"`
	CommandID               string                 `json:"CommandId"`
	DocumentName            string                 `json:"DocumentName"`
	OutputS3KeyPrefix       string                 `json:"OutputS3KeyPrefix"`
	OutputS3BucketName      string                 `json:"OutputS3BucketName"`
	CloudWatchLogGroupName  string                 `json:"CloudWatchLogGroupName"`
	CloudWatchOutputEnabled string                 `json:"CloudWatchOutputEnabled"`
}

// getCommandID gets CommandID from given MessageID
func getCommandID(messageID string) string {
	// MdsMessageID is in the format of : aws.ssm.CommandId.InstanceId
	// E.g (aws.ssm.2b196342-d7d4-436e-8f09-3883a1116ac3.i-57c0a7be)
	mdsMessageIDSplit := strings.Split(messageID, ".")
	return mdsMessageIDSplit[len(mdsMessageIDSplit)-2]
}

func GetCommandID(messageID string) (string, error) {
	//messageID format: E.g (aws.ssm.2b196342-d7d4-436e-8f09-3883a1116ac3.i-57c0a7be)
	if match, err := regexp.MatchString("aws\\.ssm\\..+\\.+", messageID); !match {
		return messageID, fmt.Errorf("invalid messageID format: %v | %v", messageID, err)
	}

	return getCommandID(messageID), nil
}

// DocumentInfo represents information stored as interim state for a document
type DocumentInfo struct {
	// DocumentID is a unique name for file system
	// For Association, DocumentID = AssociationID.RunID
	// For RunCommand, DocumentID = CommandID
	// For Session, DocumentId = SessionId
	DocumentID      string
	CommandID       string
	AssociationID   string
	InstanceID      string
	MessageID       string
	RunID           string
	CreatedDate     string
	DocumentName    string
	DocumentVersion string
	DocumentStatus  string
	RunCount        int
	ProcInfo        string
	ClientId        string
	RunAsUser       string
	SessionOwner    string
}

func NewDocumentInfo(msg InstanceMessage, parsedMsg SendCommandPayload) DocumentInfo {

	documentInfo := new(DocumentInfo)

	documentInfo.CommandID, _ = GetCommandID(msg.MessageId)
	documentInfo.DocumentID = documentInfo.CommandID
	documentInfo.InstanceID = msg.Destination
	documentInfo.MessageID = msg.MessageId
	documentInfo.RunID = "example"
	documentInfo.CreatedDate = msg.CreatedDate
	documentInfo.DocumentName = parsedMsg.DocumentName
	documentInfo.DocumentStatus = "example"

	return *documentInfo
}
