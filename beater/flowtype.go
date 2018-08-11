// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package beater

import "strconv"

type FlowType uint8

const (
	NetFlowV1 FlowType = 1
	NetFlowV5 FlowType = 5
	NetFlowV6 FlowType = 6
	NetFlowV7 FlowType = 7
	NetFlowV9 FlowType = 9
	IPFIX     FlowType = 10
)

var flowTypeNames = map[FlowType]string{
	NetFlowV1: "NetFlow V1",
	NetFlowV5: "NetFlow V5",
	NetFlowV6: "NetFlow V6",
	NetFlowV7: "NetFlow V7",
	NetFlowV9: "NetFlow V9",
	IPFIX:     "IPFIX",
}

func (t FlowType) String() string {
	name, found := flowTypeNames[t]
	if found {
		return name
	}
	return "unknown (" + strconv.Itoa(int(t)) + ")"
}
