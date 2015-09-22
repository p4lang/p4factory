// Copyright 2015-present Barefoot Networks, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//=========================================================
// Class WebSocketAdapter
//  Creates and manages the websockets opened by the client
//=========================================================

function WebSocketAdapter(appState, config) {
  this.appState = appState;
  this.config = config;

  this.host = config.WEBSOCKET_HOST;
  this.port = config.WEBSOCKET_PORT;
  
  // WebSocket through which the monitor sends viz data to the client
  this.monitorSocket = new WebSocket("ws://" + this.host + ":" + this.port);
  this.monitorSocket.onopen = this.onMonitorSocketOpen;
  this.monitorSocket.onerror = this.onMonitorSocketError;
  this.monitorSocket.onclose = this.onMonitorSocketClose;
  this.monitorSocket.onmessage = this.onMonitorSocketMessage;

  // WebSocket through which the client sends data to the monitor
  this.clientMsgSocket = new WebSocket("ws://" + config.CLIENT_MSG_HOST + ":" + config.CLIENT_MSG_PORT);
}

WebSocketAdapter.prototype.onMonitorSocketOpen = function() {
  console.log("webSocket.onopen");
};

WebSocketAdapter.prototype.onMonitorSocketError = function(e) {
  console.log("ERROR");
  console.log(e);
};

WebSocketAdapter.prototype.onMonitorSocketClose = function() {
  console.log("Monitor socket has been closed");
}

WebSocketAdapter.prototype.onMonitorSocketMessage = function(e) {
  var data = JSON.parse(e.data);

  if ("links" in data)        { processNetworkTopologyPkt(data); }
  else if (data["t"] == "sl") { processAggSwStatsPkt(data);      }
  else if (data["t"] == "nf") { processNewFlowPkt(data);         }
  else if (data["t"] == "pc") { processPathChangePkt(data);      }
  else if (data["t"] == "ft") { processFlowFilterPkt(data);      }
  else {
    console.error("Unexpected value for packet type: '" + data["t"] + "'");
  }
};

function processNetworkTopologyPkt(pkt) {
  appState.initializeNetworkTopology( pkt["nodes"], pkt["links"], pkt["level_to_num_nodes"]);
  drawNetworkGraph(appState.net);

  appState.initializeCharts();

  // Configure the time-series graphs to update at regular intervals
  setInterval(updateTimeSeriesGraphs, config.TIMESERIES_REFRESH_INTERVAL_MS);
}

function processAggSwStatsPkt(pkt) {
  pushDataToTimeSeriesGraphs(pkt["lt"]);
}

function processNewFlowPkt(pkt) {
  var flowId = pkt["f"];
  var f = new Flow(pkt["i"], flowId);
  appState.flowIdToFlow[flowId] = f;
  addOptionToSelect("#flow-filter", f.displayText, f.flowId);

  if (appState.flowFilter.options.length == 1) {
    unhighlightAllLinks();
    highlightPath(appState.net, pkt["l"], "blue");
    setOptionOfComboBox("#flow-filter", flowId);
  }

  addNotificationIfLoopPresent(appState.net, f, pkt["l"]);
}

function processPathChangePkt(pkt) {
  unhighlightAllLinks();
  highlightPath(appState.net, pkt["o"], "red");
  highlightPath(appState.net, pkt["l"], "blue");

  var flowId = pkt["f"];
  var flow = appState.flowIdToFlow[flowId];
  addNotificationIfLoopPresent(appState.net, flow, pkt["l"]);
}

function processFlowFilterPkt(pkt) {
  unhighlightAllLinks();
  highlightPath(appState.net, pkt["l"], "blue");

  var flowId = pkt["f"];
  var flow = appState.flowIdToFlow[flowId];
  addNotificationIfLoopPresent(appState.net, flow, pkt["l"]);
}
