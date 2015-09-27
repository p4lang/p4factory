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
// Class AppState
//    Contains all the UI state
//=========================================================

function AppState() {
  this.net = new Network();
  this.flowIdToFlow = {};
  this.flowFilter = $("#flow-filter")[0];
  this.webSocket = new WebSocketAdapter(self, config);
  this.chartToData = {};
  this.chartToBars = {};
  this.chartToYLabels = {};
  this.maxLatInCurrWindow = 0;
  this.xLabels = [];
  this.timeValues = [];

  var t = getCurrTimeStr();
  for (var i = 0; i <= NUM_X_TICKS; i++) {
    this.timeValues.push(t);
  }
}

AppState.prototype.recordSwitchLatencies = function(switchLatencies) {
  for (var sw in switchLatencies) {
    var l1 = switchLatencies[sw];
    var l2 = this.switchToLatHistory[sw].shift();
    this.switchToLatHistory[sw].push(l1);
    this.switchToLatSum[sw] = this.switchToLatSum[sw] + l1 - l2;
  }
};

AppState.prototype.updateFlowFilter = function() {
  var newFilter = this.flowFilter.options[this.flowFilter.selectedIndex].value;
  if (newFilter != "all") {
    var flow = this.flowIdToFlow[newFilter];
    this.webSocket.clientMsgSocket.send(flow.id);
  }
};

AppState.prototype.initializeCharts = function() {
  var self = this;
  var maxY = config.DEFAULT_LAT_MAX;
  this.net.switches.forEach(function(switchNode, i) {
    var sw = switchNode.name;
    var data = genEmptyDataForChart(500);
    self.chartToData[sw] = data;
    self.chartToBars[sw] = drawTimeSeriesGraph("#chart-packets-sw" + (i+1), data, config.COLOR_SCALE[i], maxY);
    self.chartToYLabels[sw] = drawTimeSeriesYAxis("#chart-packets-sw" + (i+1), [maxY, maxY/2, 0]);
  });

  $("#chart-packets-labels").text("Time series of per-packet switch hop latencies (Y)");
  self.xLabels = initializeXAxis();
};

AppState.prototype.initializeNetworkTopology = function(nodes, links, levelToNumNodes) {
  var net = appState.net;
  var nodeToType = {};
  var numHosts = levelToNumNodes[0];

  for (var i in range(0, numHosts)) {
    var n = nodes[i];
    nodeToType[n] = TYPE_HOST;
    net.tryAddNode(n, TYPE_HOST);
  }

  for (var i = numHosts; i < nodes.length; i++) {
    var n = nodes[i];
    nodeToType[n] = TYPE_SWITCH;
    net.tryAddNode(n, TYPE_SWITCH);
  }

  links.forEach(function(l) {
    var src = l[0];
    var dst = l[1];
    appState.net.tryAddLink( src, nodeToType[src], dst, nodeToType[dst] );
  });

  var idx = 0;
  levelToNumNodes.forEach(function(n, l) {
    for (var i = idx; i < idx + n; i++) {
      var name = nodes[i];
      var node = appState.net.node(name);
      node.level = l;
    }

    idx += n;  
  });

  drawLegends("#chart-packets-legend", appState.net.switches);
};
