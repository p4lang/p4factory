
function AppState() {
  this.switchToAvgHopLat = {};

  this.switchToLatHistory = {};
  this.switchToLatSum = {};

  this.switchesSeen = {};
  this.net = new Network();
  this.flowIdToFlow = {};

  this.flowFilter = $("#flow-filter")[0];
  this.currFlowFilter = undefined;
  this.updateFlowFilter();

  this.webSocket = new WebSocketAdapter(self, config);

  this.timestamp = ((new Date()).getTime() / 1000)|0;

  this.chart = undefined;
  this.packetsChart = undefined;
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
  if (this.flowFilter) {
    this.currFlowFilter = this.flowFilter.options[this.flowFilter.selectedIndex].value;
  }
};

AppState.prototype.initializeCharts = function() {
  var _timestamp = ((new Date()).getTime() / 1000)|0;
  var lineChartData = [];
  var pktChartData = [];

  for (var i = 0; i < config.MAX_NUM_SWITCHES; i++) {
    lineChartData.push({
      label: "s" + i,
      values: [{ time: _timestamp, y: 0 }]
    });

    pktChartData.push({
      label: "s" + i,
      values: [{ time: _timestamp, y: 0 }]
    });
  }

  this.chart = $("#chart-avg-hop-lat").epoch({
    type: 'time.line',
    data: lineChartData,
    axes: ['left', 'bottom', 'right'],
    fps: config.CHART_FPS,
    historySize: 50, 
    windowSize: 50
  });

  this.packetsChart = $("#chart-packets").epoch({
    type: 'time.bar',
    data: pktChartData,
    axes: ['left', 'right'],
    fps: config.CHART_FPS,
    historySize: 50, 
    windowSize: 50
  });

  $("#chart-avg-hop-lat-labels").text("Timestamp (X) vs Avg hop latency per switch (us) (Y)");
  $("#chart-packets-labels").text("Packet (X) vs End-to-end latency (us) (Y)");
};

AppState.prototype.updateSwitchAvgHopLat = function(switchLatencies) {
  var switchToAvgHopLat = this.switchToAvgHopLat;
  for (var sw in switchLatencies) {
    if (!(sw in switchToAvgHopLat)) {
      switchToAvgHopLat[sw] = [0,0];
    }

    var tpl = switchToAvgHopLat[sw];
    tpl[0] = (( tpl[0] * tpl[1] ) + switchLatencies[sw] ) / ( tpl[1] + 1 );
    tpl[1] = tpl[1] + 1;
    switchToAvgHopLat[sw] = tpl;
  }
};

AppState.prototype.redrawTopologyGraph = function() {
  clearNetworkGraph();
  this.net.computeNodeLevels();
  drawNetworkGraph(this.net);
};

AppState.prototype.updateTimeStamp = function() {
  this.timestamp = ((new Date()).getTime() / 1000)|0;
};

AppState.prototype.redrawSwitchAvgHopLatChart = function(switchLatencies) {
  pushDataToChart(this.timestamp, switchLatencies);
};

AppState.prototype.tryRedrawPacketChart = function(flowId, switchLatencies, path) {
  if (flowMatchesFilter(flowId, this.currFlowFilter)) {
    pushDataToPktChart(this.timestamp, switchLatencies);
    highlightPath(this.net, path);
  }
};

AppState.prototype.getFlow = function(flowId) {
  if (!(flowId in this.flowIdToFlow)) {
    var f = new Flow(flowId);
    this.flowIdToFlow[flowId] = f;
    addOptionToSelect("#flow-filter", f.displayText, f.flowId);
  }

  return this.flowIdToFlow[flowId];
};