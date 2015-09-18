
//=========================================================
// Class WebSocketAdapter
//=========================================================

function WebSocketAdapter(appState, config) {
  this.appState = appState;
  this.config = config;

  this.host = config.WEBSOCKET_HOST;
  this.port = config.WEBSOCKET_PORT;
  
  this.socket = new WebSocket("ws://" + this.host + ":" + this.port);
  this.socket.onopen = this.onopen;
  this.socket.onmessage = this.onmessage;
  this.socket.onerror = this.onerror;
  this.socket.onclose = this.onclose;
}

WebSocketAdapter.prototype.onopen = function() {
  console.log("webSocket.onopen");
};

WebSocketAdapter.prototype.onerror = function(e) {
  console.log("ERROR");
  console.log(e);
};

WebSocketAdapter.prototype.onmessage = function(e) {
  var data = JSON.parse(e.data);
  var m = parseMessage(data);

  //appState.updateSwitchAvgHopLat(m.switchLatencies);
  if (m.newLinkAdded) { 
    appState.redrawTopologyGraph();
    removeLegends();
    drawLegends("#chart-avg-hop-lat-legend", appState.net.switches);
    drawLegends("#chart-packets-legend", appState.net.switches);
  }

  if (m.loopDetected) {
    var hopLatencies = data["s"];
    addLoopNotification(flow, hopLatencies, appState.timestamp);
  }

  appState.updateTimeStamp()
  //appState.recordSwitchLatencies(m.switchLatencies);
  appState.redrawSwitchAvgHopLatChart(m.switchLatencies);
  appState.tryRedrawPacketChart(m.flowId, m.switchLatencies, m.path);
};

function parseMessage(data) {
  var flowId = getFlowId(data);
  var path = [];
  var switchLatencies = {};

  var net = appState.net;
  var currLinkCount = net.links.length;

  var flow = appState.getFlow(flowId);

  var prevNodeName = flow.dstIP;
  var prevNodeType = TYPE_HOST;
  var hopLatencies = data["s"];
  var loopDetected = false;

  hopLatencies.forEach(function(h) {
    var sw = h[0], lat = h[1];

    if (!(sw in switchLatencies)) { 
      switchLatencies[sw] = lat;
    } else { 
      switchLatencies[sw] += lat;
      loopDetected = true;
    }

    path.push(net.tryAddLink(sw, TYPE_SWITCH, prevNodeName, prevNodeType));
    prevNodeName = sw;
    prevNodeType = TYPE_SWITCH;
  });

  var srcNodeName = flow.srcIP;
  path.push(net.tryAddLink(srcNodeName, TYPE_HOST, prevNodeName, prevNodeType));

  return {
    "flowId"         : flowId,
    "newLinkAdded"   : net.links.length > currLinkCount,
    "path"           : path,
    "switchLatencies": switchLatencies,
    "loopDetected"   : loopDetected
  }
}