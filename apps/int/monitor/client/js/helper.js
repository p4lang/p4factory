
//=========================================================
// Helper classes
//=========================================================

function Flow(flowId) {
  this.flowId = flowId;

  var arr = this.flowId.split(":");
  
  var vniAndProto = parseInt(arr[0]);
  this.vni = vniAndProto >> 8;
  this.proto = vniAndProto & 0xff;
  this.srcIP = ipNumToDotNotation(parseInt(arr[1]));
  this.dstIP = ipNumToDotNotation(parseInt(arr[2]));
  this.isTcpOrUdp = ((this.proto == 6) || (this.proto == 17));
  this.srcPort = this.isTcpOrUdp ? parseInt(arr[3]) : 0;
  this.dstPort = this.isTcpOrUdp ? parseInt(arr[4]) : 0;

  if (this.isTcpOrUdp) {
      this.displayText = 
          (this.srcIP + ":" + this.srcPort + " -> " +  this.dstIP + ":" + this.dstPort + 
           " [VNI == " + this.vni + " and Protocol == " + this.proto + "]");
  } else {
      this.displayText = 
          (this.srcIP  + " -> " +  this.dstIP + 
           " [VNI == " + this.vni + " and Protocol == " + this.proto + "]");
  } 
}

//=========================================================
// Helper functions
//=========================================================

function removeLegends() {
  $(".legend").remove();
  $(".legend-text").remove();
  $(".legend-svg").remove();
}

function drawLegends(parentDivId, switches) {
  var parentDiv = $(parentDivId);
  var svgWidth = parentDiv.width() * 0.95;
  var svgHeight = parentDiv.height() * 0.95;
  
  var svg = d3.select(parentDivId).append("svg")
    .attr("class", "legend-svg")
    .attr("width", svgWidth)
    .attr("height", svgHeight);

  var legendMargins = {
    "left"   : 5,
    "top"    : 0,
    "right"  : 0,
    "bottom" : 0
  };

  var legendWidth = 40;
  var legendHeight = 20;
  var legendTextWidth = 90;

  svg.selectAll(".legend")
    .data(switches)
    .enter().append("rect")
    .attr("class", "legend")
    .attr("x", function(d,i) { return legendMargins.left + (legendWidth + legendTextWidth) * i; })
    .attr("y", function(d,i) { return 30; })
    .attr("width", legendWidth)
    .attr("height", legendHeight)
    .attr("fill", function(d,i) { return config.color(i * 2); });

  svg.selectAll("legend-text")
    .data(switches)
    .enter().append("text")
    .attr("x", function(d,i) { return legendMargins.left + (legendWidth + legendTextWidth) * i + legendWidth + 5; })
    .attr("y", function(d,i) { return 42; })
    .attr("dy", ".5ex")
    .text(function(d) { return "0x" + parseInt(d.name).toString(16); })
    .attr("text-anchor", "right");
}

function clearNetworkGraph() {
  $("#topoSvg").remove();
}

function getEdges(links) {
  var edges = [];
  for (var i in links) {
    var l = links[i];
    var e = {};
    e.id = l.id;
    e.source = l.source;
    e.target = l.target;
    edges.push(e);
  }

  return edges;
}

function drawNetworkGraph(net) {
  var copyOfNodes = net.nodes.map(function(n) { return n.deepCopy(); });
  drawGraph("#network-graph", copyOfNodes, getEdges(net.links), cola);
}

function pushDataToChart(timestamp, switchToLat) {
  var entry = [];
  var net = appState.net;

  net.switches.forEach(function(sw) {
    var v = switchToLat[sw.name];
    entry.push({ time: timestamp, y: v ? v : 0 });
  });

  for (var i = net.switches.length; i < config.MAX_NUM_SWITCHES; i++) {
    entry.push({ time: timestamp, y: 0 });
  }

  appState.chart.push(entry);
}

function pushDataToPktChart(timestamp, switchToLat) {
  var pktChartEntry = [];
  var net = appState.net;

  net.switches.forEach(function(sw) {
    var v = switchToLat[sw.name];
    pktChartEntry.push({ time: timestamp, y: v ? v : 0 });
  });

  for (var i = net.switches.length; i < config.MAX_NUM_SWITCHES; i++) {
    pktChartEntry.push({ time: timestamp, y: 0 });
  }

  appState.packetsChart.push(pktChartEntry);
}

function highlightPath(net, path) {
  $(".prev-path")
    .css("stroke", "black")
    .css("stroke-width", 1)
    .attr("class", "link");

  $(".curr-path")
    .css("stroke", "red")
    .attr("class", "link prev-path");

  path.forEach(function(link) {
    $("#link-" + link.id)
      .css("stroke", "blue")
      .css("stroke-width", 3)
      .attr("class", "link curr-path");
  })
}

function addLoopNotification(flow, hopLatencies, timestamp) {
  var swPath = hopLatencies.map(function(h) { return h[0]; }).join(" -> ");
  var dt = (new Date(timestamp * 1000)).toLocaleString([]);
  var msg =  "[" + dt + "] ============== Loop detected ===============\n";
  msg += "    Flow  : " + flow.displayText + "\n";
  msg += "    Hops  : " + swPath + "\n";
  addNotification(msg);
}

function addNotification(msg) {
  $("#notifications").append(msg);
}

function getFlowId(pkt) {
  return pkt["c"];
}

function flowMatchesFilter(flowId, filter) {
  if (filter == "all") {
    return true;
  }

  return (flowId == filter);
}

function addOptionToSelect(selectElemId, text, value) {
  var s = $(selectElemId)[0];
  if (s) { s.options[s.options.length] = new Option(text, value); }
}

function ipNumToDotNotation(ip) {
  return [24,16,8,0].map(function(i) { return (ip >> i) & 0xff; }).join(".");
}

function range(n) {
  var arr = [];
  if (n >= 0) {
    for (var i = 0; i < n; i++) {
      arr.push(i);
    }
  }

  return arr;
}
