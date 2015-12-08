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
// Class Flow
//  Contains flow-specific information
//=========================================================

function Flow(id, flowId) {
  this.id = id;
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
// Legend-related functions
//=========================================================

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
    .attr("fill", function(d,i) { return color(i); });

  svg.selectAll("legend-text")
    .data(switches)
    .enter().append("text")
    .attr("x", function(d,i) { return legendMargins.left + (legendWidth + legendTextWidth) * i + legendWidth + 5; })
    .attr("y", function(d,i) { return 42; })
    .attr("dy", ".5ex")
    .text(function(d) { return "0x" + parseInt(d.name).toString(16); })
    .attr("text-anchor", "right");
}

//=========================================================
// Notifications-related functions
//=========================================================

function addNotificationIfLoopPresent(net, flow, links) {
  var hops = linksToSwitchHops(net, links);
  if (isLoopPresent(hops)) {
    addLoopNotification(flow, hops)
  }
}

function linksToSwitchHops(net, linkIds) {
  var switches = [];
  linkIds.forEach(function(i) { 
    var l = net.links[i];
    switches.push(l.dstNode.name);
  })

  return switches;
}

function isLoopPresent(switches) {
  var switchesSeen = {};
  var res = false;

  switches.forEach(function(sw) {
    if (sw in switchesSeen) { res = true; }
    switchesSeen[sw] = true;
  });

  return res;
}

function addLoopNotification(flow, hops) {
  var swPath = hops.map(function(sw) { return "0x" + sw.toString(16); }).join(" -> ");
  var dt = (new Date()).toLocaleString([]);
  var msg =  "[" + dt + "] ============== Loop detected ===============\n";
  msg += "    Flow  : " + flow.displayText + "\n";
  msg += "    Hops  : " + swPath + "\n";
  addNotification(msg);
}

function addNotification(msg) {
  $("#notifications").append(msg);
}

//=========================================================
// ComboBox-related functions
//=========================================================

function addOptionToSelect(selectElemId, text, value) {
  var s = $(selectElemId)[0];
  if (s) { s.options[s.options.length] = new Option(text, value); }
}

function setOptionOfComboBox(comboBoxId, value) {
  $(comboBoxId)[0].value = value;
}

//=========================================================
// Miscellaneous
//=========================================================

function color(i) {
  return config.COLOR_SCALE[ i % config.COLOR_SCALE.length ];
}

function ipNumToDotNotation(ip) {
  return [24,16,8,0].map(function(i) { return (ip >> i) & 0xff; }).join(".");
}

function range(a,b) {
  var arr = [];
  if (a >= 0) {
    for (var i = a; i < b; i++) { arr.push(i); }
  }

  return arr;
}

function rangeFromZero(n) {
  return range(0, n);
}

function getCurrTimeStr() {
  return (new Date()).toLocaleTimeString();
}
