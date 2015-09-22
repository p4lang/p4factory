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
// Config specific to time-series graphs
//=========================================================

var TIME_SERIES_GRAPH_HEIGHT = 100; // in px

var NUM_X_TICKS = 5;
var X_AXIS_TICK_HEIGHT = 10;

var Y_AXIS_SVG_WIDTH = 50;
var Y_AXIS_TICK_WIDTH = 5;
var Y_AXIS_MARGIN_TOP = 2;

function drawTimeSeriesGraph(parentDivId, data, fillColor, maxValue) {
  var parentDiv = $(parentDivId);
  var parentWidth = parentDiv.width();
  var parentHeight = parentDiv.height();
  var barOuterWidth = parentWidth / data.length;
  if (barOuterWidth < 2) barOuterWidth = 2;

  var barInnerWidth = barOuterWidth - 1;

  parentDiv = d3.select(parentDivId);
  var graph = parentDiv.append("svg")
    .attr('id', 'mySvg')
    .attr("width", parentWidth - Y_AXIS_SVG_WIDTH)
    .attr("height", "100%")
    .attr("pointer-events", "all");

  var r = graph.append('rect')
    .attr('class', 'background')
    .attr('width', "100%")
    .attr('height', "100%");

  var zoomFactor = 1;
  var graphElements = graph.append('g')
    .attr("transform", "translate(0) scale(" + zoomFactor + ")");

  var bars = graphElements.selectAll(".node")
    .data(data)
    .enter().append("rect")
    .attr("fill", fillColor)
    .attr("x", function(d,i) { return barOuterWidth * i;})
    .attr("y", function(d,i) { return parentHeight - barHeight(d, maxValue); })
    .attr("width", barInnerWidth)
    .attr("height", function(d,i) { return barHeight(d, maxValue); })
    .attr("rx", 5).attr("ry", 5);

  return bars;
}

function drawTimeSeriesYAxis(parentDivId, yLabels) {
  var parentDiv = $(parentDivId);
  var parentWidth = parentDiv.width();
  var parentHeight = parentDiv.height();

  parentDiv = d3.select(parentDivId);

  var ySvg = parentDiv.append("svg")
    .attr("width", Y_AXIS_SVG_WIDTH)
    .attr("height", "100%")
    .style("background-color", "#DDF");

  var yElems = ySvg.append('g');
  yElems.append("line")
    .attr("x1", 0).attr("y1", Y_AXIS_MARGIN_TOP)
    .attr("x2", 0).attr("y2", parentHeight - Y_AXIS_MARGIN_TOP)
    .attr("stroke", "black")
    .attr("stroke-width", 3);

  yElems.append("line")
    .attr("x1", 0).attr("y1", Y_AXIS_MARGIN_TOP)
    .attr("x2", Y_AXIS_TICK_WIDTH).attr("y2", Y_AXIS_MARGIN_TOP)
    .attr("stroke", "black")

  yElems.append("line")
    .attr("x1", 0).attr("y1", parentHeight/2)
    .attr("x2", Y_AXIS_TICK_WIDTH).attr("y2", parentHeight/2)
    .attr("stroke", "black")

  yElems.append("line")
    .attr("x1", 0).attr("y1", parentHeight - Y_AXIS_MARGIN_TOP)
    .attr("x2", Y_AXIS_TICK_WIDTH).attr("y2", parentHeight - Y_AXIS_MARGIN_TOP)
    .attr("stroke", "black")

  var tickLabels =
    yElems.selectAll(".y-label")
      .data(yLabels)
      .enter().append("text")
      .attr("class", "y-label")
      .text(numMicrosToFormattedStr)
      .attr("dy", ".35em")
      .attr("x", Y_AXIS_TICK_WIDTH + 3)
      .attr("y", function(d,i) { return getYLabelPosition(parentHeight, i); })
      .attr("font-size", 10);

  return tickLabels;
}

function initializeXAxis() {
  var xSvg = d3.select("#chart-packets-x-axis")
    .append("svg")
    .attr("width", "100%")
    .attr("height", 20)
    .attr("backgroud-color", "red")
    .style("backgroud-color", "red")

  var xElems = xSvg.append('g');
  var p = $("#chart-packets-labels");
  var w = p.width() - Y_AXIS_SVG_WIDTH;
  var h = p.height();

  xElems.append("line")
   .attr("stroke-width", 3)
   .attr("stroke", "black")
   .attr("x1", 0).attr("y1", 0)
   .attr("x2", w).attr("y2", 0);

  xElems.selectAll(".x-tick")
   .data(range(0, NUM_X_TICKS + 1))
   .enter().append("line")
   .attr("class", "x-tick")
   .attr("x1", function(d) { return (w/NUM_X_TICKS) * d; }).attr("y1", 0)
   .attr("x2", function(d) { return (w/NUM_X_TICKS) * d; }).attr("y2", X_AXIS_TICK_HEIGHT)
   .attr("stroke", "black");

  var currTime = getCurrTimeStr();
  var tickLabels =
    xElems.selectAll(".x-label")
    .data(appState.timeValues)
    .enter().append("text")
    .attr("class", "x-label")
    .text(currTime)
    .attr("dy", ".72em")
    .attr("x", function(d, i) { return (w/NUM_X_TICKS) * i - 20; })
    .attr("y", X_AXIS_TICK_HEIGHT + 3)
    .attr("font-size", 10);

  return tickLabels;
}

function updateTimeSeriesGraphs() {
  appState.net.switches.forEach(function(sw) {
    redrawTimeSeriesGraph(sw.name);
  });
}

function updateYLabels() {
  var max = appState.maxLatInCurrWindow;
  if (max == 0) { max = config.DEFAULT_LAT_MAX; }
  for (var sw in appState.chartToYLabels) {
    appState.chartToYLabels[sw]
    .data([max, max/2,0])
    .text(numMicrosToFormattedStr);
  }
}

function updateXAxisLabels() {
  appState.timeValues.shift();
  appState.timeValues.push(getCurrTimeStr());
  appState.xLabels.data(appState.timeValues).text(function(d) { return d; });
}

function pushDataToTimeSeriesGraphs(switchToLat) {
  var net = appState.net;

  net.switches.forEach(function(sw, i) {
    var name = sw.name
    var v = switchToLat[name];
    pushDataToTimeSeries(name, v);
  });
}

function pushDataToTimeSeries(sw, d) {
  var chartData = appState.chartToData[sw];
  var v = chartData.shift();
  chartData.push(d);
  
  var currMax = appState.maxLatInCurrWindow;
  if (v == currMax) {
    var newMax = Math.max.apply(null, chartData);
    appState.maxLatInCurrWindow = newMax;
    updateYLabels();
  } else if (d > currMax) {
    appState.maxLatInCurrWindow = d;
    updateYLabels();
  }
}

function genEmptyDataForChart(n) {
  var data = [];
  for (var i = 0; i < n; i++) { data.push(0); }

  return data;
}

function redrawTimeSeriesGraph(sw) {
  var bars = appState.chartToBars[sw];
  var data = appState.chartToData[sw];
  var maxValue = appState.maxLatInCurrWindow;
  bars.data(data)
      //.attr("x", function(d,i) { return barOuterWidth * i;})
      //.attr("y", function(d,i) { return parentHeight - barHeight(d, maxValue); })
      .attr("y", function(d,i) { return TIME_SERIES_GRAPH_HEIGHT - barHeight(d, maxValue); })
      .attr("height", function(d,i) { return barHeight(d, maxValue); })
}

// Private functions

var barHeight = function(v, maxValue) {
  if (maxValue == 0) {
    maxValue = config.DEFAULT_LAT_MAX;
  }

  var h = (v / maxValue) * 100;
  h = Math.min(h, 100);
  h = Math.max(h, 2);
  return h;
}

function numMicrosToFormattedStr(n) {
  if (n == 0) { return "0"; }
  if (n < 1000) { return n + "us"; }
  if (n < 1E6) { 
    if ((n % 1000) == 0) { return n/1000 + "ms"; }
    return (n/1000).toFixed(1) + "ms";
  }
  
  if ((n % 1E6) == 0) { return n/1E6 + "s"; }
  return (n/1E6).toFixed(1) + "s";
}

function getYLabelPosition(parentDivHeight, labelId) {
  switch(labelId) {
    case 0: return Y_AXIS_MARGIN_TOP + 5;
    //case 1: return parentHeight/2;
    case 1: return parentDivHeight/2;
    case 2: return parentDivHeight - Y_AXIS_MARGIN_TOP - 5;
  }

  return -1;
}
