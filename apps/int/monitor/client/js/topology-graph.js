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
// Public functions (used from other modules)
//=========================================================

function drawNetworkGraph(net) {
  var copyOfNodes = net.nodes.map(function(n) { return n.deepCopy(); });
  drawTopologyGraph("#network-graph", copyOfNodes, copyLinks(net.links), cola);
}

function drawTopologyGraph(parentDivId, nodes, edges, cola) {
  function redraw() {
    graphElements.attr("transform", "translate(" + d3.event.translate + ")" + " scale(" + d3.event.scale + ")");
  }

  hljs.initHighlightingOnLoad();
  var cola = cola.d3adaptor();

  var graph = d3.select(parentDivId).append("svg")
    .attr('id', 'topoSvg')
    .attr("width", "100%")
    .attr("height", "100%")
    .attr("pointer-events", "all");

  var zoomFactor = 0.3;
  var zoom = d3.behavior.zoom();
  zoom.on("zoom", redraw);
  zoom.scale(zoomFactor);

  graph.append('rect')
    .attr('class', 'background')
    .attr('width', "100%")
    .attr('height', "100%")
    .call(zoom);

  var parentDiv = $(parentDivId);
  var parentWidth = parentDiv.width();
  var parentHeight = parentDiv.height();
  var s = "translate(" + (parentWidth/2 - 150) + "," + (parentHeight/2 - 50) + ") scale(" + zoomFactor + ")";
  var graphElements = graph.append('g')
    .attr("transform", s);

  graph.append('svg:defs').append('svg:marker')
    .attr('id', 'end-arrow')
    .attr('viewBox', '0 -5 10 10')
    .attr('refX', 8)
    .attr('markerWidth', 6)
    .attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('svg:path')
    .attr('d', 'M0,-5L10,0L0,5L2,0')
    .attr('stroke-width', '0px')
    .attr('fill', 'black');

  var constraints = generateConstraints(nodes, zoomFactor);
  cola
    .linkDistance(400)
    //.flowLayout('y')
    .size(getColaDimensions())
    .nodes(nodes)
    .links(edges)
    .constraints(constraints)
    .avoidOverlaps(true)
    .jaccardLinkLengths();

  var link = graphElements.selectAll(".link")
    .data(edges)
    .enter().append("svg:path")
    .attr("id", function(d) { return "link-" + d.id; })
    .attr("class", "link");

  var margin = 6, pad = 12;
  var node = graphElements.selectAll(".node")
    .data(nodes)
    .enter().append("rect")
    .attr("fill", colorNodeBasedOnType)
    .attr("rx", 5).attr("ry", 5)
    .attr("width", 80)
    .attr("height", 40)
    .call(cola.drag);

  var label = graphElements.selectAll(".label")
    .data(nodes)
    .enter().append("text")
    .attr("class", "label")
    .text(labelNodeBasedOnType)
    .call(cola.drag)
    .each(function (d) {
        var b = this.getBBox();
        var extra = 2 * margin + 2 * pad;
        d.width = b.width + extra;
        d.height = b.height + extra;
    });

  var ticks = 0

  cola.start(100, 100, 100).on("tick", function () {
    node.each(function (d) { d.innerBounds = d.bounds.inflate(-margin); })
        .attr("x", function (d) { return d.innerBounds.x; })
        .attr("y", function (d) { return d.innerBounds.y; })
        .attr("width", function (d) { return d.innerBounds.width(); })
        .attr("height", function (d) { return d.innerBounds.height(); });

    link.each(function (d) {
          vpsc.makeEdgeBetween(d, d.source.innerBounds, d.target.innerBounds, 5);})
        .attr("d", function (d) { 
          var dx = d.target.x - d.source.x,
          dy = d.target.y - d.source.y,
          dr = 1500;
          return "M" + d.sourceIntersection.x + "," + d.sourceIntersection.y + "A" + dr + "," + dr + " 0 0,0 " + d.arrowStart.x + "," + d.arrowStart.y; 
        });

    label.attr("x", function (d) { return d.x })
         .attr("y", function (d) { return d.y + (margin + pad) / 2 });

    ticks++;
    if (ticks > 150) { cola.stop(); }
  });
}

function unhighlightAllLinks() {
  $(".highligted-path")
    .css("stroke", "black")
    .css("stroke-width", 1)
    .attr("class", "link");
}

function highlightPath(net, linkIds, fillColor) {
  linkIds.forEach(function(i) {
    $("#link-" + i)
      .css("stroke", fillColor)
      .css("stroke-width", 3)
      .attr("class", "link highligted-path");
  })
}

//=========================================================
// Private functions (used only within this module)
//=========================================================

function generateConstraints(nodes, zoomFactor) {
  var constraints = [];
  var gapX = 100;
  var gapY = 50;
  var levelToNodes = {};
  var nameToNode = {};
  var numLevels = 0;

  nodes.forEach(function(n) {
    if (!(n.level in levelToNodes)) {
      levelToNodes[n.level] = [];
      numLevels++;
    }

    levelToNodes[n.level].push(n);
    nameToNode[n.name] = n;
  });

  for (var l = 0; l < numLevels; l++) {
    var offsets = [];
    var n1 = levelToNodes[l];
    n1.forEach(function(n) {
      offsets.push({ "node": n.id, "offset": "0" });
    });

    constraints.push({
      "type": "alignment",
      "axis": "y",
      "offsets": offsets
    });

    if (n1.length > 1) {
      for (var i = 0; i < n1.length - 1; i++) {
        constraints.push({
          "axis": "x",
          "left": n1[i].id,
          "right": n1[i+1].id,
          "gap": gapX
        });
      }
    }
  }

  // TODO: Replace these hard-code constraints with more generic constraints
  constraints.push({
    "type": "alignment",
    "axis": "x",
    "offsets": [
      { "node": 4, "offset": "0" },
      { "node": 6, "offset": "0" },
      { "node": 0, "offset": "-230" },
      { "node": 1, "offset": "230" }
    ]
  });

  constraints.push({
    "type": "alignment",
    "axis": "x",
    "offsets": [
      { "node": 5, "offset": "0" },
      { "node": 7, "offset": "0" },
      { "node": 2, "offset": "-230" },
      { "node": 3, "offset": "230" }
    ]
  });

  return constraints;
}

function getColaDimensions() {
  var p = $('#topoSvg').parent()
  return [p.width(), p.height()];
}

function colorNodeBasedOnType(node) {
  switch(node.tpe) {
    case TYPE_SWITCH : return color( node.switchId );
    case TYPE_HOST   : return "gray";
    default          : console.error("[ERROR]: Unrecognized type: " + node.tpe); return "white";
  }
}

function labelNodeBasedOnType(node) {
  switch(node.tpe) {
    case TYPE_SWITCH : return "0x" + node.name.toString(16);;
    case TYPE_HOST   : return ipNumToDotNotation(node.name);
    default          : console.error("[ERROR]: Unrecognized type: " + node.tpe); return "white";
  }
}

function copyLinks(links) {
  return links.map(function(l) {
    return { "id": l.id, "source": l.source, "target": l.target };
  })
}
