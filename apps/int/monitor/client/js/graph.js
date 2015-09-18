
function getColaDimensions() {
  var p = $('#topoSvg').parent()
  return [p.width(), p.height()];
}

function colorNodeBasedOnType(node) {
  switch(node.tpe) {
    case TYPE_SWITCH : return config.color( node.switchId * 2 );
    case TYPE_HOST   : return "gray";
    default          : console.error("[ERROR]: Unrecognized type: " + node.tpe); return "white";
  }
}

function labelNodeBasedOnType(node) {
  switch(node.tpe) {
    case TYPE_SWITCH : return "0x" + node.name.toString(16);;
    case TYPE_HOST   : return node.name;
    default          : console.error("[ERROR]: Unrecognized type: " + node.tpe); return "white";
  }
}

function generateConstraints(nodes) {
  var constraints = [];
  var gapX = 200;
  var gapY = 50;
  var levelToNodes = {};
  var numLevels = 0;

  nodes.forEach(function(n) {
    if (!(n.level in levelToNodes)) {
      levelToNodes[n.level] = [];
      numLevels++;
    }

    levelToNodes[n.level].push(n);
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

    if (l < (numLevels - 1)) {
      var n2 = levelToNodes[l+1];
      constraints.push({
        "axis": "y",
        "left": n2[0].id,
        "right": n1[0].id,
        "gap": gapY
      });
    }
  }

  return constraints;
}

function drawGraph(parentDivId, nodes, edges, cola) {
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

  var zoomFactor = 0.6;
  var zoom = d3.behavior.zoom();
  zoom.on("zoom", redraw);
  zoom.scale(zoomFactor);

  graph.append('rect')
    .attr('class', 'background')
    .attr('width', "100%")
    .attr('height', "100%")
    .call(zoom);

  //var s = "translate(" + graph.width()/2 + "," + graph.height()/2 + ") scale(" + zoomFactor + ")"
  //var s = "translate(" + graph.width()/2 + "," + graph.height()/2 + ")"
  var graphElements = graph.append('g')
    .attr("transform", "translate(100) scale(" + zoomFactor + ")");
    //.attr("transform", s);

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

  var constraints = generateConstraints(nodes);
  cola
    .linkDistance(500)
    .flowLayout('y')
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

  cola.start(40, 40, 40).on("tick", function () {
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
          dr = 1000;
          return "M" + d.sourceIntersection.x + "," + d.sourceIntersection.y + "A" + dr + "," + dr + " 0 0,0 " + d.arrowStart.x + "," + d.arrowStart.y; 
        });

    label.attr("x", function (d) { return d.x })
         .attr("y", function (d) { return d.y + (margin + pad) / 2 });

    ticks++;
    if (ticks > 50) { cola.stop(); }
  });
}