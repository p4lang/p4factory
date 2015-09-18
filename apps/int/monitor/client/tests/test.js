
//=========================================================
// Helper functions
//=========================================================

function createNode(name, level, tpe) {
  return {
    "name": name,
    "level": level,
    "tpe": tpe
  };
}

function createLink(src, dst) {
  return {
    "srcNode": src,
    "dstNode": dst,
  };
}

function checkNodeIds(nodes) {
  nodes.forEach(function(n,i) {
    equal(n.id, i, "Node ID matches its index in the array");
  });
}

function checkSwitchIds(switches) {
  switches.forEach(function(s, i) {
    equal(s.switchId, i, "switchId matches the index in the 'switches' array");
  });
}

function compareNodes(expected, actual) {
  equal(expected.length, actual.length, "Number of nodes matches");

  for (var i = 0; i < expected.length; i++) {
    var e = expected[i];
    var a = actual[i];

    equal(e.name, a.name, "Node names match");
    equal(e.level, a.level, "Node levels match");
    equal(e.tpe, a.tpe, "Node types match");
  }
}

function compareLinks(expected, actual) {
  equal(expected.length, actual.length, "Number of links matches");

  for (var i = 0; i < expected.length; i++) {
    var e = expected[i];
    var a = actual[i];

    equal(e.srcNode.name, a.srcNode.name, "Link src names match");
    equal(e.dstNode.name, a.dstNode.name, "Link dst names match");
    equal(a.source, a.srcNode.id);
    equal(a.target, a.dstNode.id);
  }
}

function compareSwitchAvgHopLat(expected, actual) {
  deepEqual(actual, expected, "Switch avg hop latencies match");
}

//=========================================================
// Global variables
//=========================================================

var config = {
  "MAX_NUM_SWITCHES" : 16,
  "WEBSOCKET_HOST"   : "localhost",
  "WEBSOCKET_PORT"   : 8766
};

var appState = new AppState();

var msg1 = {
  "c1": "2886806021:2886806022:2561",
  "c2": "2048:53984",
  "sl": [
    [572662306, 10],
    [286331153, 20]
  ]
};

var msg2 = {
  "c1": "2886806021:2886806023:2561",
  "c2": "2056:53999",
  "sl": [
    [286331153, 50]
  ]
};

var h1 = createNode("172.17.42.5", 0, TYPE_HOST);
var h2 = createNode("172.17.42.6", 0, TYPE_HOST);
var h3 = createNode("172.17.42.7", 0, TYPE_HOST);

var s1 = createNode(286331153, 1, TYPE_SWITCH);
var s2 = createNode(572662306, 1, TYPE_SWITCH);

var l1 = createLink(s2, h2);
var l2 = createLink(s1, s2);
var l3 = createLink(h1, s1);
var l4 = createLink(s1, h3);

//=========================================================
// Tests
//=========================================================

QUnit.test("parseMessage", function() {
  var net = appState.net;

  //======================================================
  // Parse msg1
  //======================================================
  var m = parseMessage(msg1);

  checkNodeIds(net.nodes);
  checkSwitchIds(net.switches);
  compareNodes([h1, h2, s2, s1], net.nodes);
  compareNodes([s2, s1], net.switches);
  compareLinks([l1, l2, l3], net.links);

  appState.updateSwitchAvgHopLat(m.switchLatencies);
  var expectedAvgHopLat = {
    286331153: [20, 1],
    572662306: [10, 1]
  };

  compareSwitchAvgHopLat( expectedAvgHopLat, appState.switchToAvgHopLat );

  var expectedSwitchLatencies = {
    286331153: 20,
    572662306: 10
  };

  deepEqual(expectedSwitchLatencies, m.switchLatencies, "Comparing 'switchLatencies' computed by parseMessage()");

  ok(m.newLinkAdded);
  equal(m.flowId, msg1.c1, "Comparing flowIds")

  //======================================================
  // Parse msg2
  //======================================================

  m = parseMessage(msg2);
  checkNodeIds(net.nodes);
  checkSwitchIds(net.switches);
  compareNodes([h1, h2, s2, s1, h3], net.nodes);
  compareNodes([s2, s1], net.switches);
  compareLinks([l1, l2, l3, l4], net.links);

  appState.updateSwitchAvgHopLat(m.switchLatencies);
  expectedAvgHopLat = {
    286331153: [35, 2],
    572662306: [10, 1]
  };

  compareSwitchAvgHopLat( expectedAvgHopLat, appState.switchToAvgHopLat );

  expectedSwitchLatencies = { 286331153: 50 };
  deepEqual(expectedSwitchLatencies, m.switchLatencies, "Comparing 'switchLatencies' computed by parseMessage()");

  ok(m.newLinkAdded);
  equal(m.flowId, msg2.c1, "Comparing flowIds")

  //======================================================
  // Parse msg1 again
  //======================================================
  m = parseMessage(msg1);
  notOk(m.newLinkAdded);
});

function addBidirectionalLink(net, n1, type1, n2, type2) {
  net.tryAddLink(n1, type1, n2, type2);
  net.tryAddLink(n2, type2, n1, type1);
}

QUnit.test("computeNodeLevels", function() {
  var net = new Network();
  net.tryAddBidirectionalLink("h1", TYPE_HOST, "l1", TYPE_SWITCH);
  net.tryAddBidirectionalLink("l2", TYPE_SWITCH, "h2", TYPE_HOST);

  net.tryAddBidirectionalLink("l1", TYPE_SWITCH, "s1", TYPE_SWITCH);
  net.tryAddBidirectionalLink("l1", TYPE_SWITCH, "s2", TYPE_SWITCH);
  net.tryAddBidirectionalLink("s2", TYPE_SWITCH, "l2", TYPE_SWITCH);
  net.tryAddBidirectionalLink("s1", TYPE_SWITCH, "l2", TYPE_SWITCH);
  net.computeNodeLevels();

  var expectedNodeLevels = {
    "h1" : 0,
    "h2" : 0,
    "l1" : 1,
    "l2" : 1,
    "s1" : 2,
    "s2" : 2,
  };

  var actualNodeLevels = {};
  net.nodes.forEach(function(n) {
    actualNodeLevels[n.name] = n.level;
  });

  deepEqual(actualNodeLevels, expectedNodeLevels);
});