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

var TYPE_HOST = 0;
var TYPE_SWITCH = 1;

//=========================================================
// Class Network
//  Models network topology information
//=========================================================

function Network() {
    this._nextNodeId = 0;
    this._nextLinkId = 0;
    this._nextSwitchId = 0;
    this.nameToNode = {};
    this.hosts = [];
    this.links = [];
    this.switches = [];
    this.nodes = [];
    this.srcToDstToLink = {};
}

Network.prototype.node = function(name) {
    if (name in this.nameToNode) {
        return this.nameToNode[name];
    }

    console.error("[ERROR] Could not find node named '" + name + "'");
};

Network.prototype.tryAddNode = function(name, tpe) {
    var self = this;
    if (!(name in self.nameToNode)) {
      var n = new Node(name, tpe, self);
      self.nodes.push(n);
      self.nameToNode[name] = n;

      switch(tpe) {
        case TYPE_SWITCH : 
            n.switchId = self.nextSwitchId();
            self.switches.push(n); 
            break;
        case TYPE_HOST   : self.hosts.push(n); break;
        default          : console.error("[ERROR]: Unrecognized type: " + tpe);
      }
    }

    return self.nameToNode[name];
};

Network.prototype.tryAddLink = function(srcName, srcType, dstName, dstType) {
    var self = this;

    var src = self.tryAddNode(srcName, srcType);
    var dst = self.tryAddNode(dstName, dstType);

    if (( srcName in self.srcToDstToLink ) &&
        ( dstName in self.srcToDstToLink[srcName] )) {
      return self.srcToDstToLink[srcName][dstName];
    }

    var link = new Link(src, dst, self);
    self.links.push(link);

    if (!(srcName in self.srcToDstToLink)) {
      self.srcToDstToLink[srcName] = {};
    }
    
    self.srcToDstToLink[srcName][dstName] = link;
    src.neighbors.push(dst);

    return link;
};

Network.prototype.tryAddBidirectionalLink = function(name1, type1, name2, type2) {
    this.tryAddLink(name1, type1, name2, type2);
    this.tryAddLink(name2, type2, name1, type1);
};

Network.prototype.link = function(srcName, dstName) {
    if (( srcName in this.srcToDstToLink ) &&
        ( dstName in this.srcToDstToLink[srcName] )) {
      return this.srcToDstToLink[srcName][dstName];
    }

    return undefined;
};

Network.prototype.nextNodeId = function() {
    return this._nextNodeId++;
};

Network.prototype.nextLinkId = function() {
    return this._nextLinkId++;
};

Network.prototype.nextSwitchId = function() {
    return this._nextSwitchId++;
};

Network.prototype.computeNodeLevels = function() {
    var nodesToVisit = [];

    this.nodes.forEach(function(n) { n.visited = false; });
    this.hosts.forEach(function(h) { nodesToVisit.push(h); });

    while (nodesToVisit.length > 0) {
        var n1 = nodesToVisit.shift();
        n1.visited = true;
        n1.neighbors.forEach(function(n2) {
            if (!(n2.visited)) {
                n2.level = n1.level + 1;
                nodesToVisit.push(n2);
            }
        });
    }
};

//=========================================================
// Class Node
//=========================================================

function Node(name, tpe, network) {
    this.id = network.nextNodeId();
    this.name = name;
    this.tpe = tpe;
    this.switchId = -1;
    this.level = 0;
    this.neighbors = [];
}

Node.prototype.deepCopy = function() {
  var clone = {};
  for (var k in this) {
    clone[k] = this[k];
  }

  return clone;
}

//=========================================================
// Class Link
//=========================================================

function Link(srcNode, dstNode, network) {
    this.id = network.nextLinkId();
    this.srcNode = srcNode;
    this.dstNode = dstNode;
    this.source = this.srcNode.id;
    this.target = this.dstNode.id;
}
