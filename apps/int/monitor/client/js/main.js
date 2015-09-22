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
// Global variables
//=========================================================

var config = {
  "CLIENT_MSG_HOST"                : "localhost",
  "CLIENT_MSG_PORT"                : 8767,
  "COLOR_SCALE"                    : ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b"],
  "DEFAULT_LAT_MAX"                : 3000,
  "TIMESERIES_REFRESH_INTERVAL_MS" : 1000,
  "WEBSOCKET_HOST"                 : "localhost",
  "WEBSOCKET_PORT"                 : 8766,
};

var appState = new AppState();

//=========================================================
// Main function
//=========================================================

function main() {
  // Set the onchange event listener for the flow filter combo box
  $("#flow-filter").change(function() {
    appState.updateFlowFilter();
    $(".link").attr("class", "link")
      .css("stroke", "black")
      .css("stroke-width", 1);
  });
}

//=========================================================
// Entry point
//=========================================================

$(document).ready(main);
