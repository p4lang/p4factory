
//=========================================================
// Global variables
//=========================================================

var config = {
  "CHART_FPS"        : 15,
  "MAX_NUM_SWITCHES" : 16,
  "SW_LAT_HIST_SIZE" : 10,
  "WEBSOCKET_HOST"   : "localhost",
  "WEBSOCKET_PORT"   : 8766
};

var appState = undefined;
config.color = d3.scale.category20().domain(range(config.MAX_NUM_SWITCHES));

//=========================================================
// Main function
//=========================================================

function main() {
  appState = new AppState();
  appState.initializeCharts();

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