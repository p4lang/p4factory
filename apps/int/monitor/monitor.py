#!/usr/bin/python3

# Copyright 2015-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import json
import socket
import threading
import websockets

from monitor_lib import *
from queue import Queue
from struct import *
from time import sleep

#===========================================
# Constants
#===========================================

WEBSOCKET_HOST = "localhost"
WEBSOCKET_PORT = 8766

#===========================================
# Global variables
#===========================================

app_state = AppState()

#===========================================
# Helper functions 
#===========================================

def print_bytearray(arr, n):
    i = 0
    while(i < n):
        (a,b,c,d) = unpack("B B B B", arr[i:i+4])
        print("%02X %02X %02X %02X" % (a,b,c,d))
        i = i + 4

@asyncio.coroutine
def send_viz_data(websocket, path):
    print("Received connection")
    app_state.client_connected_lock.acquire()
    app_state.client_connected = True
    app_state.client_connected_lock.release()

    n = app_state.net_topo
    q = dict()
    q["t"] = "tp"
    q["nodes"] = n.nodes
    q["level_to_num_nodes"] = n.level_to_num_nodes
    q["links"] = n.links

    yield from websocket.send(json.dumps(q))

    while True:
        if not websocket.open: break

        p = app_state.viz_data_pkts.get()
        yield from websocket.send(json.dumps(p))

#===========================================
# Entry point
#===========================================

t1 = PpDataReceiverThread(app_state)
t1.daemon = True
t1.start()

t2 = ClientMsgHandlerThread(app_state)
t2.daemon = True
t2.start()

t3 = PpDataProcessorThread(app_state)
t3.daemon = True
t3.start()

t4 = SwStatsAggregatorThread(app_state, 0.01)
t4.daemon = True
t4.start()

print("Starting websocket server at ws://%s:%d" % (WEBSOCKET_HOST, WEBSOCKET_PORT))
start_server_pkt = websockets.serve(send_viz_data, WEBSOCKET_HOST, WEBSOCKET_PORT)
asyncio.get_event_loop().run_until_complete(start_server_pkt)

asyncio.get_event_loop().run_forever()
