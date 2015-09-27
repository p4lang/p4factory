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
import struct
import threading
import websockets

from monitor_lib import *

#===========================================
# Constants
#===========================================

WEBSOCKET_HOST = "localhost"
WEBSOCKET_PORT = 8767

MONITOR_IP = "localhost"
MONITOR_PORT = 54322

monitor_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
monitor_sock.connect(( MONITOR_IP, MONITOR_PORT ))
packer = struct.Struct('I')

@asyncio.coroutine
def handle_client_msgs(websocket, path):
    while True:
        if not websocket.open: break

        message = yield from websocket.recv()
        if message is None:
          break

        print("Received: " + message) 

        values = [int(message)]
        d = packer.pack(*values)

        try:
            monitor_sock.sendall(d)
        except Exception as ex:
            print('[ERROR]: Closing client_msg_handler socket to monitor')
            print(ex)
            monitor_sock.close()

#===========================================
# Entry point
#===========================================

print("Starting websocket server at ws://%s:%d" % (WEBSOCKET_HOST, WEBSOCKET_PORT))
start_server_pkt = websockets.serve(handle_client_msgs, WEBSOCKET_HOST, WEBSOCKET_PORT)
asyncio.get_event_loop().run_until_complete(start_server_pkt)

asyncio.get_event_loop().run_forever()
