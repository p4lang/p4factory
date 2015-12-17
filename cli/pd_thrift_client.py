# Copyright 2013-present Barefoot Networks, Inc. 
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

from thrift.protocol import TBinaryProtocol
from thrift.protocol import TMultiplexedProtocol
import thrift.Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
import importlib
import re
import socket
import struct
import sys


class ThriftClient(object):
  MATCH_SPEC_T = "_match_spec_t"
  ACTION_SPEC_T = "_action_spec_t"
  TABLE_ADD_WITH = "_table_add_with_"
  TABLE_MODIFY_WITH = "_table_modify_with_"
  TABLE_DELETE = "_table_delete"
  ADD_MEMBER_WITH = "_add_member_with_"
  MODIFY_MEMBER_WITH = "_modify_member_with_"
  DEL_MEMBER = "_del_member"
  CREATE_GROUP = "_create_group"
  DEL_GROUP = "_del_group"
  GET_FIRST_ENTRY_HANDLE = "_get_first_entry_handle"
  GET_NEXT_ENTRY_HANDLES = "_get_next_entry_handles"
  GET_ENTRY = "_get_entry"
  THRIFT_SPEC = "thrift_spec"
  SET_DEFAULT_ACTION = "_set_default_action_"

  def __init__(self, module, hostname, port, p4_name):
  
    self.p4_client_module = importlib.import_module(".".join(["p4_pd_rpc", p4_name]))
    self.mc_client_module = importlib.import_module(".".join(["mc_pd_rpc", "mc"]))
    self.conn_mgr_client_module = importlib.import_module(".".join(["conn_mgr_pd_rpc",
"conn_mgr"]))

    self._p4_name = p4_name

    self._utils = importlib.import_module("utils")

    self.setup(hostname, port)
    self._session_handle = self._conn_mgr.client_init(16)
    from res_pd_rpc.ttypes import DevTarget_t
    self._dev_target = DevTarget_t(0, self._utils.hex_to_i16(0xFFFF))

  def get_spec_prefix(self):
    return self._p4_name + '_'

  def setup(self, hostname, port):

    # Set up thrift client and contact server
    self._transport = TSocket.TSocket(hostname, port)
    self._transport = TTransport.TBufferedTransport(self._transport)
    bprotocol = TBinaryProtocol.TBinaryProtocol(self._transport)

    self._mc_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "mc")
    self._conn_mgr_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, "conn_mgr")
    self._p4_protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, self._p4_name)

    self._client = self.p4_client_module.Client(self._p4_protocol)
    self._mc = self.mc_client_module.Client(self._mc_protocol)
    self._conn_mgr = self.conn_mgr_client_module.Client(self._conn_mgr_protocol)
    self._transport.open()

  def get_match_field_names(self, table_name):
    return self.get_parameter_names(table_name, ThriftClient.MATCH_SPEC_T)

  def get_action_parameter_names(self, action_name):
    return self.get_parameter_names(action_name, ThriftClient.ACTION_SPEC_T)

  def get_spec_class(self, name, spec_suffix):
    spec_name = self.get_spec_prefix() + name + spec_suffix
    return getattr(self.p4_client_module, spec_name)

  def get_parameter_names(self, name, spec_suffix):
    try:
      spec_class = self.get_spec_class(name, spec_suffix)
      parameter_names = [x[2] for x in spec_class.thrift_spec[1:]]
    except AttributeError:
      raise AttributeError("Spec not found for %s" % name)
    return parameter_names

  def set_default_action(self, table_name, action_name, action_spec_tuple):
    add_entry_parameters = [self._session_handle, self._dev_target]

    if action_spec_tuple != ():
      add_entry_parameters.append(self.get_action_spec(action_name, action_spec_tuple))
    return self.get_set_default_action_function(table_name, action_name)(*add_entry_parameters)

  def add_entry(self, table_name, match_spec_tuple, action_name, action_spec_tuple, priority):
    match_spec = self.get_match_spec(table_name, match_spec_tuple)

    add_entry_parameters = [self._session_handle, self._dev_target, match_spec]

    if priority != None:
      add_entry_parameters.append(priority)
    if action_spec_tuple != ():
      add_entry_parameters.append(self.get_action_spec(action_name, action_spec_tuple))
    return self.get_add_entry_function(table_name, action_name)(*add_entry_parameters)

  def add_entry_with_selector(self, table_name, match_spec_tuple, group_handle):
    match_spec = self.get_match_spec(table_name, match_spec_tuple)
    add_entry_with_selector_parameters = [self._session_handle,
        self._dev_target, match_spec, int(group_handle)]
    return self.get_add_entry_with_selector(table_name)(*add_entry_with_selector_parameters)

  def add_entry_with_member(self, table_name, match_spec_tuple, member_handle):
    match_spec = self.get_match_spec(table_name, match_spec_tuple)
    add_entry_with_member_parameters = [self._session_handle,
        self._dev_target, match_spec, int(member_handle)]
    return self.get_add_entry_with_member(table_name)(*add_entry_with_member_parameters)

  def modify_entry(self, table_name, entry_handle, action_name, action_spec_tuple):
    modify_entry_parameters = [ self._session_handle, self._dev_target.dev_id, int(entry_handle) ]
    if action_spec_tuple is not ():
      modify_entry_parameters.append(self.get_action_spec(action_name, action_spec_tuple))
    return self.get_modify_entry_function(table_name, action_name)(*modify_entry_parameters)

  def delete_entry(self, table_name, entry_handle):
    delete_entry_function_name = "%s%s" % (table_name, ThriftClient.TABLE_DELETE)
    return getattr(self._client, delete_entry_function_name)(self._session_handle, self._dev_target.dev_id, int(entry_handle))

  def add_member(self, action_profile_name, action_name, action_spec_tuple):
    action_spec = self.get_action_spec(action_name, action_spec_tuple)
    add_entry_parameters = [self._session_handle, self._dev_target]
    if action_spec_tuple != ():
      add_entry_parameters.append(self.get_action_spec(action_name, action_spec_tuple))
    return self.get_add_member_function(action_profile_name, action_name)(*add_entry_parameters)

  def delete_member(self, action_profile_name, member_handle):
    return self.get_delete_member_function(action_profile_name)(self._session_handle, self._dev_target.dev_id, int(member_handle))

  def create_group(self, action_profile_name, max_group_size):
    return self.get_create_group_function(action_profile_name)(self._session_handle, self._dev_target, int(max_group_size))

  def delete_group(self, action_profile_name, group_handle):
    return self.get_delete_group_function(action_profile_name)(self._session_handle, self._dev_target.dev_id, group_handle)

  def get_first_entry_handle(self, table_name):
    first_entry_handle = int(self.get_get_first_entry_handle_function(table_name)(self._session_handle, self._dev_target))
    if first_entry_handle < 0:
      return "No entry handle found"
    else:
      return first_entry_handle

  def get_next_entry_handles(self, table_name, entry_handle, n):
    return self.get_get_next_entry_handles_function(table_name)(self._session_handle, self._dev_target.dev_id, entry_handle, n)

  def show_entry(self, table_name, entry_handle):
    return self.get_show_entry_function(table_name)(self._session_handle, self._dev_target.dev_id, entry_handle)

  def get_match_spec(self, table_name, match_spec_tuple):
    match_spec_class = self.get_spec_class(table_name, ThriftClient.MATCH_SPEC_T)
    return self.get_spec_from_spec_tuple(match_spec_class, match_spec_tuple)

  def get_action_spec(self, action_name, action_spec_tuple):
    action_spec_class = self.get_spec_class(action_name, ThriftClient.ACTION_SPEC_T)
    return self.get_spec_from_spec_tuple(action_spec_class, action_spec_tuple)

  def get_spec_from_spec_tuple(self, spec_class, spec_string):
    thrift_spec = getattr(spec_class, ThriftClient.THRIFT_SPEC)
    spec_parameters = []
    for i in range(1, len(thrift_spec)):
      parameter_type = thrift_spec[i][1]
      if parameter_type == thrift.Thrift.TType.STRING:
        is_success = False
        try:
          parameter = self._utils.macAddr_to_string(spec_string[i - 1])
          if len(parameter) == 6:
            spec_parameters.append(parameter)
            is_success = True
        except:
          pass
        if not is_success:
          try:
            parameter = socket.inet_pton(socket.AF_INET6, spec_string[i - 1])
            if len(parameter) == 16:
              spec_parameters.append(parameter)
              is_success = True
          except:
            pass
        if not is_success:
          parameter = spec_string[i - 1]
          try:
            width, v = parameter.split('w')
            width = int(width)
            assert(width > 0)
            v = int(v, 0)
          except:
            print "Make sure you prepend the length (in bytes) of the field"
            print "A valid input is 8w0x55 for a 64-bit field set to 0x55"
            raise ValueError("Cannot parse %s to TType.STRING" % parameter)
          array = []
          while v > 0:
            array.append(v % 256)
            v /= 256
            width -= 1
          if width < 0:
            print "Value overflow"
            raise ValueError("Cannot parse %s to TType.STRING" % parameter)
          while width > 0:
            array.append(0)
            width -= 1
          array.reverse()
          parameter = self._utils.bytes_to_string(array)
          spec_parameters.append(parameter)
      if parameter_type == thrift.Thrift.TType.BYTE:
        spec_parameters.append(self._utils.hex_to_byte(spec_string[i - 1]))
      if parameter_type == thrift.Thrift.TType.I16:
        parameter = int(spec_string[i - 1], 0)
        spec_parameters.append(self._utils.hex_to_i16(parameter))
      if parameter_type == thrift.Thrift.TType.I32:
        is_success = False
        try:
          spec_parameters.append(self._utils.ipv4Addr_to_i32(spec_string[i - 1]))
          is_success = True
        except:
          pass
        if not is_success:
          parameter = int(spec_string[i - 1], 0)
          try:
            spec_parameters.append(self._utils.hex_to_i32(parameter))
          except socket.error:
            raise ValueError("Cannot parse %s to TType.I32" % spec_string[i - 1])

    return spec_class(*spec_parameters)

  def get_table_names(self):
    table_names = []
    for function in dir(self.p4_client_module):
      regex = '^(?P<table_name>\S+)%s' % (ThriftClient.SET_DEFAULT_ACTION)
      m = re.search(regex, function)
      if m is not None and m.group("table_name") not in table_names:
        table_names.append(m.group("table_name"))
    return table_names

  def get_action_names(self, parent_object_name):
    action_names = []
    for function in dir(self._client):
      regex = '^%s%s(?P<action_name>\S+)' % (parent_object_name, ThriftClient.TABLE_ADD_WITH)
      m = re.search(regex, function)
      if m is not None:
        action_names.append(m.group("action_name"))
      else:
        regex = '^%s%s(?P<action_name>\S+)' % (parent_object_name, ThriftClient.ADD_MEMBER_WITH)
        m = re.search(regex, function)
        if m is not None:
          action_names.append(m.group("action_name"))
    return action_names

  def get_match_data_names(self, table_name):
    match_spec_class = self.get_spec_class(table_name, ThriftClient.MATCH_SPEC_T)
    return [ x[2] for x in match_spec_class.thrift_spec[1:] ]

  def get_action_data_names(self, action_name):
    action_spec_class = self.get_spec_class(action_name, ThriftClient.ACTION_SPEC_T)
    return [ x[2] for x in action_spec_class.thrift_spec[1:] ]

  def get_add_entry_function(self, table_name, action_name):
    add_entry_function_name = "%s%s%s" % (table_name, ThriftClient.TABLE_ADD_WITH, action_name)
    return getattr(self._client, add_entry_function_name)

  def get_set_default_action_function(self, table_name, action_name):
    add_entry_function_name = "%s%s%s" % (table_name, ThriftClient.SET_DEFAULT_ACTION, action_name)
    return getattr(self._client, add_entry_function_name)

  def get_modify_entry_function(self, table_name, action_name):
    modify_entry_function_name = "%s%s%s" % (table_name, ThriftClient.TABLE_MODIFY_WITH, action_name)
    return getattr(self._client, modify_entry_function_name)

  def get_get_first_entry_handle_function(self, table_name):
    get_first_entry_handle_function_name = "%s%s" % (table_name, ThriftClient.GET_FIRST_ENTRY_HANDLE)
    return getattr(self._client, get_first_entry_handle_function_name)

  def get_get_next_entry_handles_function(self, table_name):
    get_next_entry_handles_function_name = "%s%s" % (table_name, ThriftClient.GET_NEXT_ENTRY_HANDLES)
    return getattr(self._client, get_next_entry_handles_function_name)

  def get_show_entry_function(self, table_name):
    show_entry_function_name = "%s%s" % (table_name, ThriftClient.GET_ENTRY)
    return getattr(self._client, show_entry_function_name)

  def get_add_member_function(self, action_profile_name, action_name):
    add_member_function_name = "%s%s%s" % (action_profile_name, ThriftClient.ADD_MEMBER_WITH, action_name)
    return getattr(self._client, add_member_function_name)

  def get_modify_member_function(self, action_profile_name, action_name):
    modify_member_function_name = "%s%s%s" % (action_profile_name, ThriftClient.MODIFY_MEMBER_WITH, action_name)
    return getattr(self._client, modify_member_function_name)

  def get_delete_member_function(self, action_profile_name):
    delete_member_function_name = "%s%s" % (action_profile_name, ThriftClient.DEL_MEMBER)
    return getattr(self._client, delete_member_function_name)

  def get_create_group_function(self, action_profile_name):
    create_group_function_name = "%s%s" % (action_profile_name, ThriftClient.CREATE_GROUP)
    return getattr(self._client, create_group_function_name)

  def get_delete_group_function(self, action_profile_name):
    delete_group_function_name = "%s%s" % (action_profile_name, ThriftClient.DEL_GROUP)
    return getattr(self._client, delete_group_function_name)

# Multicast api

  def mc_mgrp_create(self, mgid):
    return self._mc.mc_mgrp_create(self._session_handle, self._dev_target.dev_id, mgid)

  def mc_node_create(self, rid, port_map, lag_map):
    return self._mc.mc_node_create(self._session_handle, self._dev_target.dev_id, rid, port_map, lag_map)

  def mc_node_update(self, l1_hdl, port_map, lag_map):
    return self._mc.mc_node_update(self._session_handle, self._dev_target.dev_id, port_map, lag_map)

  def mc_mgrp_destroy(self, mgrp_hdl):
    return self._mc.mc_mgrp_destroy(self._session_handle, self._dev_target.dev_id, mgrp_hdl)

  def mc_node_destroy(self, l1_hdl):
    return self._mc.mc_node_destroy(self._session_handle, self._dev_target.dev_id, l1_hdl)

  def mc_associate_node(self, grp_hdl, l1_hdl):
    return self._mc.mc_associate_node(self._session_handle, self._dev_target.dev_id, grp_hdl, l1_hdl)

  def mc_dissociate_node(self, grp_hdl, l1_hdl):
    return self._mc.mc_dissociate_node(self._session_handle, self._dev_target.dev_id, grp_hdl, l1_hdl)
