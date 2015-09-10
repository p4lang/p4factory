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

import cmd
import collections
import getopt
import importlib
import os
import sys
import thrift

# Import from p4factory/cli
import pd_thrift_client


class PdCli(cmd.Cmd):
  MATCH_SPEC_T = "_match_spec_t"
  ACTION_SPEC_T = "_action_spec_t"

  def __init__(self, p4_name, thrift_module, thrift_server, port):
    cmd.Cmd.__init__(self)
    self._p4_name = p4_name
    self._module = importlib.import_module(thrift_module.strip())
    self._thrift_client = pd_thrift_client.ThriftClient(self._module, thrift_server, port, self._p4_name)

  def do_show_tables(self, line):
    """
    show_tables
    Lists all tables in the P4 program. Output can be optionally piped to Bash.
    """
    table_names = []
    for table_name in self.get_table_names(None):
      table_names.append(table_name)
    self.pipe_to("\n".join(table_names), line)

  def do_show_actions(self, line):
    """
    show_actions TABLE_NAME [ | BASH_COMMANDS ]
    Lists all action in TABLE_NAME. Output can be optionally piped to Bash.
    """
    words = collections.deque(line.split())
    try:
      table_name = self.get_table_name(words)
      action_names = []
      for action_name in self._thrift_client.get_action_names(table_name):
        action_names.append(action_name)
      self.pipe_to("\n".join(action_names), line)
    except Exception as e:
      self.usage(e, 'show_actions')

  def complete_show_actions(self, text, line, begidx, endidx):
    incomplete_word_idx = self.get_incomplete_word_idx(line, begidx)
    if incomplete_word_idx == 2:
      return self.get_table_names(text)
    else:
      return []

  def do_add_entry(self, line):
    """
    add_entry TABLE_NAME MATCH_FIELDS... ACTION_NAME ACTION_PARAMETERS...
    Adds an entry with the specified MATCH_FIELDS, ACTION_NAME and
    ACTION_PARAMETERS to TABLE_NAME. Prints the entry handle of the newly added
    entry.
    """
    words = collections.deque(line.split())
    try:
      (table_name, match_tuple) = self.get_table_name_and_match_tuple(words)
      (action_name, action_tuple) = self.get_action_name_and_tuple(words, table_name)

      priority = None
      if len(words) > 0:
        priority = self.get_handle(words, "priority")
      entry_index = self._thrift_client.add_entry(table_name, match_tuple,
        action_name, action_tuple, priority)

      print "Inserted entry with handle %d" % entry_index
    except NameError as ne:
      print >> sys.stderr, ne
    except thrift.protocol.TProtocol.TProtocolException as e:
      print >> sys.stderr, e
    except Exception as e:
      self.usage(e, "add_entry")

  def do_set_default_action(self, line):
    """
    set_default_action TABLE_NAME ACTION_NAME ACTION_PARAMETERS
    This funciton sets the default action of a given table.
    """
    words = collections.deque(line.split())
    try:
      table_name = self.get_table_name(words)
      (action_name, action_tuple) = self.get_action_name_and_tuple(words, table_name)

      entry_index = self._thrift_client.set_default_action(table_name,
        action_name, action_tuple)

      print "Default action with handle %d" % entry_index
    except NameError as ne:
      print >> sys.stderr, ne
    except thrift.protocol.TProtocol.TProtocolException as e:
      print >> sys.stderr, e
    except Exception as e:
      self.usage(e, "set_default_action")

  def complete_add_entry(self, text, line, begidx, endidx):
    incomplete_word_idx = self.get_incomplete_word_idx(line, begidx)
    if incomplete_word_idx == 2:
      return self.get_table_names(text)
    else:
      words = collections.deque(line.split())
      assert words.popleft() == "add_entry"
      table_name = self.get_next_token(words, "table name")
      num_match_fields = len(self._thrift_client.get_match_field_names(table_name))
      if incomplete_word_idx == (2 + num_match_fields + 1):
        return self.get_action_names(table_name, text)
      else:
        return []

  def do_add_entry_with_selector(self, line):
    """
    add_entry_with_selector TABLE_NAME MATCH_FIELDS GROUP_HANDLE
    Adds an entry with the specified MATCH_FIELDS to TABLE_NAME. Prints the
    entry handle of the newly added entry.
    """
    words = collections.deque(line.split())
    try:
      (table_name, match_tuple) = self.get_table_name_and_match_tuple(words)
      group_handle = self.get_handle(words, "group handle")

      entry_index = self._thrift_client.add_entry_with_selector(table_name,
          match_tuple, group_handle)

      print "Inserted entry with handle %d" % entry_index
    except Exception as e:
      self.usage(e, "add_entry_with_selector")

  def do_add_entry_with_member(self, line):
    """
    add_entry_with_member TABLE_NAME MATCH_FIELDS MEMBER_HANDLE
    This command is valid for tables with have action profiles. It adds an entry
    with the specified MATCH_FIELDS and MEMBER_HANDLE to TABLE_NAME. Prints the
    entry handle of the newly added entry.
    """
    words = collections.deque(line.split())
    try:
      (table_name, match_tuple) = self.get_table_name_and_match_tuple(words)
      member_handle = self.get_handle(words, "member handle")

      entry_index = self._thrift_client.add_entry_with_member(table_name,
          match_tuple, member_handle)

      print "Inserted entry with handle %d" % entry_index
    except Exception as e:
      self.usage(e, "add_entry_with_member")

  def do_modify_entry(self, line):
    """
    modify_entry TABLE_NAME ENTRY_HANDLE ACTION_NAME ACTION_PARAMETERS...
    Sets the ACTION_NAME and ACTION_PARAMETERS of the entry specified by
    ENTRY_HANDLE in TABLE_NAME.
    """
    words = collections.deque(line.split())
    try:
      table_name = self.get_table_name(words)
      entry_handle = self.get_handle(words, "entry handle")
      (action_name, action_tuple) = self.get_action_name_and_tuple(words, table_name)
      if 0 != self._thrift_client.modify_entry(table_name, entry_handle, action_name, action_tuple):
        print >> sys.stderr, "Modify entry failed."
    except Exception as e:
      self.usage(e, "modify_entry")

  def do_delete_entry(self, line):
    """
    delete_entry TABLE_NAME ENTRY_HANDLE
    Deletes an entry specified by ENTRY_HANDLE in TABLE_NAME.
    """
    words = collections.deque(line.split())
    try:
      table_name = self.get_table_name(words)
      entry_handle = self.get_handle(words, "entry handle")
      if self._thrift_client.delete_entry(table_name, entry_handle) == 0:
        print "Entry deleted"
      else:
        print >> sys.stderr, "Invalid entry handle %d" % entry_handle
    except Exception as e:
      self.usage(e, "delete_entry")

  def complete_delete_entry(self, text, line, begidx, endidx):
    return self.get_full_table_name(text, line, begidx)

  def do_add_member(self, line):
    """
    add_member ACTION_PROFILE_NAME ACTION_NAME ACTION_PARAMETERS...
    Add an entry to an action profile. Print the member handle of the newly
    added entry.
    """
    words = collections.deque(line.split())
    try:
      action_profile_name = self.get_next_token(words, "action profile name")
      (action_name, action_tuple) = self.get_action_name_and_tuple(words, action_profile_name)
      print self._thrift_client.add_member(action_profile_name, action_name, action_tuple)
    except Exception as e:
      self.usage(e, "add_member")

  def do_delete_member(self, line):
    """
    delete_member ACTION_PROFILE_NAME MEMBER_HANDLE
    Deletes an member specified by MEMBER_HANDLE in ACTION_PROFILE_NAME.
    """
    words = collections.deque(line.split())
    try:
      action_profile_name = self.get_next_token(words, "action profile name")
      member_handle = self.get_handle(words, "member handle")
      if self._thrift_client.delete_member(action_profile_name, member_handle) == 0:
        print "Member deleted"
      else:
        print >> sys.stderr, "Invalid member handle %d" % member_handle
    except Exception as e:
      self.usage(e, "delete_member")

  def do_create_group(self, line):
    """
    create_group ACTION_PROFILE_NAME MAX_GROUP_SIZE
    Creates a new group for an action profile. Prints the handle of the new
    group.
    """
    words = collections.deque(line.split())
    try:
      action_profile_name = self.get_next_token(words, "action profile name")
      max_group_size = self.get_handle(words, "max group size")
      print self._thrift_client.create_group(action_profile_name, max_group_size)
    except Exception as e:
      self.usage(e, "create_group")

  def do_add_member_to_group(self, line):
    """
    add_member_to_group GROUP_HANDLE MEMBER_HANDLE
    Adds a action profile member to an action profile group.
    """
    words = collections.deque(line.split())
    try:
      action_profile_name = self.get_next_token(words, "action profile name")
      group_handle = self.get_handle(words, "group handle")
      member_handle = self.get_handle(words, "member handle")
      self._thrift_client.add_member_to_group(action_profile_name, group_handle, member_handle)
    except Exception as e:
      self.usage(e, "add_member_to_group")

  def do_delete_group(self, line):
    """
    delete_group ACTION_PROFILE_NAME GROUP_HANDLE
    Delete a group specified by GROUP_HANDLE
    """
    words = collections.deque(line.split())
    try:
      action_profile_name = self.get_next_token(words, "action profile name")
      group_handle = self.get_handle(words, "group handle")
      if self._thrift_client.delete_group(action_profile_name, group_handle) != 0:
        print "Group deleted"
      else:
        print >> sys.stderr, "Invalid group handle %d" % group_handle
    except Exception as e:
      self.usage(e, "delete_group")

  def do_get_first_entry_handle(self, line):
    """
    get_first_entry_handle TABLE_NAME
    Prints the first valid entry handle in TABLE_NAME. This command can be used
    to begin iterating over all entry handles in a table.
    """
    words = collections.deque(line.split())
    try:
      table_name = self.get_table_name(words)
      print self._thrift_client.get_first_entry_handle(table_name)
    except Exception as e:
      self.usage(e, "get_first_entry_handle")

  def complete_get_first_entry_handle(self, text, line, begidx, endidx):
    return self.get_full_table_name(text, line, begidx)

  def do_get_next_entry_handles(self, line):
    """
    get_next_entry_handles TABLE_NAME ENTRY_HANDLE NUM_ENTRY_HANDLES
    Prints NUM_ENTRY_HANDLES valid entry handles following ENTRY_HANDLE in
    TABLE_NAME.
    """
    words = collections.deque(line.split())
    try:
      table_name = self.get_table_name(words)
      entry_handle = self.get_handle(words, "entry handle")
      n = self.get_handle(words, "number of entry handles")
      print self._thrift_client.get_next_entry_handles(table_name, entry_handle, n)
    except Exception as e:
      self.usage(e, "get_next_entry_handles")

  def complete_get_next_entry_handles(self, text, line, begidx, endidx):
    return self.get_full_table_name(text, line, begidx)

  def do_show_entry(self, line):
    """
    show_entry TABLE_NAME ENTRY_HANDLE
    Prints the match key and action type and parameters for the entry specified
    by ENTRY_HANDLE in TABLE_NAME.
    """
    words = collections.deque(line.split())
    try:
      table_name = self.get_table_name(words)
      entry_handle = self.get_handle(words, "entry handle")
      print self._thrift_client.show_entry(table_name, entry_handle)
    except Exception as e:
      self.usage(e, "show_entry")

  def complete_show_entry(self, text, line, begidx, endidx):
    return self.get_full_table_name(text, line, begidx)

  def do_dump_table(self, line):
    """
    dump_table TABLE_NAME
    Prints all entries in TABLE_NAME. Output can be optionally piped to Bash.
    """
    words = collections.deque(line.split())
    try:
      table_name = self.get_table_name(words)
      entry_handle = self._thrift_client.get_first_entry_handle(table_name)
      entries = []
      if isinstance(entry_handle, int):
        while True:
          entries.append("Entry handle %s" % str(entry_handle))
          entries.append(self._thrift_client.show_entry(table_name, entry_handle))
          entry_handle_list = self._thrift_client.get_next_entry_handles(table_name, entry_handle, 1)
          if len(entry_handle_list) == 0:
            break
          entry_handle = entry_handle_list[0]
        self.pipe_to("\n".join(entries), line)
      else:
        print entry_handle
    except Exception as e:
      self.usage(e, "dump_table")

  def complete_dump_table(self, text, line, begidx, endidx):
    incomplete_word_idx = self.get_incomplete_word_idx(line, begidx)
    if incomplete_word_idx == 2:
      return self.get_table_names(text)
    else:
      return []

  def emptyline(self):
    pass

  def do_exit(self, line):
    "Exit"
    return 'exited by user command'

  def do_quit(self, line):
    "Exit"
    return self.do_exit(line)

  def do_EOF(self, line):
    "Exit"
    return self.do_exit(line)

  def get_handle(self, words, handle_name):
    try:
      handle_str = self.get_next_token(words, handle_name)
      handle = int(handle_str)
    except ValueError as ve:
      raise ValueError("Invalid %s \"%s\"." % (handle_name, handle_str))
    return handle

  def get_table_name_and_match_tuple(self, words):
    table_name = self.get_table_name(words)
    num_match_fields = len(self._thrift_client.get_match_field_names(table_name))
    match_field_names = self._thrift_client.get_match_field_names(table_name)
    match_tuple = self.get_tuple(words, match_field_names, "match field")
    return (table_name, match_tuple)

  def get_table_name(self, words):
    table_name = self.get_next_token(words, "table name")
    if table_name not in self._thrift_client.get_table_names():
      raise NameError("Invalid table name \"%s\"" % table_name)
    return table_name

  def get_full_table_name(self, text, line, begidx):
    incomplete_word_idx = self.get_incomplete_word_idx(line, begidx)
    if incomplete_word_idx == 2:
      return self.get_table_names(text)
    else:
      return []

  def get_action_name_and_tuple(self, words, parent_object_name):
    action_name = self.get_next_token(words, "action name")
    if action_name in self._thrift_client.get_action_names(parent_object_name):
      try:
        action_parameter_names = self._thrift_client.get_action_parameter_names(action_name)
      except:
        action_parameter_names = []
      action_tuple = self.get_tuple(words, action_parameter_names, "action parameter")
      return (action_name, action_tuple)
    else:
      raise AttributeError("%s does not contain action %s" % (parent_object_name, action_name))

  def get_next_token(self, words, name_type):
    try:
      name = words.popleft()
    except IndexError as ie:
      raise IndexError('Missing %s' % name_type)
    return name

  def get_tuple(self, words, field_names, parameter_type):
    parameters = []
    for i in range(len(field_names)):
      parameter = self.get_next_token(words, field_names[i])
      if parameter == "?":
        raise IndexError("Next %s is %s" % (parameter_type, field_names[i]))
      parameters.append(parameter)
    return tuple(parameters)

  def get_incomplete_word_idx(self, line, begidx):
    return len(line[:begidx].split()) + 1

  def get_table_names(self, table_name_prefix):
    table_names = self._thrift_client.get_table_names()
    if not table_name_prefix:
      completion = table_names
    else:
      completion = [ t_n for t_n in table_names if
          t_n.startswith(table_name_prefix) ]
    return completion

  def get_action_names(self, table_name, action_name_prefix):
    action_names = self._thrift_client.get_action_names(table_name)
    if not action_name_prefix:
      completion = action_names
    else:
      completion = [ a_n for a_n in action_names if
          a_n.startswith(action_name_prefix) ]
    return completion

  def pipe_to(self, previous_output, line):
    if line.find("|") != -1:
      command = "echo \"%s\" | %s" % (previous_output, line[line.find("|") + 1:])
      return_code = os.system(command)
      if return_code != 0:
        print >> sys.stderr, "Error executing bash command, return code %d" % return_code
    else:
      print previous_output

  def usage(self, exception, command):
    print >> sys.stderr, exception
    print >> sys.stderr, "Try 'help %s' for more information" % command

# Multicast API
  def do_mc_mgrp_create(self, line):
    """
    mc_mgrp_create MGRP_ID
    This function creates a multicast group with multicast index MGRP_ID.
    For example: mc_mgrp_create 1
    """
    words = collections.deque(line.split())
    try:
      mgid = self.get_handle(words, "MGRP_ID")
      mgrp_hdl = self._thrift_client.mc_mgrp_create(mgid)
      print "MGRP has created with handle %d" % mgrp_hdl
    except NameError as ne:
      print >> sys.stderr, ne
    except thrift.protocol.TProtocol.TProtocolException as e:
      print >> sys.stderr, e
    except Exception as e:
      self.usage(e, "mc_mgrp_create")

  ## TODO - add multiple port and lag support
  def do_mc_node_create(self, line):
    """
    mc_node_create R_ID PORT_MAP LAG_MAP
    This function creates a multicast node with replication id R_ID and with list of ports defined by PORT_MAP (as a bit vector).
    Currently only port 0-7 can be configured with this function.
    For exmaple: mc_node_create 0 30 -1
    If PORT_MAP or LAG_MAP is -1, their value is not specified.
    """
    words = collections.deque(line.split())
    try:
      rid = self.get_handle(words, "R_ID")
      port_map = self.get_handle(words, "PORT_MAP")
      lag_map = self.get_handle(words, "LAG_MAP")
      if port_map != -1:
        ports = chr(port_map) + ('\x00' * 31)
      else:
        ports = '\x00' * 32
      if lag_map != -1:
        lags = chr(lag_map) + ('\x00' * 31)
      else:
        lags = '\x00' * 32
      l1_hdl = self._thrift_client.mc_node_create(rid, ports, lags)
      print "Node was created with handle %d" % l1_hdl
    except NameError as ne:
      print >> sys.stderr, ne
    except thrift.protocol.TProtocol.TProtocolException as e:
      print >> sys.stderr, e
    except Exception as e:
      self.usage(e, "mc_node_create")

  def do_mc_node_update(self, line):
    """
    mc_node_update L1_HDL PORT_MAP LAG_MAP
    This function updates a multicast node.
    Currently only port 0-7 can be configured with this function.
    For example: mc_node_update 1234321 14 -1
    """
    words = collections.deque(line.split())
    try:
      l1_hdl = self.get_handle(words, "L1_HDL")
      port_map = self.get_handle(words, "PORT_MAP")
      lag_map = self.get_handle(words, "LAG_MAP")
      if port_map != -1:
        ports = chr(port_map) + ('\x00' * 31)
      else:
        ports = '\x00' * 32
      if lag_map != -1:
        lags = chr(lag_map) + ('\x00' * 31)
      else:
        lags = '\x00' * 32
      self._thrift_client.mc_node_update(l1_hdl, ports, lags)
      print "Node has been updated."
    except NameError as ne:
      print >> sys.stderr, ne
    except thrift.protocol.TProtocol.TProtocolException as e:
      print >> sys.stderr, e
    except Exception as e:
      self.usage(e, "mc_node_update")

  def do_mc_mgrp_destroy(self, line):
    """
    mc_mgrp_destroy MGRP_HDL
    This function removes multcast group MGRP_HDL
    For example: mc_mgrp_destroy 1234321
    """
    words = collections.deque(line.split())
    try:
      mgrp_hdl = self.get_handle(words, "MGRP_HDL")
      self._thrift_client.mc_mgrp_destroy(mgrp_hdl)
      print "Multicast group has been destroyed."
    except NameError as ne:
      print >> sys.stderr, ne
    except thrift.protocol.TProtocol.TProtocolException as e:
      print >> sys.stderr, e
    except Exception as e:
      self.usage(e, "mc_mgrp_destroy")

  def do_mc_node_destroy(self, line):
    """
    mc_node_destroy L1_HDL
    This function removes node L1_HDL
    For example: mc_node_destroy 1234321
    """
    words = collections.deque(line.split())
    try:
      l1_hdl = self.get_handle(words, "L1_HDL")
      self._thrift_client.mc_l1_node_destroy(l1_hdl)
      print "Node has been destroyed."
    except NameError as ne:
      print >> sys.stderr, ne
    except thrift.protocol.TProtocol.TProtocolException as e:
      print >> sys.stderr, e
    except Exception as e:
      self.usage(e, "mc_node_destroy")

  def do_mc_associate_node(self, line):
    """
    mc_associate_node MGRP_HANDLE L1_HANDLE
    This function associates a node to a multicast tree.
    For example: mc_associate_node 1234321 1234567
    """
    words = collections.deque(line.split())
    try:
      mgrp_hdl = self.get_handle(words, "MGRP_HANDLE")
      l1_hdl = self.get_handle(words, "L1_HANDLE")
      self._thrift_client.mc_associate_node(mgrp_hdl, l1_hdl)
      print "Node has been associated to the multicast group"
    except NameError as ne:
      print >> sys.stderr, ne
    except thrift.protocol.TProtocol.TProtocolException as e:
      print >> sys.stderr, e
    except Exception as e:
      self.usage(e, "mc_associate_node")

  def do_mc_dissociate_node(self, line):
    """
    mc_dissociate_node MGRP_HANDLE L1_HANDLE
    This function dissociates a node from a multicast tree.
    For example: mc_dissociate_node 1234321 1234567
    """
    words = collections.deque(line.split())
    try:
      mgrp_hdl = self.get_handle(words, "MGRP_HANDLE")
      l1_hdl = self.get_handle(words, "L1_HANDLE")
      self._thrift_client.mc_associate_node(mgrp_hdl, l1_hdl)
      print "Node has been dissociated from the multicast group"
    except NameError as ne:
      print >> sys.stderr, ne
    except thrift.protocol.TProtocol.TProtocolException as e:
      print >> sys.stderr, e
    except Exception as e:
      self.usage(e, "mc_dissociate_node")

def main(argv):
  def usage():
    print >> sys.stderr, "pd_cli.py -s <colon separated list of directories to be added to Python's sys-path> -p <p4-name> -i <Python Thrift client module> -c <Thrift server>:<port>"
    sys.exit(2)
  # Add current directory to system path.
  sys.path.append(os.getcwd())
  thrift_server = 'localhost'
  port = 9090
  using_default_thrift_server_port = True
  thrift_client_module = "pd_thrift"
  using_default_thrift_client_module = True
  command = None
  p4_name = None
  try:
    opts, args = getopt.getopt(argv, "s:p:i:c:m:", ["--sys-path=", "--p4-name=", "import=", "connect=", "command="])
  except getopt.GetoptError:
    usage()

  for opt, arg in opts:
    if opt in ["-s", "--sys-path"]:
      sys.path.extend(arg.split(":"))
    elif opt in ["-p", "--p4-name"]:
      p4_name = arg
    elif opt in ["-i", "--import"]:
      thrift_client_module = arg
      using_default_thrift_client_module = False
    elif opt in ["-c", "--connect"]:
      using_default_thrift_server_port = False
      arg_list = arg.split(":")
      if len(arg_list) != 2:
        usage()
      thrift_server = arg_list[0]
      port = int(arg_list[1])
    elif opt in ["-m", "--command"]:
      command = arg
    else:
      print >> sys.stderr, "Invalid option", opt
      usage()

  if p4_name is None:
    print >> sys.stderr, "P4 name not given"
    sys.exit(1)

  if using_default_thrift_server_port is True:
    print >> sys.stderr, "Using default thrift server and port %s:%d" % (thrift_server, port)
  if using_default_thrift_client_module is True:
    print >> sys.stderr, "Using default thrift client module %s" % thrift_client_module

  try:
    pd_cli = PdCli(p4_name, thrift_client_module, thrift_server, port)
  except ImportError as ie:
    print >> sys.stderr, "ImportError:", ie
    sys.exit(1)

  if command is None:
    pd_cli.cmdloop()
  else:
    pd_cli.onecmd(command)


if __name__ == '__main__':
  main(sys.argv[1:])
