# Copyright 2021 Google LLC
# Copyright 2021 Fraunhofer FKIE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""This module provides the instrumentation functionality for atheris.

Mainly the funprint_cfg()patch_code(), which can instrument a code object and the
helper class Instrumentor.
"""

import os
import sys
import types
import importlib
import dis
import ast
import networkx as nx
from collections import OrderedDict
from .native import _reserve_counters
from . import utils

from .version_dependent import get_code_object, get_lnotab, CONDITIONAL_JUMPS, UNCONDITIONAL_JUMPS, ENDS_FUNCTION, HAVE_REL_REFERENCE, HAVE_ABS_REFERENCE, REVERSE_CMP_OP, CALLS_FUNCTION

current_index = 0
current_pc = 0

TARGET_MODULE = "atheris"
REGISTER_FUNCTION = "_reserve_counters"
COVERAGE_FUNCTION = "_trace_branch"
COMPARE_FUNCTION = "_trace_cmp"
CFG_COVERAGE = "_trace_cf"

def read_func_calls():
  with open('/home/ubuntu/atheris/data/data.txt') as f:
    data = ast.literal_eval(f.read())
    final_dict = {}
    for ele in data:
      for key in ele:
        final_dict[key] = ele[key]
    return final_dict
def read_fltd():
  with open('/home/ubuntu/atheris/data/fltd.txt') as f:
    return ast.literal_eval(f.read())



FLTD = read_fltd()
FUNC_CALLS = read_func_calls()
TARGET_FUNC = "33: f3()"
second_bb_id = 0

class Instruction:
  """
    This class represents a single instruction after every
    EXTENDED_ARG has been resolved in the bytecode.
    It is assumed that all instructions are always 2*n bytes long.
    Sometimes the Python-Interpreter pads instructions with
    'EXTENDED_ARG 0' so instructions must have a minimum size.
    """

  @classmethod
  def get_fixed_size(cls):
    return 2

  def __init__(self, lineno, offset, opcode, arg=None, min_size=None):
    self.lineno = lineno
    self.offset = offset
    self.opcode = opcode
    self.mnemonic = dis.opname[opcode]

    if arg is None:
      self.arg = 0
    else:
      self.arg = arg

    if min_size is not None:
      self._min_size = min_size
    else:
      self._min_size = 0

    if self.mnemonic in HAVE_REL_REFERENCE:
      self._is_relative = True
      self.reference = self.offset + self.get_size() + self.arg
    elif self.mnemonic in HAVE_ABS_REFERENCE:
      self._is_relative = False
      self.reference = self.arg
    else:
      self._is_relative = None
      self.reference = None

    self.check_state()

  def has_argument(self):
    return self.opcode >= dis.HAVE_ARGUMENT

  def _get_arg_size(self):
    if self.arg >= (1 << 24):
      return 8
    elif self.arg >= (1 << 16):
      return 6
    elif self.arg >= (1 << 8):
      return 4
    else:
      return 2

  def get_size(self):
    return max(self._get_arg_size(), self._min_size)

  def get_stack_effect(self):
    # dis.stack_effect does not work for EXTENDED_ARG and NOP
    if self.mnemonic in ["EXTENDED_ARG", "NOP"]:
      return 0

    return dis.stack_effect(self.opcode,
                            (self.arg if self.has_argument() else None))

  def to_bytes(self):
    size = self._get_arg_size()
    arg = self.arg
    ret = [self.opcode, arg & 0xff]

    for _ in range(size // 2 - 1):
      arg >>= 8
      ret = [dis.opmap["EXTENDED_ARG"], arg & 0xff] + ret

    while len(ret) < self._min_size:
      ret = [dis.opmap["EXTENDED_ARG"], 0] + ret

    assert (len(ret) == self.get_size())

    return bytes(ret)

  def adjust(self, changed_offset, size, keep_ref):
    """
        This function can be used to signal two different events:
            (1) Insertion of instructions
            (2) Change of size of a single, already existing instruction

        (1) Signal this instruction that some instructions of size
            `size` (in bytes) have been inserted at offset `changed_offset`
            in the instruction listing.

        (2) Signal this instruction that an instruction at offset
        `changed_offset` - 0.5
            has increased in size. If `changed_offset` is self.offset + 0.5,
            this
            instruction increased in size.

        Either way, adjust the current offset, reference and argument
        accordingly.
        """
    old_offset = self.offset
    old_reference = self.reference
    old_size = self.get_size()

    if old_offset < changed_offset < (old_offset + 1):
      if old_reference is not None:
        if self._is_relative:
          self.reference += size
        elif old_reference > old_offset:
          self.reference += size
          self.arg += size

      return

    if changed_offset <= old_offset:
      self.offset += size

    if old_reference is not None and not keep_ref:
      if changed_offset <= old_reference:
        self.reference += size

      if self._is_relative:
        if old_offset < changed_offset <= old_reference:
          self.arg += size
      else:
        if changed_offset <= old_reference:
          self.arg += size

  def check_state(self):
    assert (self.mnemonic != "EXTENDED_ARG")
    assert (0 <= self.arg <= 0x7fffffff)
    assert (0 <= self.opcode < 256)

    if self.reference is not None:
      if self._is_relative:
        assert (self.offset + self.get_size() + self.arg == self.reference)
      else:
        assert (self.arg == self.reference)

  def is_jump(self):
    return self.mnemonic in CONDITIONAL_JUMPS or self.mnemonic in UNCONDITIONAL_JUMPS

  def make_nop(self):
    self.opcode = dis.opmap["NOP"]
    self.mnemonic = "NOP"
    self.arg = 0
    self._is_relative = None
    self.reference = None
    self.check_state()


class BasicBlock:

  def __init__(self, instructions, last_one):
    global second_bb_id
    self.second_id = second_bb_id
    second_bb_id += 1
    self.instructions = instructions
    self.id = instructions[0].offset
    self.calls_func= 0
    self.call_lines=[]
    self.call_names = []
    last_instr = instructions[-1]
    for inst in instructions:
        if inst.mnemonic in CALLS_FUNCTION:
            self.calls_func=1
            self.call_lines.append(inst.lineno)

            #print(inst.lineno,inst.mnemonic)
    #print(CALLS_FUNCTION)
    if last_one or last_instr.mnemonic in ENDS_FUNCTION:
      self.edges = []
    elif last_instr.mnemonic in CONDITIONAL_JUMPS:
      self.edges = list(
          set([last_instr.reference,
               last_instr.offset + last_instr.get_size()]))
    else:
      if last_instr.reference is not None:
        self.edges = [last_instr.reference]
      else:
        self.edges = [last_instr.offset + last_instr.get_size()]


    
  def __iter__(self):
    return iter(self.instructions)

  def __repr__(self):
    return f"BasicBlock(id={self.id}, edges={self.edges})"




global_ids = {}
total_counters = 0
dic = {}
class Instrumentor:
  """
    This class implements the core instrumentation functionality.
    It gets a single code object, builds a CFG of the bytecode and
    can instrument the code for coverage collection via trace_control_flow()
    and for data-flow tracing via trace_data_flow().

    How to insert code:
        1. Select a target basic block
        2. Build up the new code as a list of `Instruction` objects.
           Make sure to get the offsets right.
        3. Calculate the overall size needed by your new code (in bytes)
        4. Call _adjust() with your target offset and calculated size
        5. Insert your instruction list into the instruction list of the basic
        block
        6. Call _handle_size_changes()
    Take a look at trace_control_flow() and trace_data_flow() for examples.

    Note that Instrumentor only supports insertions, not deletions.
    """

  def __init__(self, code, start_idx, start_pc):
    self._start_idx = start_idx
    self._start_pc = start_pc
    self._cfg = OrderedDict()
    self.consts = list(code.co_consts)
    self._names = list(code.co_names)
    self.num_counters = 0
    self.num_pcs = 0
    self._changes = []
    self._code = code
    self.path_info = {}
    self.dist_info = {}
    self.fun_calling_bb = []
    self._build_cfg()
    self._check_state()
    #self.print_cfg()

  def print_cfg(self):
    print(f"Disassembly of {self._code.co_filename}:{self._code.co_name}\n")
    for i, basic_block in enumerate(self._cfg.values()):
      if i > 5:
        break;
      else:
        print(" -bb- ",basic_block.id,basic_block.second_id)
        for instr in basic_block:
          print(f" L.{instr.lineno}  [{instr.offset}]  {instr.mnemonic} ", end="")

          if instr.has_argument():
            print(f"{instr.arg} ", end="")

            if instr._is_relative:
              print(f"(to {instr.reference})", end="")
          print()
        if basic_block.calls_func:
            print("This basic block calls a function")
      print(f"Edges from BB {basic_block.id} -> {basic_block.edges}\n")


  def calculate_bb_dist(self):
    G=nx.DiGraph()
    fun_calling_bb = []
    #print(self._code.co_filename.split('/')[-1])
    #print(func_calls)
    for i, basic_block in enumerate(self._cfg.values()):
      G.add_node(basic_block.id);

    
    nx.set_node_attributes(G,0,name="calls_function")
    nx.set_node_attributes(G,[],name="call_lines")
    nx.set_node_attributes(G,[],name="called_funcs")

    for i, basic_block in enumerate(self._cfg.values()):
      if basic_block.calls_func:
        G.nodes[basic_block.id]["calls_function"] = 1
        G.nodes[basic_block.id]["call_lines"] = basic_block.call_lines
        for ele in basic_block.call_lines:
          key = ""
          print(self._code.co_filename,ele)
          try:
            for each_func in FUNC_CALLS[self._code.co_filename][str(ele)]:
              fun_key =": " +each_func +"()"
              for k in FLTD.keys():
              #print(fun_key,k)
                if fun_key in k:
                  key = k
                  break

              if key != "" and FLTD[key] > -1 or key == TARGET_FUNC:
                basic_block.call_names.append(key)
          except:
            try:
              for each_func in FUNC_CALLS[self._code.co_filename.split('/')[-1]][str(ele)]:
                fun_key =": " +each_func +"()"
                for k in FLTD.keys():
              #print(fun_key,k)
                  if fun_key in k:
                    key = k
                    break

                if key != "" and FLTD[key] > -1 or key == TARGET_FUNC:
                  basic_block.call_names.append(key)
            except:
              None
              #print("Call names",basic_block.id,key)
        fun_calling_bb.append(basic_block.id)
      if len(basic_block.edges) > 0:
          for ele in basic_block.edges:
            G.add_edge(basic_block.id,ele)
    for bb in self._cfg.values():
        #print(bb.id,bb.call_names)
        for ele in self._cfg.values():
          self.path_info[(bb.second_id,ele.second_id)] = []
          self.dist_info[(bb.second_id,ele.second_id)] = -1
          try:
            self.path_info[(bb.second_id,ele.second_id)] = nx.shortest_path(G,source=bb.id, target=ele.id)
            self.dist_info[(bb.second_id,ele.second_id)] = nx.shortest_path_length(G,source=bb.id, target=ele.id)
            #print(path_info[(bb,ele)])
          except Exception as e:
            #print(e)
            continue
    self.fun_calling_bb = fun_calling_bb
    #print("BB_DISTance",self.dist_info,fun_calling_bb)

  def bbtd(self,CG_fltd,call_info):
    call_chain_fun = []
    current_blocks = []
    filename = self._code.co_filename.split('/')[-1]
    if filename not in dic:
      dic[filename] = {}

    for bb in self._cfg.values():
        sum =0
        if bb.calls_func and TARGET_FUNC in bb.call_names or self._code.co_name in TARGET_FUNC:
          print("Target Fun Filename bb.id bb.second_id",filename,bb.id,bb.second_id)
          dic[filename][bb.second_id] = (0,bb.id)
          current_blocks.append(bb.id)
          continue
        elif bb.calls_func:
          min =99999999
          key= ""
          for ele in bb.call_names:
            if CG_fltd[ele] < min and CG_fltd[ele] > -1:
                min = CG_fltd[ele]
                print("Reachable Fun Filename bb.id bb.second_id",filename,bb.id,bb.second_id,min)
          sum = min;

          if sum != 99999999:
            dic[filename][bb.second_id] = (10 * sum,bb.id)
            current_blocks.append(bb.id)
    good_vals = dic[filename].keys()
    #print(current_blocks,good_vals)
    for bb in self._cfg.values():
      sum = 0
      if bb.second_id not in good_vals:
        for ele in current_blocks:
          print("Good values",good_vals,bb.second_id)
          if (bb.second_id,self._cfg[ele].second_id) in self.dist_info and self.dist_info[(bb.second_id,self._cfg[ele].second_id)] > -1:
            sum += 1 /(self.dist_info[(bb.second_id,self._cfg[ele].second_id)] + dic[filename][self._cfg[ele].second_id][0])
        if sum > 0:
          sum = 1/sum
        else:
          sum = 99999999
        dic[filename][bb.second_id] = (sum,bb.id)
      print("BBTD",dic)
        

    """
      if sum == 0 or sum == 99999999:
          #print(self.fun_calling_bb)
          for ele in self.fun_calling_bb:
            for func in self._cfg[ele].call_names:
              for func in CG_fltd.keys():
                if key in k:
                  key = k
                  break;
              try:
                sum = sum + (1 / (self.dist_info[(bb,ele)] + 10 * CG_fltd[key]))
              except:
                sum = sum
        dic[bb.id] = sum
    """
    #print("-------------Basic Block level Target Distance---------")
    #print(dic,self.fun_calling_bb,self.dist_info)

  
  def _build_cfg(self):

    lineno = self._code.co_firstlineno
    arg = None
    offset = None
    length = Instruction.get_fixed_size()
    instr_list = []
    basic_block_borders = []
    did_jump = False
    jump_targets = set()

    for instruction in dis.get_instructions(self._code):
      if instruction.starts_line is not None:
        lineno = instruction.starts_line

      if instruction.opname == "EXTENDED_ARG":
        if arg is None:
          arg = 0
          offset = instruction.offset

        arg <<= 8
        arg |= instruction.arg
        length += Instruction.get_fixed_size()

        continue

      elif arg is not None:
        instr_list.append(
            Instruction(
                lineno,
                offset,
                instruction.opcode, (arg << 8) | instruction.arg,
                min_size=length))
        arg = None
        offset = None
        length = Instruction.get_fixed_size()

      else:
        instr_list.append(
            Instruction(lineno, instruction.offset, instruction.opcode,
                        instruction.arg))

      if instr_list[-1].reference is not None:
        jump_targets.add(instr_list[-1].reference)

    for c, instr in enumerate(instr_list):
      if instr.offset == 0 or instr.offset in jump_targets or did_jump:
        basic_block_borders.append(c)

      if instr.is_jump():
        did_jump = True
      else:
        did_jump = False

    basic_block_borders.append(len(instr_list))

    for i in range(len(basic_block_borders) - 1):
      start_of_bb = basic_block_borders[i]
      end_of_bb = basic_block_borders[i + 1]
      bb = BasicBlock(instr_list[start_of_bb:end_of_bb],
                      i == len(basic_block_borders) - 2)
      self._cfg[bb.id] = bb
     # print(bb.id,bb.edges)
    
    #print(self._cfg[0])
    self.print_cfg()
    #self.calculate_bb_dist()
    

  def _check_state(self):
    assert (len(self._cfg) > 0)
    seen_ids = set()

    for basic_block in self._cfg.values():
      assert (len(basic_block.instructions) > 0)

      assert (basic_block.id not in seen_ids)
      seen_ids.add(basic_block.id)

      for edge in basic_block.edges:
        assert (edge in self._cfg)

    listing = self._get_linear_instruction_listing()
    i = 0

    assert (listing[0].offset == 0)

    while i < len(listing) - 1:
      assert (listing[i].offset + listing[i].get_size() == listing[i +
                                                                   1].offset)
      listing[i].check_state()
      i += 1

  def _get_name(self, name):
    """
        Get an offset into the co_names list or
        create a new entry if `name` is not found.
        """
    try:
      return self._names.index(name)
    except ValueError:
      self._names.append(name)
      return len(self._names) - 1

  def _get_const(self, constant):
    """
        Get an offset into the co_consts list or
        create a new entry if `const` is not found.
        """
    for i in range(len(self.consts)):
      if type(self.consts[i]) == type(constant) and self.consts[i] == constant:
        return i

    self.consts.append(constant)
    return len(self.consts) - 1

  def _get_counter(self):
    counter = self._start_idx + self.num_counters
    self.num_counters += 1
    global total_counters
    total_counters = counter
    to_ret =  self._get_const(counter)

    #print("Assigned ID : ",counter)    
    return to_ret

  def _get_pc(self):
    pc = self._start_pc + self.num_pcs
    self.num_pcs += 1
    return self._get_const(pc)

  def _adjust(self, offset, size, *keep_refs):
    """
        Signal all instructions that some instructions of size
        `size` (in bytes) will be inserted at offset `offset`.
        Sometimes it is necessary that some instructions do not
        change their reference when a new insertion happens.
        All those Instruction-objects whose reference shall not change
        must be in `keep_refs`.
        """
    for basic_block in self._cfg.values():
      for instr in basic_block:
        instr.adjust(offset, size, instr in keep_refs)

  def _handle_size_changes(self):
    """
        After insertions have been made it could be that the argument
        of some instructions crossed certain boundaries so that more
        EXTENDED_ARGs are required to build the oparg.
        This function identifies all of those instructions whose size increased
        with the latest insertion and adjusts all other instruction to the
        new size.
        """
    listing = self._get_linear_instruction_listing()

    while True:
      found_invalid = False
      i = 0

      while i < len(listing) - 1:
        next_offset = listing[i].offset + listing[i].get_size()

        if next_offset < listing[i + 1].offset:
          raise Exception(
              f"Something weird happened with the offsets at offset {listing[i].offset}"
          )

        elif next_offset > listing[i + 1].offset:
          delta = next_offset - listing[i + 1].offset
          self._adjust(listing[i].offset + 0.5, delta)
          found_invalid = True

        i += 1

      if not found_invalid:
        break

  def _get_linear_instruction_listing(self):
    listing = []
    for basic_block in self._cfg.values():
      for instr in basic_block:
        listing.append(instr)
    return listing

  def to_code(self):
    self._check_state()
    listing = self._get_linear_instruction_listing()
    code = bytes()
    stacksize = 0

    for instr in listing:
      code += instr.to_bytes()
      stacksize = max(stacksize, stacksize + instr.get_stack_effect())

    return get_code_object(self._code, stacksize, code,
                           tuple(self.consts + ["__ATHERIS_INSTRUMENTED__"]),
                           tuple(self._names), get_lnotab(self._code, listing))

  def _generate_trace_branch_invocation(self, lineno, offset,bb_id=None):
    """
        Builds the bytecode that calls atheris._trace_branch()
        """
    to_insert = []
    start_offset = offset
    const_atheris = self._get_const(sys.modules[TARGET_MODULE])
    #print(self.consts,self._get_counter());
    #print("Instrumenting BB",bb_id)
    name_cov = self._get_name(COVERAGE_FUNCTION)
    global total_counters
    counter = self._get_counter()
   # total_counters.append(bb_id)
    filename = self._code.co_filename
    filename = self._code.co_filename.split('/')[-1]
    #print("Filename",filename)
    #print("counter vs my counter",counter,total_counters)
    if filename in global_ids.keys():
        global_ids[filename][bb_id] = total_counters
    else:
        global_ids[filename] = {}
        global_ids[filename][bb_id] = total_counters

    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"], const_atheris))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_ATTR"], name_cov))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"],
                    counter))
    offset += to_insert[-1].get_size()
    to_insert.append(Instruction(lineno, offset, dis.opmap["CALL_FUNCTION"], 1))
    offset += to_insert[-1].get_size()
    to_insert.append(Instruction(lineno, offset, dis.opmap["POP_TOP"]))
    offset += to_insert[-1].get_size()

    return offset - start_offset, to_insert
  def _generate_bb_tracker(self, lineno, offset,bb_id=None):
    """
        Builds the bytecode that calls atheris._trace_branch()
        """
    to_insert = []
    start_offset = offset
    const_atheris = self._get_const(sys.modules[TARGET_MODULE])
    name_cov = self._get_name(CFG_COVERAGE)

    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"], const_atheris))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_ATTR"], name_cov))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"],
                bb_id))
    offset += to_insert[-1].get_size()
    to_insert.append(Instruction(lineno, offset, dis.opmap["CALL_FUNCTION"], 1))
    offset += to_insert[-1].get_size()
    to_insert.append(Instruction(lineno, offset, dis.opmap["POP_TOP"]))
    offset += to_insert[-1].get_size()

    return offset - start_offset, to_insert


  def _generate_cmp_invocation(self, op, lineno, offset):
    """
        Builds the bytecode that calls atheris._trace_cmp().
        Only call this if the two objects being compared are non-constants.
        """
    to_insert = []
    start_offset = offset
    const_atheris = self._get_const(sys.modules[TARGET_MODULE])
    name_cmp = self._get_name(COMPARE_FUNCTION)
    const_op = self._get_const(op)
    const_pc = self._get_pc()
    const_False = self._get_const(False)

    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"], const_atheris))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_ATTR"], name_cmp))
    offset += to_insert[-1].get_size()
    to_insert.append(Instruction(lineno, offset, dis.opmap["ROT_THREE"]))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"], const_op))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"], const_pc))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"], const_False))
    offset += to_insert[-1].get_size()
    to_insert.append(Instruction(lineno, offset, dis.opmap["CALL_FUNCTION"], 5))
    offset += to_insert[-1].get_size()

    return offset - start_offset, to_insert

  def _generate_const_cmp_invocation(self, op, lineno, offset, switch):
    """
        Builds the bytecode that calls atheris._trace_cmp().
        Only call this if one of the objects being compared is a constant
        coming from co_consts.
        If `switch` is true the constant is the second argument and needs
        to be switched with the first argument.
        """
    to_insert = []
    start_offset = offset
    const_atheris = self._get_const(sys.modules[TARGET_MODULE])
    name_cmp = self._get_name(COMPARE_FUNCTION)
    const_pc = self._get_pc()
    const_True = self._get_const(True)
    const_op = None

    if switch:
      const_op = self._get_const(REVERSE_CMP_OP[op])
    else:
      const_op = self._get_const(op)

    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"], const_atheris))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_ATTR"], name_cmp))
    offset += to_insert[-1].get_size()
    to_insert.append(Instruction(lineno, offset, dis.opmap["ROT_THREE"]))
    offset += to_insert[-1].get_size()

    if switch:
      to_insert.append(Instruction(lineno, offset, dis.opmap["ROT_TWO"]))
      offset += to_insert[-1].get_size()

    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"], const_op))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"], const_pc))
    offset += to_insert[-1].get_size()
    to_insert.append(
        Instruction(lineno, offset, dis.opmap["LOAD_CONST"], const_True))
    offset += to_insert[-1].get_size()
    to_insert.append(Instruction(lineno, offset, dis.opmap["CALL_FUNCTION"], 5))
    offset += to_insert[-1].get_size()

    return offset - start_offset, to_insert

  def trace_control_flow(self):
    """
        Insert a call to atheris._trace_branch() in every basic block that
        is a target of a branch. The argument of _trace_branch() is an id for
        the branch.

        The following bytecode gets inserted:
          LOAD_CONST     atheris
          LOAD_ATTR      _trace_branch
          LOAD_CONST     <id>
          CALL_FUNCTION  1
          POP_TOP                  ; _trace_branch() returns None, remove the
          return value
        """
    already_instrumented = set()

    offset = self._cfg[0].instructions[0].offset
    total_size, to_insert = self._generate_trace_branch_invocation(
        self._cfg[0].instructions[0].lineno, offset,self._cfg[0].second_id)
    self._adjust(offset, total_size)
    self._cfg[0].instructions = to_insert + self._cfg[0].instructions

    for basic_block in self._cfg.values():
      if len(basic_block.edges) == 2:
        for edge in basic_block.edges:
          bb = self._cfg[edge]

          if bb.id not in already_instrumented:
            already_instrumented.add(bb.id)
            source_instr = []
            offset = bb.instructions[0].offset

            for source_bb in self._cfg.values():
              if bb.id in source_bb.edges and source_bb.instructions[
                  -1].reference == offset:
                source_instr.append(source_bb.instructions[-1])
            total_size, to_insert = self._generate_trace_branch_invocation(
                bb.instructions[0].lineno, offset,bb.second_id)

            self._adjust(offset, total_size, *source_instr)

            bb.instructions = to_insert + bb.instructions

    self._handle_size_changes()

  def trace_data_flow(self):
    """
        This function instruments bytecode for data-flow tracing.
        This works by replacing the instruction COMPARE_OP with
        a call to atheris._trace_cmp().
        The arguments for _trace_cmp() are as follows:
            - obj1 and obj2: The two values to compare
            - opid: argument to COMPARE_OP
            - pc: a counter for how many COMPARE_OPs have been replaced
            - is_const: whether obj1 is a constant in co_consts.
        To detect if any of the values being compared is a constant, all push
        and pop operations
        have to be analyzed. If a constant appears in a comparison it must
        always be given as obj1 to _trace_cmp().

        The bytecode that gets inserted looks like this:
          LOAD_CONST     atheris
          LOAD_ATTR      _trace_cmp
          ROT_THREE                   ; move atheris._trace_cmp below the two
          objects
          LOAD_CONST     <opid>
          LOAD_CONST     <pc>
          LOAD_CONST     <is_const>
          CALL_FUNCTION  5
        """
    stack_size = 0
    seen_consts = []

    for basic_block in self._cfg.values():
      for c, instr in enumerate(basic_block.instructions):
        if instr.mnemonic == "LOAD_CONST":
          seen_consts.append(stack_size)
        elif instr.mnemonic == "COMPARE_OP" and instr.arg <= 5:
          # Determine the two values on the top of the stack when COMPARE_OP happens
          consts_on_stack = list(
              filter(lambda x: stack_size - 2 <= x < stack_size, seen_consts))
          tos_is_constant = stack_size - 1 in consts_on_stack
          tos1_is_constant = stack_size - 2 in consts_on_stack

          if not (tos_is_constant and tos1_is_constant):
            offset = instr.offset
            total_size = None
            to_insert = None

            # Both items are non-constants
            if (not tos_is_constant) and (not tos1_is_constant):
              total_size, to_insert = self._generate_cmp_invocation(
                  instr.arg, instr.lineno, offset)

            # One item is constant, one is non-constant
            else:
              total_size, to_insert = self._generate_const_cmp_invocation(
                  instr.arg, instr.lineno, offset, tos_is_constant)

            self._adjust(offset, total_size)

            for i, new_instr in enumerate(to_insert):
              basic_block.instructions.insert(c + i, new_instr)

            instr.make_nop()

        stack_size += instr.get_stack_effect()
        seen_consts = list(filter(lambda x: x < stack_size, seen_consts))

    self._handle_size_changes()

  def _dis(self):
    print(f"Disassembly of {self._code.co_filename}:{self._code.co_name}")
    for basic_block in self._cfg.values():
      print(" -bb-")
      for instr in basic_block:
        print(f" L.{instr.lineno}  [{instr.offset}]  {instr.mnemonic} ", end="")

        if instr.has_argument():
          print(f"{instr.arg} ", end="")

          if instr._is_relative:
            print(f"(to {instr.reference})", end="")

        print()


def patch_code(code, trace_dataflow, nested=False):
  """
    This function takes an uninstrumented code object
    of a module and instruments it including all nested
    code objects.
    """
  global current_index, current_pc

  old_index = current_index

  inst = Instrumentor(code, current_index, current_pc)

  # If this code object has already been instrumented, skip it
  if "__ATHERIS_INSTRUMENTED__" in inst.consts:
    return code
  
  #print("-----------Function level target distance--------")
  #print(FLTD)
  #print("-----------Call lines------------------")
  #print(FUNC_CALLS)
  inst.calculate_bb_dist()
  #print(inst._code.co_filename.split('/'))
  try:
    inst.bbtd(FLTD,FUNC_CALLS[inst._code.co_filename])
  except:
    inst.bbtd(FLTD,FUNC_CALLS[inst._code.co_filename.split('/')[-1]])

  #print("Before\n");
  #inst._dis();
  inst.trace_control_flow();
  print(global_ids)
  #print("After\n");
  #inst._dis();

  if trace_dataflow:
    inst.trace_data_flow()

  current_index += inst.num_counters
  current_pc += inst.num_pcs

  # Repeat this for all nested code objects
  for i in range(len(inst.consts)):
    if isinstance(inst.consts[i], types.CodeType):
      if (inst.consts[i].co_name
          in ["<lambda>", "<module>" if not nested else None] or
          inst.consts[i].co_name[0] != "<" or
          inst.consts[i].co_name[-1] != ">"):
        inst.consts[i] = patch_code(inst.consts[i], trace_dataflow, nested=True)

  if not nested:
    #inst.bbtd(FLTD,FUNC_CALLS[inst._code.co_filename.split('/')[-1]])
    #print(inst.global_ids)
    _reserve_counters(current_index - old_index)
   # print("Reserved :" , current_index - old_index)
  return inst.to_code()


def instrument_func(func):
  """Add Atheris instrumentation to a specific function."""
  old_index = current_index

  func.__code__ = patch_code(func.__code__, True, True)
  _reserve_counters(current_index - old_index)
  #print("Reserved :" , current_index - old_index)
  
  #print("*****Global IDs",global_ids)
  new_dic = {}
  for ele in dic.keys():
    for ele2 in dic[ele].keys():
      new_dic[global_ids[ele][ele2]] = dic[ele][ele2][0]
  print("Final dict",new_dic)
  f=open("dict.txt","w")
  for ele in new_dic:
    f.write(str(ele)+":"+str(new_dic[ele])+"\n")
  f.close()
  return func


def _is_instrumentable(obj):
  """Returns True if this object can be instrumented."""
  try:
    # Only callables can be instrumented
    if not hasattr(obj, "__call__"):
      return False
    # Only objects with a __code__ member of type CodeType can be instrumented
    if not hasattr(obj, "__code__"):
      return False
    if not isinstance(obj.__code__, types.CodeType):
      return False
    # Only code in a real module can be instrumented
    if not hasattr(obj, "__module__"):
      return False
    if obj.__module__ not in sys.modules:
      return False
    # Bound methods can't be instrumented - instrument the real func instead
    if hasattr(obj, "__self__"):
      return False
    # Only Python functions and methods can be instrumented, nothing native
    if (not isinstance(obj, types.FunctionType)) and (not isinstance(
        obj, types.MethodType)):
      return False
  except Exception:
    # If accessing any of those fields produced an exception, the object
    # probably can't be instrumented
    return False

  return True

def instrument_all():
  """Add Atheris instrementation to all Python code already imported.

  This function is experimental.

  This function is able to instrument core library functions that can't be
  instrumented by instrument_func or instrument_imports, as those functions are
  used in the implementation of the instrumentation.
  """
  import gc

  progress_renderer = None

  function_call_lines = read_func_calls()

  funcs = [obj for obj in gc.get_objects() if _is_instrumentable(obj)]
  if sys.stderr.isatty():
    sys.stderr.write(f"INFO: Instrumenting functions: ")
    progress_renderer = utils.ProgressRenderer(sys.stderr, len(funcs))
  else:
    sys.stderr.write(f"INFO: Instrumenting {len(funcs)} functions...\n")

  for i in range(len(funcs)):
    func = funcs[i]
    #print(func)
   # print("*****Global IDs",global_ids)
    exit()
    try:
      instrument_func(func)
      #print(func)
    except Exception as e:
      if progress_renderer:
        progress_renderer.drop()
      sys.stderr.write(f"ERROR: Failed to instrument function {func}: {e}\n")
    if progress_renderer:
      progress_renderer.count = i + 1
  if progress_renderer:
    progress_renderer.drop()
  else:

    print("INFO: Instrumentation complete.")
