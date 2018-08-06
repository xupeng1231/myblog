from collections import defaultdict
import sys
import random
import operator
import binascii
import time
import itertools
import copy
import argparse
import copy
import os
from tqdm import tqdm
import z3
import base64
import subprocess

from contextlib import contextmanager
from os.path import getsize, basename

@contextmanager
def pbopen(filename, flags):
    total = getsize(filename)
    pb = tqdm(total=total, unit="B", unit_scale=True,
              desc=basename(filename), miniters=1)

    def wrapped_line_iterator(fd):
        processed_bytes = 0
        for line in fd:
            processed_bytes += len(line)
            # update progress every MB.
            if processed_bytes >= 1024 * 1024:
                pb.update(processed_bytes)
                processed_bytes = 0

            yield line

        # finally
        pb.update(processed_bytes)
        pb.close()

    with open(filename, flags) as fd:
        yield wrapped_line_iterator(fd)

def grouper(n, iterable, fillvalue=None):
    "grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)

def train_asm(asm, path='./rules/'):
    subprocess.call(['./engine.py', '--rule_path', path, '--save', asm])
    return

def train_bytes(byte_string, path='./rules/'):
    subprocess.call(['./engine.py', '--rule_path', path, '--save', '--bytes', byte_string])
    return

def dump_bytes(byte_string, path, myid):
    subprocess.call(['./engine.py', '--dump', path, '--dump_check', myid, '--bytes', byte_string])
    return

def generate_advrule(rule_path, new_path):
    subprocess.call(['./general_infer.py', rule_path, new_path])

def verify_command(data):
    info = data.split(':')
    if len(info) != 4 or info[0] != 'START' or info[3] != 'END':
        # handle error here
        pass
    command = info[1]
    bytestring = base64.b64decode(info[2])
    return (command, bytestring)

def prep_command(command, data):
    base64_data = base64.b64encode(data)
    command_string = 'START:{}:{}:END'.format(command, base64_data)
    assert(len(data) < 4069)
    return command_string

# TODO: All these classes should be shared with engine.py
def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.
    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).
    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes":True,   "y":True,  "ye":True,
             "no":False,     "n":False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")

class ProbeInfo(object):
    def __init__(self, def_val_bef, def_val_aft, use_val, ref_val):
        self.def_reg_before = def_val_bef
        self.def_reg_after = def_val_aft
        self.use_reg = use_val
        self.ref_reg = ref_val

    def __hash__(self):
        return hash(self.def_reg_after)

    def __eq__(self, other):
        return (self.def_reg_after == other.def_reg_after)

    def __ne__(self, other):
        return not(self == other)

class RegOutput(object):
    def __init__(self, use_reg=None, def_reg=None, change_mask=0, def_mask=0, fix_value=0, condition=None, use_mask2=None):

        # ZL: we'll create multiple def_masks for each use bit.
        self.use_mask2 = use_mask2

        self.use_reg = use_reg
        self.def_reg = def_reg
        self.condition = condition
        self.change_mask = change_mask
        self.def_mask = def_mask
        self.fix_value = fix_value
        if self.use_reg:
            self.use_val_str = '{{:0{}b}}'.format(use_reg.bits)
        else:
            self.use_val_str = ''
        self.def_val_str = '{{:0{}b}}'.format(def_reg.bits)

        self.interest_bits = None

    def __repr__(self):
        output_list = []
        output_list.append("Condition: {}".format(self.condition))
        if self.use_reg:
            output_list.append("USE_{0: <8} : {1}".format(self.use_reg.name, self.use_val_str.format(self.change_mask)))
        else:
            output_list.append("USE_{0: <8} : No src register.".format('None'))
        output_list.append("DEF_{0: <8} : {1}".format(self.def_reg.name, self.def_val_str.format(self.def_mask)))
        output_list.append("FIX_{0: <8} : {1}".format(self.def_reg.name, self.def_val_str.format(self.fix_value)))
        #output_list.append('')
        output_list.append('Use Breakdown')
        if self.use_mask2:
            for pos, val in enumerate(self.use_mask2):
                output_list.append('{: <3} : {}'.format(pos, self.def_val_str.format(val)))
        else:
            output_list.append('NONE!')
        return '\n'.join(output_list)

# create a simpler condition class for serialization
class SimpleCondition(object):
    def __init__(self, condition_info):
        self.reg = condition_info.reg
        self.cond_vals = copy.deepcopy(condition_info.cond_vals)

    def eval(self, val):
        for partition in self.cond_vals:
            for cond_val, cond_mask in self.cond_vals[partition]:
                if (val & cond_mask) == cond_val:
                    return partition
        print(self.cond_vals)
        raise Exception('Fulfill neither True nor False')

class ConditionInfo(object):
    def __init__(self, reg=None, conditions=None):
        self.reg = reg
        self.conditions = conditions
        self.cond_vals = {}
        self.repr_str = ""
        if reg and conditions:
            # we assume that all cond masks are the same
            assert(len({x for x, _ in conditions}) < 5)
            self.val_str = '{{:0{}b}}'.format(reg.bits)
            self.repr_str = '{}'.format(self.reg.name)
            for cond_mask, cond_val in self.conditions:
                self.repr_str = '{} {} {}'.format(self.repr_str, self.val_str.format(cond_mask), self.val_str.format(cond_val))
            self.cond_vals[True] = self.gen_conds(True)
            self.cond_vals[False] = self.gen_conds(False)
            print('True')
            print(self.cond_vals[True])
            print('False')
            print(self.cond_vals[False])

    def evaluate(self, cpu_state):
        if not self.conditions:
            return True
        return self.eval_val(cpu_state[self.reg])

    def eval_val(self, value):
        if not self.conditions:
            return True
        # evaluate if value is true or false based on the condition
        result = False
        # evaluation result is the logical all of all the conditions
        for condition_mask, condition_value in self.conditions:
            result |= (value & condition_mask) == condition_value
        return result
    
    def gen_conds(self, partition, blacklist=[], max_runs=256):
        # use z3 to generate results
        solver = blog1.z3.Solver()
        x = blog1.z3.BitVec('x', self.reg.bits)
        z3conds_raw_set = defaultdict(set)
        z3conds_set = defaultdict(set)
        cond_set = set()
        temp_cond = 0
        for cond_mask, _ in self.conditions:
            if partition:
                cond_set.add(cond_mask)
            else:
                temp_cond |= cond_mask

        if partition:
            for cond_mask, cond_val in self.conditions:
                z3conds_raw_set[cond_mask].add((x & cond_mask == cond_val, x & ~cond_mask == 0b0))
        else:
            temp_cond = 0
            for cond_mask, _ in self.conditions:
                temp_cond |= cond_mask
            for cond_mask, cond_val in self.conditions:
                z3conds_raw_set[temp_cond].add((x & cond_mask == cond_val, x & ~cond_mask == 0b0))


        for cond_mask in z3conds_raw_set:
            if partition:
                z3conds = [blog1.z3.And(a, b) for a, b in z3conds_raw_set[cond_mask]]
                z3conds_set[cond_mask] = blog1.z3.Or(*z3conds)
            else:
                neg_z3conds = [blog1.z3.And(blog1.z3.Not(a), b) for a, b in z3conds_raw_set[cond_mask]]
                z3conds_set[cond_mask] = blog1.z3.And(*neg_z3conds)

        values = set()
        for cond_mask in z3conds_set:
            print(partition, z3conds_set[cond_mask])
            solver.add(z3conds_set[cond_mask])
            for count in range(max_runs):
                if solver.check() == blog1.z3.sat:
                    value = solver.model()[x]
                    check_val = value.as_long()
                    values.add((check_val, cond_mask))
                    solver.add(x != value)
                else:
                    break
                if count == max_runs - 1:
                    raise Exception('Max tries for conditional value reached!')
            solver.reset()
        return values
    
    def apply_cond(self, value, partition):
        part_cond, cond_mask = random.sample(self.cond_vals[partition], 1)[0]
        return value & ~cond_mask | part_cond

    def __hash__(self):
        return hash(self.repr_str)

    def __eq__(self, other):
        return (self.repr_str == other.repr_str)

    def __ne__(self, other):
        return not(self == other)

    def __repr__(self):
        out_str = []
        out_str.append("-"*80)
        out_str.append("Conditional Register: {}".format(self.reg.name))
        output = "Conditional Register: {}".format
        for cond_mask, cond_val in self.conditions:
            out_str.append("COND_MASK  : {}".format(self.val_str.format(cond_mask)))
            out_str.append("COND_VALUE : {}".format(self.val_str.format(cond_val)))
        out_str.append("-"*80)
        output = "\n".join(out_str)
        return output
#end TODO: share objects with engine.py
