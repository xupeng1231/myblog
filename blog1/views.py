from django.shortcuts import render

import cPickle as pickle
from isa.isa import *
from isa.x86_registers import *
from isa.x86 import *
from common import *
from capstone import *

archs = ["X86","AMD","ARM","XXX","YYY"]


def index(request):
    return render(request,"index.html",{"archs":archs})

def search(request):
    insn=request.GET["insn"]
    insn_arch=request.GET["insn_arch"]
    return render(request, "index.html",
                  {"archs": archs,
                   "info": "ABC " * 100,
                   "insn_str":"["+insn+"  ;;;;"+insn_arch+"]"})


def graph(path):
    uses,conditions=pickle.load(open(path,"rb"))
    graphs=[]
    for use in uses:
        if use.def_reg and use.use_reg and use.use_mask2:
            graph=[(use.use_reg.name,use.use_reg.bits),(use.def_reg.name,use.def_reg.bits)]
            pairs=[]
            for pos,mask in enumerate(use.use_mask2):
                pairs.extend(itertools.product((pos,),filter(lambda x:(1 << x) & mask > 0,range(use.def_reg.bits))))
            graph.append(pairs)
            graphs.append(graph)
    return graphs

class rule():

    def __init__(self, path):
        self.use, self.conditions = pickle.load(open(path, "rb"))
        self.uses_group = defaultdict(set)

    def resolve(self):
        for use in self.use:
            self.uses_group[use.condition].add(use)

    def output(self):
        self.resolve()

        if len(self.conditions) > 1:
            raise Exception

        partition = True

        for use in self.uses_group[partition]:
            print"##",(use.def_reg.name)
            print "^^",(use.use_reg.name)
            print "&&",(use)
        print self.conditions
        # print(self.conditions)
        for partition in self.conditions:
            print "--",(partition.reg)
            print "==",(partition.cond_vals)
            for side in partition.cond_vals:
                if side == True:
                    for val, mask in partition.cond_vals[side]:
                        print(bin(val))
                        print(bin(mask))


def test():
    path = "../0fb66e04.pkl"
    test_rule = rule(path)
    test_rule.output()

cs=Cs(arch=CS_ARCH_X86,mode=CS_MODE_32)
insn=cs.disasm(str(bytearray.fromhex("0fb66e04")),offset=0,count=1)
insn=next(insn)
print insn.mnemonic
print insn.op_str

test()
print( graph("../0fb66e04.pkl") )
