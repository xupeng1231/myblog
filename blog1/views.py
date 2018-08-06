from django.shortcuts import render
from django.http import JsonResponse
import json

import cPickle as pickle
from common import *
archs = ["X86","AMD","ARM","XXX","YYY"]


def index(request):
    return render(request,"index.html",{"archs":archs})



def info(request):
    insn = request.GET["insn"]
    insn_arch = request.GET["insn_arch"]
    return JsonResponse({"info": "ABC " * 100,
                        "insn_str":"["+insn+"  ;;;;"+insn_arch+"]",
                        "graphs":graph("/home/ying/django-projects/myblog/0fb66e04.pkl")})

def Register(name,size,value):
    obj={}
    obj["name"]=name
    obj["size"]=size
    obj["value"]=value
    return obj

def Relations(regs,arrows):
    obj={}
    obj["regs"]=regs
    obj["arrows"]=arrows
    return obj
def graph(path):
    uses,conditions=pickle.load(open(path,"rb"))
    regs=[]
    arrows=[]
    for use in uses:
        if use.def_reg and use.use_reg and use.use_mask2:
            i=len(regs)
            size=max( use.use_reg.bits,use.def_reg.bits)
            regs.append(Register(use.use_reg.name, size, 0xff))
            regs.append(Register(use.def_reg.name, size, 0xff))

            pairs=[]
            for pos,mask in enumerate(use.use_mask2):
                pairs.extend(itertools.product((pos,),filter(lambda x:(1 << x) & mask > 0,range(use.def_reg.bits))))
            arrows.extend([[i,x[0],i+1,x[1]] for x in pairs])

    return Relations(regs,arrows)


