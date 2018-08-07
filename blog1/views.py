from django.shortcuts import render
from django.http import JsonResponse
from models import InsDatabase
import cPickle as pickle
from common import *
import traceback
from keystone import *

archs = {"X86":KS_ARCH_X86,"ARM":KS_ARCH_ARM,"ARM64":KS_ARCH_ARM64,"MIPS":KS_ARCH_MIPS,"SPARC":KS_ARCH_SPARC}


def index(request):
    return render(request,"index.html",{"archs":sorted(archs.keys())})

def info(request):
    insn_str = request.GET["insn"]
    insn_arch = request.GET["insn_arch"]
    try:
        ks = Ks(arch=archs[insn_arch],mode=KS_MODE_32)
        code, count=ks.asm(insn_str,addr=0)
        code=''.join(["{:02x}".format(c) for c in code])
    except:
        return JsonResponse({"status":"fail",
                             "info":"assemble error!"})

    ins_data=InsDatabase.objects.filter(code=code)
    if len(ins_data)>0:
        graph,information=graph_info(ins_data[0].data)
        return JsonResponse({"status":"success",
                        "info": information,
                        "insn_str":"["+insn_str+"  ;;;;"+insn_arch+"]",
                        "graphs":graph})
    else:
        #get_data
        data = open("/home/ying/django-projects/myblog/0fb66e04.pkl", "rb").read()
        ins_data = InsDatabase(code=code, arch=insn_arch, data=data)
        ins_data.save()
        graph, information = graph_info(data)
        return JsonResponse({"status": "success",
                             "info": information,
                             "insn_str": "[" + insn_str + "  ;;;;" + insn_arch + "]",
                             "graphs": graph})


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


def graph_info(data):
    uses,conditions=pickle.loads(str(data))
    regs=[]
    arrows=[]
    info=[]
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
        info.append(str(use))
    return Relations(regs,arrows),"\n".join(info).replace("\n","<br>")




