from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.
archs = ["X86","AMD","ARM","XXX","YYY"]


def index(request):
    return render(request,"index.html",{"archs":archs})

def search(request):
    insn=request.GET["insn"]
    insn_arch=request.GET["insn_arch"]
    return render(request, "index.html",
                  {"archs": archs,"info": "ABC " * 100,
                   "insn_str":"["+insn+"  ;;;;"+insn_arch+"]"})