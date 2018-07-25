function Register(name,size,value){
    var object= new Object()
    object.name=name
    object.size=size
    object.value=value
    return object
}

function Relations(regs,arrows){
    var object= new Object()
    object.regs=regs
    object.arrows=arrows
    return object
}


function draw_register(stage,x,y,reg,ex,ey){
    var width=$("#rect1").attr("width");
    stage.text(x,y,reg.name+":",{width:ex,height:ey,hAlign:"center",vAlign:"middle",color:"red"})
    for(var i=1;i<=reg.size;i++){
        stage.rect(x+i*ex,y,ex,ey)
        stage.text(x+i*ex,y,(i-1)+"",{width:ex,height:ey,hAlign:"left",vAlign:"middle",})
    }

}

function draw_relations(stage,relations){
    cw=stage.width()
    max_num=0
    for (var i=0;i<relations.regs.length;i++){
        var reg=relations.regs[i];
        if (reg.size>max_num){
            max_num=reg.size
        }
    }
    ew=(cw-1)/(max_num+1)
    eh=ew/2
    eg=eh/2*3
    stage.height(2+(eh+eg)*relations.regs.length- (relations.regs.length>0?eg:0))
    for (var i=0;i<relations.regs.length;i++){
        draw_register(stage,0,(eh+eg)*i+1,relations.regs[i],ew,eh)
    }

    for(var i=0;i<relations.arrows.length;i++){
        ri0=relations.arrows[i][0]
        ri1=relations.arrows[i][2]
        bi0=relations.arrows[i][1]
        bi1=relations.arrows[i][3]
        ax0=(bi0+1.5)*ew
        ay0=ri0*(eh+eg)+0.5*eh
        ax1=(bi1+1.5)*ew
        ay1=ri1*(eh+eg)+0.5*eh
        arrow(stage,ax0,ay0,ax1,ay1)
    }

}

function arrow(stage,x0,y0,x1,y1){
    xg=x1-x0
    yg=y1-y0
    x2=x1-4*xg/Math.sqrt(Math.pow(xg,2)+Math.pow(yg,2))
    y2=y1-4*yg/Math.sqrt(Math.pow(xg,2)+Math.pow(yg,2))
    x3=x2+3*yg/Math.sqrt(Math.pow(xg,2)+Math.pow(yg,2))
    y3=y2-3*xg/Math.sqrt(Math.pow(xg,2)+Math.pow(yg,2))
    x4=x2-3*yg/Math.sqrt(Math.pow(xg,2)+Math.pow(yg,2))
    y4=y2+3*xg/Math.sqrt(Math.pow(xg,2)+Math.pow(yg,2))
    var linePath=acgraph.path()
    linePath.parent(stage)
    linePath.moveTo(x0,y0)
    linePath.lineTo(x1,y1)
    linePath.lineTo(x3,y3)
    linePath.moveTo(x1,y1)
    linePath.lineTo(x4,y4)
}

$(document).ready(function(){
    var stage = acgraph.create("rect1");
    regs=[Register("eax",32,0xff),Register("ebx",32,0xff)]
    rels=[]
    for(var i=0;i<32;i++){
        rels[i]=[0,i,1,i]
    }
    relations=Relations(regs,rels)
    draw_relations(stage,relations)
});