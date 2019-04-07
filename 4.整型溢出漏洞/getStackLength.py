# coding=utf-8
from idaapi import *
from idc import *
import idautils
import sys as sys
from xml.dom.minidom import Document
'''
获得可能存在的整型溢出漏洞函数以及堆栈变量类型信息
根据一个给定的XML Schema，使用DOM树的形式从空白文件生成一个XML
'''


doc = Document()  #创建DOM文档对象

bookstore = doc.createElement('bookstore') #创建根元素
bookstore.setAttribute('xmlns:xsi',"https://www.w3.org/2001/XMLSchema-instance")#设置命名空间
bookstore.setAttribute('xsi:noNamespaceSchemaLocation','bookstore.xsd')#引用本地XML Schema
doc.appendChild(bookstore)

book = doc.createElement('book')
book.setAttribute('genre','XML')
bookstore.appendChild(book)

title = doc.createElement('title')
title_text = doc.createTextNode('IDAPython整型溢出漏洞检测') #元素内容写入
title.appendChild(title_text)
book.appendChild(title)

var_size_threshold = 16  #阈值
current_addr = ScreenEA()  

class AnayBinFil(object):
    def __init__(self):
        list = []
    # 得到某一条汇编指令所指向的内存的内容 
    def GetXref_String(self,ea,n):
        if (GetOpType(ea,n) == 2):
            ea = GetOperandValue(ea,n)
        if (not SegName(ea) == '.rodata'):
            addrx = idautils.DataRefsFrom(ea)
            for item in addrx:
                return self.GetXref_String(item,n)
            return idc.Dword(ea)
        return GetString(ea)
        
    
    #get the register's content whose number is i from ea forward search
    def get_content_register(self,ea,i):
 
        if (GetOpType(ea,0) == 1 and GetOperandValue(ea,0) == i):# wanted register
            if (ua_mnem (ea) == 'LDR'):
                if (GetOpType(ea,1) == 2):#Optype is Memory Reference
                    return self.GetXref_String(ea,1)
                elif (GetOpType(ea,1) == 4):#Base+index+Displacement
                    if(GetOperandValue(ea,1) == 0): # like  : LDR R3,[R3]
                        return self.get_content_register(PrevHead(ea),i)
                    else:
                        return 
                else :
                    print 'unkown Optype:' ,hex(ea),idc.GetDisasm(ea)
            elif (ua_mnem(ea) == 'MOV'):
                if (GetOpType(ea,1) == 5):
                    return GetOperandValue(ea,1)
                elif (GetOpType(ea,1) == 1):
                    return self.get_content_register(PrevHead(ea),GetOperandValue(ea,1))
                else:
                    print 'unkown OpType:',hex(ea),idc.GetDisasm(ea)
        else:
            return self.get_content_register(PrevHead(ea),i)
 
 
    #from a call instruction BackForward search parameter
    def BackForward(self,addr,n):
        Reg_content = []
        i = 0 # register number
        for i in range(n):
            Reg_content.append(self.get_content_register(addr,i))
 
        return Reg_content
 
 
    def Anayl_Func_Call(self, func_name, para_num):
         if func_name == "":
             return
         segkind = ['.text' , '.init' ,'.plt']
         startaddr = MinEA() 
         while True:
            fun_addr = FindText(startaddr,SEARCH_DOWN, 0, 0, str(func_name))
            if not (SegName(fun_addr)) in segkind:
                break
            startaddr = NextHead(fun_addr)
 
         print 'find pattern string addr',hex(fun_addr)
         
         call_addrs = idautils.DataRefsTo(fun_addr)
         dic = {}
         for item in call_addrs:
             if (not isCode(GetFlags(item))):
                 continue
             CALL_ADDR = item
             while ( not ua_mnem(CALL_ADDR) == 'BL' ):
                 CALL_ADDR = NextHead(CALL_ADDR)
             CALL_ADDR = PrevHead(CALL_ADDR)        
             para = self.BackForward(CALL_ADDR,para_num)
             xref_funname = GetFunctionName(CALL_ADDR)
             dic[xref_funname] = para
         return dic
 
        
#漏洞名称及地址
vulnerabilities = doc.createElement('Vulnerabilities_IntegerOverflow')
book.appendChild(vulnerabilities)


price_size = 0
print "\n[+] Finding Integer overflow vulnerabilities,Potential vulnerabilities will be printed below,Please wait......"
for f in Functions(SegStart(current_addr), SegEnd(current_addr)):  
        stack_frame = GetFrame(f)        #get frame of stack  
        frame_size = GetStrucSize(stack_frame)        #compute size of stackframe  
  
        frame_counter = 0  
        prev_count = -1  
        distance = 0  
        
        ana_fun_name = stack_frame  #要分析的函数名
        para_num = 0 #参数数量
        ana = AnayBinFil()
        dic = ana.Anayl_Func_Call(ana_fun_name,para_num+1)
        size = sys.getsizeof(dic)
  
        while frame_counter < frame_size:
                stack_var = GetMemberName(stack_frame, frame_counter)        #get one from stack  
                if stack_var != "":  
                        if prev_count != -1:  
                                distance = frame_counter - prev_distance  
                                prev_distance = frame_counter        #record last location  
                                  
                                if distance >= var_size_threshold:  
                                        if distance < size:
                                               author_name = doc.createElement('Vulnerability-name')
                                               author_stackVariable  = doc.createElement('Vulnerability-stackVariable')
                                               author_name_text = doc.createTextNode(GetFunctionName(f))
                                               author_stackVariable_text  = doc.createTextNode(str(prev_member))
                                               vulnerabilities.appendChild(author_name)
                                               vulnerabilities.appendChild(author_stackVariable)
                                               author_name.appendChild(author_name_text)
                                               author_stackVariable.appendChild(author_stackVariable_text)
                                               book.appendChild(vulnerabilities)
                                               price_size += 3
                                               print  "[+] Function: %s - > Integer overflow exits(Stack Variable: %s) !!!" % ( GetFunctionName(f), prev_member )
                        else:  
                                prev_count = frame_counter  
                                prev_distance = frame_counter  
                                prev_member = stack_var  
                        try:  
                                frame_counter = frame_counter + GetMemberSize(stack_frame, frame_counter)        #compute offset  
                        except:  
                                frame_counter += 1  
                else:  
                        frame_counter += 1
print("Integer overflow vulnerabilities retrieval ended")
idc.Exit(0)

#这里写漏洞影响大小             
price = doc.createElement('price')
price_text = doc.createTextNode(str(price_size))
price.appendChild(price_text)
book.appendChild(price)

########### 将DOM对象doc写入文件
f = open('Vulnerability_Analysis_Report_IntegerOverflow.xml','w')
f.write(doc.toprettyxml(indent = ''))
f.close()










