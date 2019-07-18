#coding:utf-8
from idaapi import *
from xml.dom.minidom import Document
'''
获得可能存在的堆栈溢出漏洞位置信息
根据一个给定的XML Schema，使用DOM树的形式从空白文件生成一个XML
'''

doc = Document()     # 创建DOM文档对象

bookstore = doc.createElement('bookstore')    # 创建根元素
bookstore.setAttribute('xmlns:xsi',"https://www.w3.org/2001/XMLSchema-instance")    # 设置命名空间
bookstore.setAttribute('xsi:noNamespaceSchemaLocation','bookstore.xsd')#引用本地XML Schema
doc.appendChild(bookstore)

book = doc.createElement('book')
book.setAttribute('genre','XML')
bookstore.appendChild(book)

title = doc.createElement('title')
title_text = doc.createTextNode('IDAPython栈堆缓冲区溢出检测') #元素内容写入
title.appendChild(title_text)
book.appendChild(title)

def is_stack_buffer(addr, idx):
   inst = DecodeInstruction(addr)
   return get_stkvar(inst[idx], inst[idx].addr) != None 

def find_arg(addr, arg_num):
   # 获取函数所在段的起始地址
   function_head = GetFunctionAttr(addr, idc.FUNCATTR_START)    
   steps = 0
   arg_count = 0
   # 预计检查指令在80条以内
   while steps < 80:    
       steps = steps + 1
       # 向前查看指令
       addr = idc.PrevHead(addr)  
       # 获取前一条指令的名称        
       op = GetMnem(addr).lower() 
       # 检查一下是否存在像ret,retn,jmp,b这样可以中断数据流的指令        
       if op in ("ret", "retn", "jmp", "b") or addr < function_head:            
           return
       if op == "push":
           arg_count = arg_count + 1
           if arg_count == arg_num:
               # 返回被push到堆栈的操作数
               return GetOpnd(addr, 0) 

# 漏洞名称及地址
vulnerabilities = doc.createElement('Vulnerabilities_StackOverflow')
book.appendChild(vulnerabilities)

price_size = 0
print("Stack overflow vulnerabilities retrieval begins,Potential vulnerabilities will be printed below,Please wait...")
for functionAddr in Functions():
   # 检查所有函数
   if "strcpy" in GetFunctionName(functionAddr): 
       xrefs = CodeRefsTo(functionAddr, False)
       # 遍历交叉引用，追踪函数执行过程
       for xref in xrefs:
           # 检查交叉引用是否是函数调用
           if GetMnem(xref).lower() == "call":
               # 找到函数的第一个参数
               opnd = find_arg(xref, 1) 
               function_head = GetFunctionAttr(xref, idc.FUNCATTR_START)
               addr = xref
               _addr = xref                
               while True:
                   _addr = idc.PrevHead(_addr)
                   _op = GetMnem(_addr).lower()                    
                   if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
                       break
                   elif _op == "lea" and GetOpnd(_addr, 0) == opnd:
                       # 检查目标函数的缓冲区是否在堆栈当中
                        if is_stack_buffer(_addr, 1):		
                           author_addr  = doc.createElement('Vulnerability-addr')
                           author_addr_text  = doc.createTextNode(hex(addr))
                           vulnerabilities.appendChild(author_addr)
                           author_addr.appendChild(author_addr_text)
                           book.appendChild(vulnerabilities)
                           price_size += 3
						   
                           print "\n[+]STACK BUFFER STRCOPY FOUND at 0x%X"  % addr                        
                        break
                   # 如果我们检测到要定位的寄存器是来自其他寄存器，则更新循环，在另一个寄存器中继续查找数据源
                   elif _op == "mov" and GetOpnd(_addr, 0) == opnd:
                       op_type = GetOpType(_addr, 1)
                       if op_type == o_reg:
                           opnd = GetOpnd(_addr, 1)
                           addr = _addr
                       else:
                           break
   else:
       print "[-] No Stack overflow vulnerabilities found in " + GetFunctionName(functionAddr) + "."

# 这里写漏洞影响评分             
price = doc.createElement('price')
price_text = doc.createTextNode(str(price_size))
price.appendChild(price_text)
book.appendChild(price)

########### 将DOM对象doc写入文件
f = open('Vulnerability_Analysis_Report_StackOverflow.xml','w')
f.write(doc.toprettyxml(indent = ''))
f.close()
print("Stack overflow vulnerabilities retrieval ended")


