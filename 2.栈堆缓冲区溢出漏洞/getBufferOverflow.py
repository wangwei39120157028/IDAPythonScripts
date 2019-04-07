#coding:utf-8
from idaapi import *
from xml.dom.minidom import Document
'''
获得可能存在的堆栈溢出漏洞位置信息
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
title_text = doc.createTextNode('IDAPython栈堆缓冲区溢出检测') #元素内容写入
title.appendChild(title_text)
book.appendChild(title)

def is_stack_buffer(addr, idx):
   inst = DecodeInstruction(addr)
   return get_stkvar(inst[idx], inst[idx].addr) != None 

def find_arg(addr, arg_num):
   # Get the start address of the function that we are in
   function_head = GetFunctionAttr(addr, idc.FUNCATTR_START)    
   steps = 0
   arg_count = 0
   # It is unlikely the arguments are 100 instructions away, include this as a safety check
   while steps < 100:    
       steps = steps + 1
       # Get the previous instruction
       addr = idc.PrevHead(addr)  
       # Get the name of the previous instruction        
       op = GetMnem(addr).lower() 
       # Check to ensure that we havent reached anything that breaks sequential code flow        
       if op in ("ret", "retn", "jmp", "b") or addr < function_head:            
           return
       if op == "push":
           arg_count = arg_count + 1
           if arg_count == arg_num:
               #Return the operand that was pushed to the stack 
               return GetOpnd(addr, 0) 

#漏洞名称及地址
vulnerabilities = doc.createElement('Vulnerabilities_StackOverflow')
book.appendChild(vulnerabilities)

price_size = 0
print("Stack overflow vulnerabilities retrieval begins,Potential vulnerabilities will be printed below,Please wait...")
for functionAddr in Functions():
   # Check each function to look for strcpy
   if "strcpy" in GetFunctionName(functionAddr): 
       xrefs = CodeRefsTo(functionAddr, False)
       # Iterate over each cross-reference
       for xref in xrefs:
           # Check to see if this cross-reference is a function call
           if GetMnem(xref).lower() == "call":
               # Since the dest is the first argument of strcpy
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
                       # We found the destination buffer, check to see if it is in the stack
                        if is_stack_buffer(_addr, 1):
						
                           author_addr  = doc.createElement('Vulnerability-addr')
                           author_addr_text  = doc.createTextNode(hex(addr))
                           vulnerabilities.appendChild(author_addr)
                           author_addr.appendChild(author_addr_text)
                           book.appendChild(vulnerabilities)
                           price_size += 3
						   
                           print "\n[+]STACK BUFFER STRCOPY FOUND at 0x%X"  % addr                        
                        break
                   # If we detect that the register that we are trying to locate comes from some other register
                   # then we update our loop to begin looking for the source of the data in that other register
                   elif _op == "mov" and GetOpnd(_addr, 0) == opnd:
                       op_type = GetOpType(_addr, 1)
                       if op_type == o_reg:
                           opnd = GetOpnd(_addr, 1)
                           addr = _addr
                       else:
                           break
   else:
       print "[-] No Stack overflow vulnerabilities found in " + GetFunctionName(functionAddr) + "."

#这里写漏洞影响大小             
price = doc.createElement('price')
price_text = doc.createTextNode(str(price_size))
price.appendChild(price_text)
book.appendChild(price)

########### 将DOM对象doc写入文件
f = open('Vulnerability_Analysis_Report_StackOverflow.xml','w')
f.write(doc.toprettyxml(indent = ''))
f.close()
print("Stack overflow vulnerabilities retrieval ended")


