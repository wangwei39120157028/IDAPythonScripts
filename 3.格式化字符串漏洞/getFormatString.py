#coding:utf-8
from idaapi import *
import idautils
import idc
from xml.dom.minidom import Document
'''
获得可能存在的格式化字符串漏洞函数及对应位置信息
根据一个给定的XML Schema，使用DOM树的形式从空白文件生成一个XML
'''

doc = Document()  # 创建DOM文档对象

bookstore = doc.createElement('bookstore') # 创建根元素
bookstore.setAttribute('xmlns:xsi',"https://www.w3.org/2001/XMLSchema-instance")   # 设置命名空间
bookstore.setAttribute('xsi:noNamespaceSchemaLocation','bookstore.xsd')#引用本地XML Schema
doc.appendChild(bookstore)

book = doc.createElement('book')
book.setAttribute('genre','XML')
bookstore.appendChild(book)

title = doc.createElement('title')
title_text = doc.createTextNode('IDAPython格式化字符串漏洞检测') #元素内容写入
title.appendChild(title_text)
book.appendChild(title)

class VulnChoose(Choose2):
    # 漏洞隐患函数判断类来显示格式字符串vuln扫描的结果
    def __init__(self, title, items, icon, embedded=False):
        Choose2.__init__(self, title, [["Address", 20], ["Function", 30], ["Format", 30]], embedded=embedded)
        self.items = items
        self.icon = 45

    def GetItems(self):
        return self.items

    def SetItems(self, items):
        self.items = [] if items is None else items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        Jump(int(self.items[n][0], 16))

def check_fmt_function(name, addr):
	# 检查格式字符串参数是否有效
	function_head = GetFunctionAttr(addr, FUNCATTR_START)
	while True:
		addr = PrevHead(addr)
		op = GetMnem(addr).lower()
		dst = GetOpnd(addr, 0)
		if op in ("ret", "retn", "jmp", "b") or addr < function_head:
			return
		c = GetCommentEx(addr, 0)
		if c and c.lower() == "format":
				break
		elif name.endswith(("snprintf_chk",)):
			if op in ("mov", "lea") and dst.endswith(("r8", "r8d", "[esp+10h]")):
				break
		elif name.endswith(("sprintf_chk",)):
			if op in ("mov", "lea") and (dst.endswith(("rcx", "[esp+0Ch]", "R3")) or
										 dst.endswith("ecx") and BITS == 64):
				break
		elif name.endswith(("snprintf", "fnprintf")):
			if op in ("mov", "lea") and (dst.endswith(("rdx", "[esp+8]", "R2")) or
										dst.endswith("edx") and BITS== 64):
				break
		elif name.endswith(("sprintf", "fprintf", "dprintf", "printf_chk")):
			if op in ("mov", "lea") and (dst.endswith(("rsi", "[esp+4]", "R1")) or
										 dst.endswith("esi") and BITS == 64):
				break
		elif name.endswith("printf"):
			if op in ("mov", "lea") and (dst.endswith(("rdi", "[esp]", "R0")) or
										 dst.endswith("edi") and BITS == 64):
				break

	# 找到格式化参，检查它的类型和值
	# 获得最近一次操作数栈
	op_index = GetDisasm(addr).count(",")
	op_type = GetOpType(addr, op_index)
	opnd = GetOpnd(addr, op_index)

	if op_type == o_reg:
		# 格式化字符串在寄存器中，尝试回溯并获取其源文件
		_addr = addr
		while True:
			_addr = PrevHead(_addr)
			_op = GetMnem(_addr).lower()
			if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
				break
			elif _op in ("mov", "lea", "ldr") and GetOpnd(_addr, 0) == opnd:
				op_type = GetOpType(_addr, 1)
				opnd = GetOpnd(_addr, 1)
				addr = _addr
				break

	if op_type == o_imm or op_type == o_mem:
		# 检查格式化字符串隐患是否可利用
		op_addr = GetOperandValue(addr, op_index)
		seg = getseg(op_addr)
		if seg:
			if not seg.perm & SEGPERM_WRITE:
				# 格式化段是只读模式
				return
	print "0x%X: Possible Vulnerability: %s, format = %s" % (addr, name, opnd)
	return ["0x%X" % addr, name, opnd]

#漏洞名称及地址
vulnerabilities = doc.createElement('Vulnerabilities_FormatString')
book.appendChild(vulnerabilities)

price_size = 0
print "\n[+] Finding Format String vulnerabilities,Potential vulnerabilities will be printed below,Please wait......"
found = []
for addr in idautils.Functions():
    name = GetFunctionName(addr)
    if "printf" in name and "v" not in name and SegName(addr) in (".text", ".plt", ".idata"):
        print name
        xrefs = idautils.CodeRefsTo(addr, False)
        for xref in xrefs:
            vul = check_fmt_function(name, xref)
            print xref
            if vul:
                found.append(vul)
if found:
    print "[!] Done! %d possible vulnerabilities found." % len(found)
    for fd in found:
        author_name = doc.createElement('Vulnerability-name')
        author_addr  = doc.createElement('Vulnerability-addr')
        author_name_text = doc.createTextNode(fd[1])
        author_addr_text  = doc.createTextNode(fd[0])
        vulnerabilities.appendChild(author_name)
        vulnerabilities.appendChild(author_addr)
        author_name.appendChild(author_name_text)
        author_addr.appendChild(author_addr_text)
        book.appendChild(vulnerabilities)
        price_size += 5
    ch = VulnChoose("Vulnerability", found, None, False)
    ch.Show()
else:
    print "[-] No format string vulnerabilities found."

# 这里写漏洞影响的相对评分             
price = doc.createElement('price')
price_text = doc.createTextNode(str(price_size))
price.appendChild(price_text)
book.appendChild(price)

########### 将DOM对象doc写入文件
f = open('Vulnerability_Analysis_Report_FormatString.xml','w')
f.write(doc.toprettyxml(indent = ''))
f.close()

print("Format string vulnerabilities retrieval ended")
