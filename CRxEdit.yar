rule CRxEdit_start
{
	meta:
		script = "Type.as CRxEdit"
		script = "Type.comment CRxEdit,\"游戏文本输入控件 Type=0x17 (static)\""
		script = "Type.aanc CRxEdit,CRxCtrl"
		script = "Type.ad CRxEdit,\"void set_text(const char * str);\""
		
		script = "Type.as CRxText"
		script = "Type.comment CRxText,\"用于接收文字输入的结构 Type=0x58\""
		script = "Type.ad CRxText,\"void set_text(uint32_t value);\""
		script = "Type.ad CRxText,\"void set_text(uint64_t value);\""
		script = "Type.ad CRxText,\"void set_text(const char * value);\""
	condition:
		true
}

//238 char CRxEdit::text[0x80];
//13c char CRxText::text[0x80];
rule CRxEdit_text
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "Type.am CRxEdit,char,text,0x80,$result"
		script = "$result = [@pattern + 0xf]"
		script = "Type.am CRxText,char,text,0x80,$result"
	strings:
		$pattern = { 8B 0D [4] 6A FF 68 80 00 00 00 81 C1 [4] 51 8D 96 [4] 52 E8 }
	condition:
		#pattern == 1
}


rule CRxEdit_end
{
	meta:
		script = "Type.print CRxEdit,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "Type.print CRxText,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}