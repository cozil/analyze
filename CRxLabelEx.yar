rule CRxLabelEx_start
{
	meta:
		script = "Type.as CRxLabelEx"
		script = "Type.aanc CRxLabelEx,CRxCtrl"
		script = "Type.comment CRxLabelEx, \"多行文本标签对象 Type=0x55 (static)\""
		script = "Type.ad CRxLabelEx,\"void set_text(const char * value);\""
	condition:
		true
}

//229 char text[200];
rule CRxLabelEx_text
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "Type.am CRxLabelEx,char,text,0x200,$result"
	strings:
		$pattern = { 68 00 02 00 00 [3] 8B [2] 6A FF 68 00 02 00 00 [8] E8 }
	condition:
		#pattern == 1
}

rule CRxLabelEx_end
{
	meta:
		script = "Type.print CRxLabelEx,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}