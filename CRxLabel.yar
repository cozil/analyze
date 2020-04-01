rule CRxLabel_start
{
	meta:
		script = "Type.as CRxLabel"
		script = "Type.aanc CRxLabel,CRxCtrl"
		script = "Type.comment CRxLabel, \"标签对象 Type=0x20\""
		script = "Type.ad CRxLabel,\"void set_text(const char * value);\""
	condition:
		true
}

//228 char text[0x118];
rule CRxLabel_text
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxLabel,char,text,0x118,$result"
	strings:
		$pattern = { 8D 9E [8] 01 [7] 8B 4D ?? 6A 00 6A 00 [2] 68 10 04 00 00 }
	condition:
		#pattern == 1
}

rule CRxLabel_end
{
	meta:
		script = "Type.print CRxLabel,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}