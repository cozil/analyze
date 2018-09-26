rule CRxButton_start
{
	meta:
		script = "Type.as CRxButton"
		script = "Type.aanc CRxButton,CRxObject"
		script = "Type.comment CRxButton,\"按钮类 type=0x22\""
		script = "Type.ad CRxButton,\"void clicked();\""
	condition:
		true
}

rule CRxButton_disabled
{
	meta:
		script = "$result = [@pattern + 0x17]"
		script = "Type.am CRxButton,int,disabled,0,$result"
	strings:
		$pattern = { 83 C0 FE 83 F8 06 0F 87 [4] 53 57 FF 24 85 [4] 83 BE [4] 00 }
	condition:
		#pattern == 1
}

rule CRxButton_cmdtype
{
	meta:
		script = "$result = [@pattern + 0x21]"
		script = "Type.am CRxButton,int,cmdtype,0,$result"
	strings:
		$pattern = { 83 B9 [4] 00 [5] 00 [8] 00 [9] 8B 86 [6] 8B 52 04 6A 00 50 68 F4 03 00 00 FF D2 }
	condition:
		#pattern == 1
}

rule CRxButton_end
{
	meta:
		script = "Type.print CRxButton"
		script = "log"
		script = "log"
	condition:
		true
}