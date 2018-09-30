rule CRxMgrSxstone_start
{
	meta:
		script = "Type.as CRxMgrSxstone"
		script = "Type.aanc CRxMgrSxstone,CRxMgr"
		script = "Type.comment CRxMgrSxstone, \"赋予属性管理\""
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrSxstone_dlg
{
	meta:
		script = "$result = [@pattern + 0x6]"
		script = "Type.am CRxMgrSxstone,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 6A 01 8B C8 89 86 [4] E8 [4] 68 F4 23 00 00 C7 45 ?? 7D 00 00 00 C7 45 ?? BA 00 00 00 E8 [18] 6A 56 }
	condition:
		#pattern == 1
}


//23C CRxButton * dlg_bn_confirm;
//240 CRxButton * dlg_bn_cancel;
//244 CRxButton * dlg_bn_close;
rule CRxMgrSxstone_dlg_ctrls
{
	meta:
		script = "$result = [@pattern + 0xb9]"
		script = "Type.am CRxMgrSxstone,CRxButton*,dlg_bn_confirm,0,$result"
		script = "$result = [@pattern + 0xe6]"
		script = "Type.am CRxMgrSxstone,CRxButton*,dlg_bn_cancel,0,$result"
		script = "$result = [@pattern + 0x93]"
		script = "Type.am CRxMgrSxstone,CRxButton*,dlg_bn_close,0,$result"
	strings:
		$pattern = { 6A 01 [129] 6A 62 68 [4] 68 [6] 89 86 [4] 8B 86 [7] E8 [4] D9 05 [4] D9 5D [4] D9 05 [4] 89 86 [4] D9 5D [15] 6A 63 68 [4] 68 [9] E8 [4] 89 86 }
	condition:
		#pattern == 1
}

rule CRxMgrSxstone_end
{
	meta:
		script = "Type.print CRxMgrSxstone,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}