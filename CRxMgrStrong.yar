rule CRxMgrStrong_start
{
	meta:
		script = "Type.as CRxMgrStrong"
		script = "Type.aanc CRxMgrStrong,CRxMgr"
		script = "Type.comment CRxMgrStrong,\"强化管理\""
	condition:
		true
}


//228 CRxWnd * dlg;
rule CRxMgrStrong_dlg
{
	meta:
		script = "$result = [@pattern + 0x6]"
		script = "Type.am CRxMgrStrong,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 6A 01 8B C8 89 86 [4] E8 [4] BF 7D 00 00 00 68 F4 23 00 00 89 7D ?? C7 45 ?? BA 00 00 00 E8 [4] 83 C4 04 89 45 ?? C6 45 ?? 01 [4] 6A 56 }
	condition:
		#pattern == 1
}



//238 CRxButton * dlg_bn_close;
rule CRxMgrStrong_dlg_bn_close
{
	meta:
		script = "$result = [@pattern + 0x41]"
		script = "Type.am CRxMgrStrong,CRxButton*,dlg_bn_close,0,$result"
	strings:
		$pattern = { C6 45 ?? 07 [20] 53 6A 61 [3] 1A [3] 02 01 00 00 ?? 6A 1A 68 02 01 00 00 [2] E8 [8] 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//230 CRxButton * dlg_bn_confirm
rule CRxMgrStrong_dlg_bn_confirm
{
	meta:
		script = "$result = [@pattern + 0x41]"
		script = "Type.am CRxMgrStrong,CRxButton*,dlg_bn_confirm,0,$result"
	strings:
		$pattern = { C6 45 ?? 08 [20] 53 6A 62 [3] AE 01 00 00 [3] 4C ?? 68 AE 01 00 00 6A 4C [2] E8 [8] 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//234 CRxButton * dlg_bn_cancel
rule CRxMgrStrong_dlg_bn_cancel
{
	meta:
		script = "$result = [@pattern + 0x47]"
		script = "Type.am CRxMgrStrong,CRxButton*,dlg_bn_cancel,0,$result"
	strings:
		$pattern = { C6 45 ?? 09 [20] 53 6A 63 [3] AE 01 00 00 [3] 93 00 00 00 ?? 68 AE 01 00 00 68 93 00 00 00 [2] E8 [8] 8B 96 [4] 89 86 }
	condition:
		#pattern == 1
}

rule CRxMgrStrong_end
{
	meta:
		script = "Type.print CRxMgrStrong,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}