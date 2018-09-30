rule CRxMgrRaise_start
{
	meta:
		script = "Type.as CRxMgrRaise"
		script = "Type.aanc CRxMgrRaise,CRxMgr"
		script = "Type.comment CRxMgrRaise, \"提真管理\""
	condition:
		true
}

//228 CRxWnd * dlg;
//240 CRxButton * dlg_bn_close;
rule CRxMgrRaise_dlg
{
	meta:
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxMgrRaise,CRxWnd*,dlg,0,$result"
		script = "$result = [@pattern + 0x2f]"
		script = "Type.am CRxMgrRaise,CRxButton*,dlg_bn_close,0,$result"
	strings:
		$pattern = { 68 [4] 68 [4] 6A 61 [3] 1A [3] 1A ?? 6A 1A 68 02 01 00 00 [2] E8 [8] 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}


//238 CRxButton * dlg_bn_confirm;
rule CRxMgrRaise_dlg_bn_confirm
{
	meta:
		script = "$result = [@pattern + 0x40]"
		script = "Type.am CRxMgrRaise,CRxButton*,dlg_bn_confirm,0,$result"
	strings:
		$pattern = { C6 45 ?? 03 [10] 68 [4] 68 [4] 6A 62 [3] AE 01 00 00 [3] 4C ?? 68 AE 01 00 00 6A 4C [2] E8 [8] 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//23C CRxButton * dlg_bn_cancel;
rule CRxMgrRaise_dlg_bn_cancel
{
	meta:
		script = "$result = [@pattern + 0x46]"
		script = "Type.am CRxMgrRaise,CRxButton*,dlg_bn_cancel,0,$result"
	strings:
		$pattern = { C6 45 ?? 04 [10] 68 [4] 68 [4] 6A 63 [3] AE 01 00 00 [3] 93 00 00 00 ?? 68 AE 01 00 00 68 93 00 00 00 [2] E8 [8] 8B 96 [4] 89 86 }
	condition:
		#pattern == 1
}

rule CRxMgrRaise_end
{
	meta:
		script = "Type.print CRxMgrRaise,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}