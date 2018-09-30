rule CRxMgrPortal_start
{
	meta:
		script = "Type.as CRxMgrPortal"
		script = "Type.aanc CRxMgrPortal,CRxMgr"
		script = "Type.comment CRxMgrPortal, \"单线地图传送窗口管理\""
	condition:
		true
}

//228 CRxWnd * dlg;
//244 CRxButton * dlg_bn_close;
rule CRxMgrPortal_dlg
{
	meta:
		script = "$result = [@pattern + 0x26]"
		script = "Type.am CRxMgrPortal,CRxWnd*,dlg,0,$result"
		script = "$result = [@pattern + 0x2c]"
		script = "Type.am CRxMgrPortal,CRxButton*,dlg_bn_close,0,$result"
	strings:
		$pattern = { 68 [4] 53 56 83 C1 04 51 81 C2 E3 00 00 00 52 6A 04 68 E3 00 00 00 8B C8 E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//23C CRxButton * dlg_bn_confirm;
rule CRxMgrPortal_dlg_bn_confirm
{
	meta:
		script = "$result = [@pattern + 0x2c]"
		script = "Type.am CRxMgrPortal,CRxButton*,dlg_bn_confirm,0,$result"
	strings:
		$pattern = { 68 [4] 57 56 81 C1 9B 01 00 00 51 83 C2 41 52 68 9B 01 00 00 6A 41 8B C8 E8 [8] 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//240 CRxButton * dlg_bn_cancel;
rule CRxMgrPortal_dlg_bn_cancel
{
	meta:
		script = "$result = [@pattern + 0x33]"
		script = "Type.am CRxMgrPortal,CRxButton*,dlg_bn_cancel,0,$result"
	strings:
		$pattern = { 68 [4] 6A 02 56 81 C2 9B 01 00 00 52 81 C1 8E 00 00 00 51 68 9B 01 00 00 68 8E 00 00 00 8B C8 E8 [8] 8B 96 [4] 89 86 }
	condition:
		#pattern == 1
}

rule CRxMgrPortal_end
{
	meta:
		script = "Type.print CRxMgrPortal,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}