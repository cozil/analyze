
rule CRxMgrDepot_start
{
	meta:
		script = "Type.as CRxMgrDepot"
		script = "Type.aanc CRxMgrDepot,CRxMgr"
		script = "Type.comment CRxMgrDepot, \"仓库管理\""
	condition:
		true
}

//228 CRxWndDepot * dlg;
rule CRxMgrDepot_dlg
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrDepot,CRxWndDepot*,dlg,0,$result"
	strings:
		$pattern = { 8B 8E [4] 53 6A 50 6A 61 6A 3D 6A 1C 6A 01 E8 }
	condition:
		#pattern == 1
}

//234 CRxButton * dlg_bn_close1;
rule CRxMgrDepot_dlg_bn_close1
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxMgrDepot,CRxButton*,dlg_bn_close1,0,$result"
	strings:
		$pattern = { 6A 62 [3] 1A [3] 02 01 00 00 ?? 6A 1A 68 02 01 00 00 [2] E8 [8] 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//23C CRxButton * dlg_bn_close2;
rule CRxMgrDepot_dlg_bn_close2
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxMgrDepot,CRxButton*,dlg_bn_close2,0,$result"
	strings:
		$pattern = { 6A 63 [3] 1A [3] 02 01 00 00 ?? 6A 1A 68 02 01 00 00 [2] E8 [8] 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

rule CRxMgrDepot_end
{
	meta:
		script = "Type.print CRxMgrDepot,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}