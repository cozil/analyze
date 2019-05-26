
rule CRxMgrDepot_start
{
	meta:
		script = "Type.as CRxMgrDepot"
		script = "Type.aanc CRxMgrDepot,CRxMgr"
		script = "Type.comment CRxMgrDepot, \"仓库管理\""
		script = "Type.ad CRxMgrDepot,\"static const int open_depot1_id = 0x1;\""
		script = "Type.ad CRxMgrDepot,\"static const int open_depot2_id = 0x2;\""
		script = "Type.ad CRxMgrDepot,\"static const int close_depot1_id = 0x62;\""
		script = "Type.ad CRxMgrDepot,\"static const int close_depot2_id = 0x63;\""
	condition:
		true
}

//228 CRxWndDepot * dlg;
rule CRxMgrDepot_dlg
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrDepot,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 8B 8E [4] 53 6A 50 6A 61 6A 3D 6A 1C 6A 01 E8 }
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