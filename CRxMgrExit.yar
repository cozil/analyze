rule CRxMgrExit_start
{
	meta:
		script = "Type.as CRxMgrExit"
		script = "Type.comment CRxMgrExit,\"游戏小地图管理器type=0x2b\""
	condition:
		true
}

//230 CRxWnd * dlg;
//240 CRxLabelEx * dlg_lb_text;
rule CRxMgrExit_dlg
{
	meta:
		script = "$result = [@pattern + 0x25]"
		script = "Type.am CRxMgrExit,CRxWnd*,dlg,0,$result"
		script = "$result = [@pattern + 0x2b]"
		script = "Type.am CRxMgrExit,CRxLabelEx*,dlg_lb_text,0,$result"
	strings:
		$pattern = { C6 [2] 02 [7] 6A 73 68 03 01 00 00 6A 05 6A 3C 6A 14 [2] E8 [8] 8B [5] 89 }
	condition:
		#pattern == 1
}

rule CRxMgrExit_end
{
	meta:
		script = "Type.print CRxMgrExit,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}