rule CRxMgrExit_start
{
	meta:
		script = "Type.as CRxMgrExit"
		script = "Type.comment CRxMgrExit,\"游戏小地图管理器type=0x2b\""
		//script = "Type.ad CRxMgrExit,\"inline void click_close() {{ click(0x63); }}\""
		//script = "Type.ad CRxMgrExit,\"inline void click_cancel() {{ click(0x62); }}\""
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

//244 CRxButton * dlg_bn_cancel;
//rule CRxMgrExit_dlg_bn_cancel
//{
//	meta:
//		script = "$result = [@pattern + 0x47]"
//		script = "Type.am CRxMgrExit,CRxButton*,dlg_bn_cancel,0,$result"
//	strings:
//		$pattern = { C6 [2] 03 [16] 68 [4] 68 [5] 6A 62 [3] B2 00 00 00 [3] 55 ?? 68 B2 00 00 00 6A 55 [2] E8 [9] 6A 78 88 [2] 89 }
//	condition:
//		#pattern == 1
//}

//254 CRxButton * dlg_bn_close;
//rule CRxMgrExit_dlg_bn_accept
//{
//	meta:
//		script = "$result = [@pattern + 0x47]"
//		script = "Type.am CRxMgrExit,CRxButton*,dlg_bn_close,0,$result"
//	strings:
//		$pattern = { C6 [2] 05 [16] 68 [4] 68 [5] 6A 62 [3] B2 00 00 00 [3] 77 ?? 68 B2 00 00 00 6A 77 [2] E8 [9] 6A 78 88 [2] 89 }
//	condition:
//		#pattern == 1
//}

rule CRxMgrExit_end
{
	meta:
		script = "Type.print CRxMgrExit,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}