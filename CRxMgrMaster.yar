rule CRxMgrMaster_start
{
	meta:
		script = "Type.as CRxMgrMaster"
		script = "Type.aanc CRxMgrMaster,CRxMgr"
		script = "Type.comment CRxMgrMaster,\"至尊、热血符管理\""
		script = "Type.ad CRxMgrMaster,\"inline void click_confirm() {{ click(0x63); }}\""
		script = "Type.ad CRxMgrMaster,\"inline void click_cancel() {{ click(0x5f); }}\""
	condition:
		true
}

//234 CRxLabel * lb_child1;
//238 CRxLabel * lb_child2;
//23c CRxLabel * lb_child3;
//3a0 CRxWnd * dlg;
rule CRxMgrMaster_dlg
{
	meta:
		script = "$result = [@pattern1 + 0x7]"
		script = "Type.am CRxMgrMaster,CRxWnd*,dlg,0,$result"
		
		script = "$result = [@pattern1 + 0x1c] + byte:[@pattern2 + 0x46]"
		script = "Type.am CRxMgrMaster,CRxLabel*,lb_child1,0,$result"
		script = "Type.mcomment CRxMgrMaster,lb_child1,\"作为徒弟时，此为师傅名称\""
		script = "Type.am CRxMgrMaster,CRxLabel*,lb_child2,0,$result+4"
		script = "Type.am CRxMgrMaster,CRxLabel*,lb_child3,0,$result+8"
	strings:
		$pattern1 = { E8 [4] 8B [5] E8 [4] 89 [2] C7 [2] 3E 00 00 00 8D [5] 89 [2] EB ?? EB ?? 8D A4 [5] 90 }
		$pattern2 = { C7 [2] 07 00 00 00 [40] 6A 05 [10] E8 [8] 89 }
	condition:
		for all of them : (# == 1)
}

rule CRxMgrMaster_end
{
	meta:
		script = "Type.print CRxMgrMaster,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}