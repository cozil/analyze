rule CRxMgrStrong_start
{
	meta:
		script = "Type.as CRxMgrStrong"
		script = "Type.aanc CRxMgrStrong,CRxMgr"
		script = "Type.comment CRxMgrStrong,\"强化管理\""
		script = "Type.ad CRxMgrStrong,\"static const int close_id = 0x61;\""
		script = "Type.ad CRxMgrStrong,\"static const int confirm_id = 0x62;\""
		script = "Type.ad CRxMgrStrong,\"static const int cancel_id = 0x63;\""
		script = "Type.ad CRxMgrStrong,\"inline void click_close() {{ click(close_id); }}\""
		script = "Type.ad CRxMgrStrong,\"inline void click_confirm() {{ click(confirm_id); }}\""
		script = "Type.ad CRxMgrStrong,\"inline void click_cancel() {{ click(cancel_id); }}\""			
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
		$pattern = { 6A 01 [2] 89 [5] E8 [5] 7D 00 00 00 68 [7] C7 [2] BA 00 00 00 E8 [10] C6 [2] 01 [4] 6A 63 }
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