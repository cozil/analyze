rule CRxMgrSxstone_start
{
	meta:
		script = "Type.as CRxMgrSxstone"
		script = "Type.aanc CRxMgrSxstone,CRxMgr"
		script = "Type.comment CRxMgrSxstone, \"赋予属性管理\""
		script = "Type.ad CRxMgrSxstone,\"static const int close_id = 0x61;\""
		script = "Type.ad CRxMgrSxstone,\"static const int confirm_id = 0x62;\""
		script = "Type.ad CRxMgrSxstone,\"static const int cancel_id = 0x63;\""
		script = "Type.ad CRxMgrSxstone,\"inline void click_close() {{ click(close_id); }}\""
		script = "Type.ad CRxMgrSxstone,\"inline void click_confirm() {{ click(confirm_id); }}\""
		script = "Type.ad CRxMgrSxstone,\"inline void click_cancel() {{ click(cancel_id); }}\""
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
		$pattern = { 6A 01 [2] 89 [5] E8 [4] 68 [4] C7 [2] 7D 00 00 00 C7 [2] BA 00 00 00 E8 [18] 6A 56 }
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