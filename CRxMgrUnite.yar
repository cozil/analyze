rule CRxMgrUnite_start
{
	meta:
		script = "Type.as CRxMgrUnite"
		script = "Type.aanc CRxMgrUnite,CRxMgr"
		script = "Type.comment CRxMgrUnite,\"合成管理\""
		script = "Type.ad CRxMgrUnite,\"static const int close_id = 0x61;\""
		script = "Type.ad CRxMgrUnite,\"static const int confirm_id = 0x62;\""
		script = "Type.ad CRxMgrUnite,\"static const int cancel_id = 0x63;\""
		script = "Type.ad CRxMgrUnite,\"inline void click_close() {{ click(close_id); }}\""
		script = "Type.ad CRxMgrUnite,\"inline void click_confirm() {{ click(confirm_id); }}\""
		script = "Type.ad CRxMgrUnite,\"inline void click_cancel() {{ click(cancel_id); }}\""
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrUnite_dlg
{
	meta:
		script = "$result = [@pattern + 0x6]"
		script = "Type.am CRxMgrUnite,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 6A 01 [2] 89 [5] E8 [4] 68 [4] C7 [2] 7D 00 00 00 C7 [2] BA 00 00 00 E8 [18] 6A 60 ?? 6A 01 }
	condition:
		#pattern == 1
}

rule CRxMgrUnite_end
{
	meta:
		script = "Type.print CRxMgrUnite,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}