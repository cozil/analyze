rule CRxMgrMakerFrame_start
{
	meta:
		script = "Type.as CRxMgrMakerFrame"
		script = "Type.aanc CRxMgrMakerFrame,CRxMgr"
		script = "Type.comment CRxMgrMakerFrame,\"制造框架窗口管理\""
		script = "Type.ad CRxMgrMakerFrame,\"static const int smith_id = 0x898;\""
		script = "Type.ad CRxMgrMakerFrame,\"static const int sewer_id = 0x899;\""
		script = "Type.ad CRxMgrMakerFrame,\"static const int chemist_id = 0x89a;\""
		script = "Type.ad CRxMgrMakerFrame,\"static const int breaker_id = 0x89b;\""
		script = "Type.ad CRxMgrMakerFrame,\"static const int close_id = 0x61;\""
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrMakerFrame_dlg
{
	meta:
		script = "$result = [@pattern + 0x8]"
		script = "Type.am CRxMgrMakerFrame,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { D9 05 [4] 8B 96 [4] D9 5D ?? D9 05 [4] 8B 4D ?? 6A 00 D9 5D ?? 8B 45 ?? 6A 00 68 98 08 00 00 }
	condition:
		#pattern == 1
}

rule CRxMgrMakerFrame_end
{
	meta:
		script = "Type.print CRxMgrMakerFrame,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
