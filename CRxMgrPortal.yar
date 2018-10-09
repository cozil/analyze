rule CRxMgrPortal_start
{
	meta:
		script = "Type.as CRxMgrPortal"
		script = "Type.aanc CRxMgrPortal,CRxMgr"
		script = "Type.comment CRxMgrPortal, \"单线地图传送窗口管理\""
		script = "Type.ad CRxMgrPortal,\"inline void click_close() {{ click(0x0); }}\""
		script = "Type.ad CRxMgrPortal,\"inline void click_confirm() {{ click(0x1); }}\""
		script = "Type.ad CRxMgrPortal,\"inline void click_cancel() {{ click(0x2); }}\""
		
		script = "Type.ad CRxMgrPortal,\"bool available(void) const;\""
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrPortal_dlg
{
	meta:
		script = "$result = [@pattern + 0x26]"
		script = "Type.am CRxMgrPortal,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 68 [4] 53 56 83 C1 04 51 81 C2 E3 00 00 00 52 6A 04 68 E3 00 00 00 8B C8 E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 }
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