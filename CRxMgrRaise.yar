rule CRxMgrRaise_start
{
	meta:
		script = "Type.as CRxMgrRaise"
		script = "Type.aanc CRxMgrRaise,CRxMgr"
		script = "Type.comment CRxMgrRaise, \"提真管理\""
		script = "Type.ad CRxMgrRaise,\"inline void click_close() {{ click(0x61); }}\""
		script = "Type.ad CRxMgrRaise,\"inline void click_confirm() {{ click(0x62); }}\""
		script = "Type.ad CRxMgrRaise,\"inline void click_cancel() {{ click(0x63); }}\""
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrRaise_dlg
{
	meta:
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxMgrRaise,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 68 [4] 68 [4] 6A 61 [3] 1A [3] 1A ?? 6A 1A 68 02 01 00 00 [2] E8 [8] 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

rule CRxMgrRaise_end
{
	meta:
		script = "Type.print CRxMgrRaise,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}