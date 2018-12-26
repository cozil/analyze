rule CRxMgrUnite_start
{
	meta:
		script = "Type.as CRxMgrUnite"
		script = "Type.aanc CRxMgrUnite,CRxMgr"
		script = "Type.comment CRxMgrUnite,\"合成管理\""
		script = "Type.ad CRxMgrUnite,\"inline void click_close() {{ click(0x61); }}\""
		script = "Type.ad CRxMgrUnite,\"inline void click_confirm() {{ click(0x62); }}\""
		script = "Type.ad CRxMgrUnite,\"inline void click_cancel() {{ click(0x63); }}\""
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
		//17014之前版本
		//$pattern = { 6A 01 8B C8 89 86 [4] E8 [4] 68 F4 23 00 00 C7 45 ?? 7D 00 00 00 C7 45 ?? BA 00 00 00 E8 [18] 6A 53 56 6A 01 }
		$pattern = { 6A 01 8B C8 89 86 [4] E8 [4] 68 F4 23 00 00 C7 45 ?? 7D 00 00 00 C7 45 ?? BA 00 00 00 E8 [18] 6A 60 56 6A 01 }
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