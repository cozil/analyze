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
		$pattern = { 6A 01 8B C8 89 86 [4] E8 [4] 68 F4 23 00 00 C7 45 ?? 7D 00 00 00 C7 45 ?? BA 00 00 00 E8 [18] 6A 53 56 6A 01 }
	condition:
		#pattern == 1
}

//238 CRxButton * dlg_bn_close;
//rule CRxMgrUnite_dlg_bn_close
//{
//	meta:
//		script = "$result = [@pattern + 0x10]"
//		script = "Type.am CRxMgrUnite,CRxButton*,dlg_bn_close,0,$result"
//	strings:
//		$pattern = { 53 6A 62 68 [4] 68 [4] 53 89 86 [4] 8B 45 ?? 50 51 52 56 E8 }
//	condition:
//		#pattern == 1
//}

//230 CRxButton * dlg_bn_confirm
//234 CRxButton * dlg_bn_cancel
//rule CRxMgrUnite_dlg_bn_confirm
//{
//	meta:
//		script = "$result = [@pattern + 0x11]"
//		script = "Type.am CRxMgrUnite,CRxButton*,dlg_bn_confirm,0,$result"
//		script = "$result = [@pattern + 0x23]"
//		script = "Type.am CRxMgrUnite,CRxButton*,dlg_bn_cancel,0,$result"
//	strings:
//		$pattern = { 53 53 6A 63 68 [4] 68 [4] 53 89 86 [4] 8B 45 ?? 50 51 52 56 E8 [4] 89 86 }
//	condition:
//		#pattern == 1
//}

rule CRxMgrUnite_end
{
	meta:
		script = "Type.print CRxMgrUnite,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}