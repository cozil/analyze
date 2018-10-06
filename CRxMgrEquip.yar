rule CRxMgrEquip_start
{
	meta:
		script = "Type.as CRxMgrEquip"
		script = "Type.aanc CRxMgrEquip,CRxMgr"
		script = "Type.comment CRxMgrEquip, \"装备栏管理\""
		script = "Type.ad CRxMgrEquip,\"inline void click_close() {{ click(0xd); }}\""
	condition:
		true
}


//23c CRxWnd * dlg;
rule CRxMgrEquip_dlg
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrEquip,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 8B [6] 6A 78 E8 [4] 83 C4 08 6A 04 6A 0F 68 04 01 00 00 6A 5C 68 F1 00 00 00 6A 17 }
	condition:
		#pattern == 1
}

//274 CRxButton * dlg_bn_close;
//rule CRxMgrEquip_dlg_bn_close
//{
//	meta:
//		script = "$result = [@pattern + 0x22]"
//		script = "Type.am CRxMgrEquip,CRxButton*,dlg_bn_close,0,$result"
//	strings:
//		$pattern = { 6A 0D [3] 1A [3] E6 00 00 00 ?? 6A 1A 68 E6 00 00 00 [2] E8 [8] 89 [5] C6 [5] 01 }
//	condition:
//		#pattern == 1
//}

//270 CRxMgrExtBag * mgr_extbag;
rule CRxMgrEquip_mgr_extbag
{
	meta:
		script = "$result = [@pattern + 0x8]"
		script = "Type.am CRxMgrEquip,CRxMgrExtBag*,mgr_extbag,0,$result"
	strings:
		$pattern = { 83 [2] 78 75 ?? 8B [5] 6A FF 6A FF 6A 01 E8 }
	condition:
		#pattern == 1
}

rule CRxMgrEquip_end
{
	meta:
		script = "Type.print CRxMgrEquip,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}