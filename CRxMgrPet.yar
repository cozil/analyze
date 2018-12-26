rule CRxMgrPet_start
{
	meta:
		script = "Type.as CRxMgrPet"
		script = "Type.aanc CRxMgrPet,CRxMgr"
		script = "Type.comment CRxMgrPet, \"宠物管理\""
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrPet_dlg
{
	meta:
		script = "$result = [@pattern + 0x27]"
		script = "Type.am CRxMgrPet,CRxWnd*,dlg,0,$result"
	strings:
		//17014之前版本
		//$pattern = { C7 [2] 02 00 00 00 [4] 68 C6 02 00 00 ?? 6A 10 6A 00 [2] E8 [8] A3 [4] 8B }
		$pattern = { C7 [2] 02 00 00 00 [4] 68 [5] 6A 10 6A 00 [2] E8 [8] A3 [4] 8B }
	condition:
		#pattern == 1
}

rule CRxMgrPet_end
{
	meta:
		script = "Type.print CRxMgrPet,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}