rule CRxMgrSweet_start
{
	meta:
		script = "Type.as CRxMgrSweet"
		script = "Type.aanc CRxMgrSweet,CRxMgr"
		script = "Type.comment CRxMgrSweet, \"情侣管理\""
	condition:
		true
}

//22c CRxMgrFlower * mgr_flower;
rule CRxMgrSweet_mgr_flower
{
	meta:
		script = "$result = [@pattern + 0x37]"
		script = "Type.am CRxMgrSweet,CRxMgrFlower*,mgr_flower,0,$result"
	strings:
		$pattern = { 68 78 02 00 00 [40] 68 D0 02 00 00 [3] 89 }
	condition:
		#pattern == 1
}

//234 CRxMgrSweetState * mgr_state;
rule CRxMgrSweet_state
{
	meta:
		script = "$result = [@pattern + 0x37]"
		script = "Type.am CRxMgrSweet,CRxMgrSweetState*,mgr_state,0,$result"
	strings:
		$pattern = { 68 D4 02 00 00 [40] 68 00 03 00 00 [3] 89 }
	condition:
		#pattern == 1
}


rule CRxMgrSweet_end
{
	meta:
		script = "Type.print CRxMgrSweet,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}