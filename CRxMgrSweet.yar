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
		script = "$result = [@pattern + 0x1e]"
		script = "Type.am CRxMgrSweet,CRxMgrFlower*,mgr_flower,0,$result"
	strings:
		$pattern = { c6 [2] 02 [7] e8 [8] 68 [7] 89 [5] e8 [10] c6 [2] 03 }
	condition:
		#pattern == 1
}

//234 CRxMgrSweetState * mgr_state;
rule CRxMgrSweet_state
{
	meta:
		script = "$result = [@pattern + 0x1e]"
		script = "Type.am CRxMgrSweet,CRxMgrSweetState*,mgr_state,0,$result"
	strings:
		$pattern = { c6 [2] 04 [7] e8 [8] 68 [7] 89 [5] e8 [10] c6 [2] 05 }
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