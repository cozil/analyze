rule CRxMgrFypk_start
{
	meta:
		script = "Type.as CRxMgrFypk"
		script = "Type.aanc CRxMgrFypk,CRxMgr"
		script = "Type.comment CRxMgrFypk, \"风云大战管理\""
	condition:
		true
}

//228 CRxMgrFynode * mgr_fynode;
//22C CRxMgrFymap *	mgr_fymap;
rule CRxMgrFypk_mgr_fynode
{
	meta:
		script = "$result = [@pattern + 0x22]"
		script = "Type.am CRxMgrFypk,CRxMgrFynode*,mgr_fynode,0,$result"
		script = "Type.mcomment CRxMgrFypk,mgr_fynode,\"风云神物管理\""
		
		script = "$result = [@pattern + 0x47]"
		script = "Type.am CRxMgrFypk,CRxMgrFymap*,mgr_fymap,0,$result"
		script = "Type.mcomment CRxMgrFypk,mgr_fymap,\"风云地图管理\""
	strings:
		$pattern = { 89 45 ?? C6 45 ?? 05 [7] E8 [8] 68 4C 03 00 00 C6 45 ?? 04 89 86 [4] E8 [4] 83 C4 04 89 45 ?? C6 45 ?? 06 [7] E8 [8] 89 86 }
	condition:
		#pattern == 1
}

rule CRxMgrFypk_end
{
	meta:
		script = "Type.print CRxMgrFypk,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}