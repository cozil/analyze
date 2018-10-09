rule CRxMgrFynode_start
{
	meta:
		script = "Type.as CRxMgrFynode"
		script = "Type.aanc CRxMgrFynode,CRxMgr"
		script = "Type.comment CRxMgrFynode, \"风云据点管理\""
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrFynode_dlg
{
	meta:
		script = "$result = [@pattern + 0x19]"
		script = "Type.am CRxMgrFynode,CRxWnd*,dlg,0,$result"	
	strings:
		$pattern = { D9 5D ?? 8B 4D ?? 6A 63 68 [4] 68 [4] 57 51 52 50 56 89 86 }
	condition:
		#pattern == 1
}

rule CRxMgrFynode_end
{
	meta:
		script = "Type.print CRxMgrFynode,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}