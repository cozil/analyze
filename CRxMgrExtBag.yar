rule CRxMgrExtBag_start
{
	meta:
		script = "Type.as CRxMgrExtBag"
		script = "Type.aanc CRxMgrExtBag,CRxMgr"
		script = "Type.comment CRxMgrExtBag, \"侠客行囊管理\""
		script = "Type.ad CRxMgrExtBag,\"inline bool available() const {{ return (2 == state); }}\""
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrExtBag_dlg
{
	meta:
		script = "$result = [@pattern + 0x3a]"
		script = "Type.am CRxMgrExtBag,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 68 [4] 6A 01 [3] 1B [3] D4 00 00 00 ?? 6A 1B 68 D4 00 00 00 [2] E8 [8] 89 [5] C6 [5] 01 8B [5] 8B }
	condition:
		#pattern == 1
}

//23c uint32_t state;
rule CRxMgrExtBag_state
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrExtBag,uint32_t,state,0,$result"
	strings:
		$pattern = { 83 [5] 00 [2] E8 [4] 6A 01 [2] E8 [4] 6A 01 [2] E8 }
	condition:
		#pattern == 1
}

rule CRxMgrExtBag_end
{
	meta:
		script = "Type.print CRxMgrExtBag,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}