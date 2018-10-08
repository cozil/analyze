
//
//CRxMgrShop部分成员偏移分析
//

rule CRxMgrShop_start
{
	meta:
		script = "Type.as CRxMgrShop"
		script = "Type.aanc CRxMgrShop,CRxMgr"
		script = "Type.comment CRxMgrShop,\"商店管理\""
		script = "Type.ad CRxMgrShop,\"inline void click_close() {{ click(0x5b); }}\""
		script = "Type.ad CRxMgrShop,\"inline void click_nextpage() {{ click(0x2712); }}\""
		script = "Type.ad CRxMgrShop,\"inline void click_prevpage() {{ click(0x2711); }}\""
		
	condition:
		true
}

//228 CRxWnd * dlg
//230 int npc_id
rule CRxMgrShop_dlg
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxMgrShop,CRxWnd*,dlg,0,$result"
		script = "$result = [@pattern + 0x14]"
		script = "Type.am CRxMgrShop,int,npc_id,0,$result"
	strings:
		$pattern = { 8B 86 [4] 8B 0D [4] 50 E8 [4] C7 86 [4] 00 00 00 00 8B 0D [4] C7 05 [4] 00 00 00 00 C7 05 [4] 64 00 00 00 C7 05 [4] 00 00 00 00 }
	condition:
		#pattern == 1	
}



//22C CRxList * ls_shop
rule CRxMgrShop_ls_shop
{
	meta:
		script = "$result = [@pattern + 0x21]"
		script = "Type.am CRxMgrShop,CRxList*,ls_shop,0,$result"
	strings:
		$pattern = { C6 [2] 02 [4] 6A 65 ?? 6A 3C [3] E8 [8] 8B [5] 89 }
	condition:
		#pattern == 1	
}


//250 int page_id
//254 int page_count
rule CRxMgrShop_page_id
{
	meta:
		script = "$result = [@pattern + 0x0a]"
		script = "Type.am CRxMgrShop,int,page_id,0,$result"
		script = "$result = [@pattern + 0x1f]"
		script = "Type.am CRxMgrShop,int,page_count,0,$result"
	strings:
		$pattern = { 83 F8 65 7C ?? 83 C0 9B 89 86 [4] 8B 45 ?? 85 C0 74 ?? 33 C9 83 F8 01 0F 94 C1 89 86 [4] 51 8B 8E [4] E8 }
	condition:
		#pattern == 1
}

rule CRxMgrShop_end
{
	meta:
		script = "Type.print CRxMgrShop,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
