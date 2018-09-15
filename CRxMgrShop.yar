
//
//CRxMgrShop部分成员偏移分析
//

rule CRxMgrShop_start
{
	meta:
		script = "log \"struct CRxMgrShop {\""
	condition:
		true
}

//228 CRxWndShop * dlg
//230 int npc_id
rule CRxMgrShop_dlg
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"/*{p:$result}*/    CRxWndShop * dlg;\""
		script = "$result = [@pattern + 0x14]"
		script = "log \"/*{p:$result}*/    int npc_id;\""
	strings:
		$pattern = { 8B 86 [4] 8B 0D [4] 50 E8 [4] C7 86 [4] 00 00 00 00 8B 0D [4] C7 05 [4] 00 00 00 00 C7 05 [4] 64 00 00 00 C7 05 [4] 00 00 00 00 }
	condition:
		#pattern == 1	
}



//22C CRxList * ls_shop
rule CRxMgrShop_ls_shop
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "log \"/*{p:$result}*/    CRxList * ls_shop;\""
	strings:
		$pattern = { 8B 89 [4] 85 C9 74 09 6A 07 6A 00 E8 [4] C3 }
	condition:
		#pattern == 1	
}

//250 int page_id
//254 int page_count
rule CRxMgrShop_page_id
{
	meta:
		script = "$result = [@pattern + 0x0a]"
		script = "log \"/*{p:$result}*/    int page_id;\""
		script = "$result = [@pattern + 0x1f]"
		script = "log \"/*{p:$result}*/    int page_count;\""
	strings:
		$pattern = { 83 F8 65 7C ?? 83 C0 9B 89 86 [4] 8B 45 ?? 85 C0 74 ?? 33 C9 83 F8 01 0F 94 C1 89 86 [4] 51 8B 8E [4] E8 }
	condition:
		#pattern == 1
}

rule CRxMgrShop_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}
