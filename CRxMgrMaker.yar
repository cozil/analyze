rule CRxMgrMaker_start
{
	meta:
		script = "Type.as CRxMgrMaker"
		script = "Type.aanc CRxMgrMaker,CRxMgr"
		script = "Type.comment CRxMgrMaker, \"制造管理\""
		script = "Type.ad CRxMgrMaker,\"inline bool is_dlg_simth() const {{ return dlg->flag == 0; }}\""
		script = "Type.ad CRxMgrMaker,\"inline bool is_dlg_sewer() const {{ return dlg->flag == 1; }}\""
		script = "Type.ad CRxMgrMaker,\"inline bool is_dlg_chemist() const {{ return dlg->flag == 2; }}\""
		script = "Type.ad CRxMgrMaker,\"inline bool is_dlg_breaker() const {{ return dlg->flag == 3; }}\""
		script = "Type.ad CRxMgrMaker,\"static const int makeit_id = 0x1;\""
		script = "Type.ad CRxMgrMaker,\"static const int cancel_id = 0x2;\""
		
		script = "Type.ad CRxMgrMaker,\"inline void click_makeit() {{ click(makeit_id); }}\""
		script = "Type.ad CRxMgrMaker,\"inline void click_cancel() {{ click(cancel_id); }}\""
	condition:
		true
}

//22c CRxWnd * dlg;
rule CRxMgrMaker_dlg
{
	meta:
		script = "$result = [@pattern + 0x18]"
		script = "Type.am CRxMgrMaker,CRxWnd*,dlg,0,$result"
	strings:
		//17014之前版本
		//$pattern = { 6A 5D ?? 6A 64 ?? 8B C8 E8 [4] EB ?? 33 C0 A3 [4] 8B 8E }
		$pattern = { 6A [2] 6A 64 ?? 8B C8 E8 [4] EB ?? 33 C0 A3 [4] 8B 8E }
	condition:
		#pattern == 1
}

//23c CRxCombo * cb_items;
rule CRxMgrMaker_dlg_cb_items
{
	meta:
		script = "$result = [@pattern + 0x1e]"
		script = "Type.am CRxMgrMaker,CRxCombo*,cb_items,0,$result"
	strings:
		$pattern = { 6A 10 68 CB 00 00 00 6A 38 6A 4E [2] E8 [4] EB ?? 33 C0 8B [5] 89 }
	condition:
		#pattern == 1
}

//c88 RX_MEMBLOCK makerDataList[0x11];
rule CRxMgrMaker_makerDataList
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "Type.am CRxMgrMaker,RX_MEMBLOCK,makerDataList,0x11,$result"
		SCRIPT = "Type.mcomment CRxMgrMaker,makerDataList,\"RX_MAKER_ITEM结构，遇到空值结束检索\""
		script = "lblset [@pattern + 0x6], \"RX_MEMBLOCK::destroy\""
		script = "lblset [@pattern + 0xb], \"RX_MEMBLOCK::init\""
	strings:
		$pattern = { E8 [4] 68 [4] 68 [4] 6A 11 6A 10 8D 86 [4] 50 89 5D ?? C7 06 [4] E8 }
	condition:
		#pattern == 1
}

rule CRxMgrMaker_end
{
	meta:
		script = "Type.print CRxMgrMaker,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}