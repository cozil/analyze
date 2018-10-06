rule CRxMgrMaker_start
{
	meta:
		script = "Type.as CRxMgrMaker"
		script = "Type.comment CRxMgrMaker, \"制造管理\""
		script = "Type.ad CRxMgrMaker,\"inline bool is_dlg_simth() const {{ return dlg->flag == 0; }}\""
		script = "Type.ad CRxMgrMaker,\"inline bool is_dlg_sewer() const {{ return dlg->flag == 1; }}\""
		script = "Type.ad CRxMgrMaker,\"inline bool is_dlg_chemist() const {{ return dlg->flag == 2; }}\""
		script = "Type.ad CRxMgrMaker,\"inline bool is_dlg_breaker() const {{ return dlg->flag == 3; }}\""
		script = "Type.ad CRxMgrMaker,\"inline void click_makeit() {{ click(0x1); }}\""
		script = "Type.ad CRxMgrMaker,\"inline void click_cancel() {{ click(0x2); }}\""
	condition:
		true
}

//CRxWnd * dlg;
rule CRxMgrMaker_dlg
{
	meta:
		script = "$result = [@pattern + 0x18]"
		script = "Type.am CRxMgrMaker,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 6A 5D ?? 6A 64 ?? 8B C8 E8 [4] EB ?? 33 C0 A3 [4] 8B 8E }
	condition:
		#pattern == 1
}

//CRxButton * dlg_bn_confirm;
//rule CRxMgrMaker_dlg_bn_confirm
//{
//	meta:
//		script = "$result = [@pattern + 0x11]"
//		script = "Type.am CRxMgrMaker,CRxButton*,dlg_bn_confirm,0,$result"
//	strings:
//		$pattern = { 6A 02 D9 5D ?? 68 [4] 68 [4] 89 86 [4] 8B 45 ?? 53 50 51 8B 96 2C 02 00 00 6A 04 }
//	condition:
//		#pattern == 1
//}

//CRxButton * dlg_bn_close;
//rule CRxMgrMaker_dlg_bn_close
//{
//	meta:
//		script = "$result = [@pattern + 0x12]"
//		script = "Type.am CRxMgrMaker,CRxButton*,dlg_bn_close,0,$result"
//	strings:
//		//89 86 [4] E8 [5] 30 00 00 00 68 F4 23 00 00 [8] 4C 00 00 00 [12] 6D 00 00 00 [12] 8E 00 00 00 [12] AF 00 00 00
//		$pattern = { 83 C4 50 68 90 01 00 00 8D BE [4] 53 57 89 86 [4] E8 [4] B8 30 00 00 00 68 F4 23 00 00 }
//	condition:
//		#pattern == 1
//}

//CRxCombo * cb_items;
rule CRxMgrMaker_dlg_cb_items
{
	meta:
		script = "$result = [@pattern + 0x1e]"
		script = "Type.am CRxMgrMaker,CRxCombo*,cb_items,0,$result"
	strings:
		$pattern = { 6A 10 68 CB 00 00 00 6A 38 6A 4E [2] E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//RX_MEMBLOCK makerDataList[0x11];
rule crxMgrMaker_makerDataList
{
	meta:
		script = "$result = [@pattern + 0x18]"
		script = "Type.am CRxMgrMaker,RX_MEMBLOCK,makerDataList,0x11,$result"
		SCRIPT = "Type.mcomment CRxMgrMaker,makerDataList,\"RX_MAKER_ITEM结构，遇到空值结束检索\""
		script = "lblset [@pattern + 0x6], \"RX_MEMBLOCK::destroy\""
		script = "lblset [@pattern + 0xb], \"RX_MEMBLOCK::init\""
	strings:
		$pattern = { E8 [4] 68 [4] 68 [4] 6A 11 6A 10 8D 86 [4] 50 89 5D ?? C7 06 [4] E8 }
	condition:
		#pattern == 1
}

