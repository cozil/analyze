rule CRxMgrDrug_start
{
	meta:
		script = "Type.as CRxMgrDrug"
		script = "Type.aanc CRxMgrDrug,CRxMgr"
		script = "Type.comment CRxMgrDrug, \"制药管理\""
		script = "Type.ad CRxMgrDrug,\"static const int close_id = 0x61;\""
		script = "Type.ad CRxMgrDrug,\"static const int confirm_id = 0x62;\""
		script = "Type.ad CRxMgrDrug,\"static const int cancel_id = 0x63;\""
		script = "Type.ad CRxMgrDrug,\"static const int msg_close_id = 0x65;\""
		script = "Type.ad CRxMgrDrug,\"inline void click_close() {{ click(close_id); }}\""
		script = "Type.ad CRxMgrDrug,\"inline void click_confirm() {{ click(confirm_id); }}\""
		script = "Type.ad CRxMgrDrug,\"inline void click_cancel() {{ click(cancel_id); }}\""
		script = "Type.ad CRxMgrDrug,\"inline void click_msg_close() {{ click(msg_close_id); }}\""
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrDrug_dlg
{
	meta:
		script = "$result = [@pattern + 0x5e]"
		script = "Type.am CRxMgrDrug,CRxWnd*,dlg,0,$result"
		script = "Type.mcomment CRxMgrDrug,dlg,\"制药窗口\""
	strings:
		$pattern = { 83 ?? 64 [41] 6A 01 [6] 6A 01 [18] 68 [7] E8 [4] 83 C4 24 6A 01 [2] 89 }
	condition:
		#pattern == 1
}

//248 CRxWnd * dlg_msg;
rule CRxMgrDrug_dlg_msg
{
	meta:
		script = "$result = [@pattern + 0x44]"
		script = "Type.am CRxMgrDrug,CRxWnd*,dlg_msg,0,$result"
		script = "Type.mcomment CRxMgrDrug,dlg,\"制药成功窗口，需要关闭后才能制药\""
	strings:
		$pattern = { 6A 01 6A 01 ?? 68 [4] D1 E9 ?? D1 EA [3] E8 [8] 8B [5] 89 }
	condition:
		#pattern == 1
}

//2bc RX_DRUG_ITEM drugList[0x25];
rule CRxMgrDrug_drugList
{
	meta:
		script = "$result = [@pattern + 0x2f]"
		script = "Type.am CRxMgrDrug,RX_DRUG_ITEM,drugList,0x25,$result"
		script = "Type.mcomment CRxMgrDrug,drugList,\"成功找到成员偏移时表示结构RX_DRUG_ITEM未改变\""
	strings:
		$pattern = { 68 00 01 00 00 ?? E8 [6] 90 01 00 00 8D 95 [4] 6A 01 [3] E8 [28] 6A FF 89 [5] 6A 40 }
	condition:
		#pattern == 1
}

rule CRxMgrDrug_end
{
	meta:
		script = "Type.print CRxMgrDrug,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}