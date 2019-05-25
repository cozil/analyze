rule CRxMgrTrade_start
{
	meta:
		script = "Type.as CRxMgrTrade"
		script = "Type.aanc CRxMgrTrade,CRxMgr"
		script = "Type.comment CRxMgrTrade, \"交易管理\""
		script = "Type.ad CRxMgrTrade,\"inline void click_confirm_cancel() {{ click(0x5f); }}\""
		script = "Type.ad CRxMgrTrade,\"inline void click_confirm_accept() {{ click(0x60); }}\""
		script = "Type.ad CRxMgrTrade,\"inline void click_confirm_reject() {{ click(0x61); }}\""
		
		script = "Type.ad CRxMgrTrade,\"inline void click_accept() {{ click(0x62); }}\""
		script = "Type.ad CRxMgrTrade,\"inline void click_close() {{ click(0x63); }}\""
		
		script = "Type.ad CRxMgrTrade,\"inline bool req_activated() const {{ return (dlg_confirm->visible != 0); }}\""
		script = "Type.ad CRxMgrTrade,\"inline bool req_trading() const {{ return (req_activated() && (dlg_confirm->flag == 0)); }}\""
		script = "Type.ad CRxMgrTrade,\"inline bool req_accepting() const {{ return (req_activated() && (dlg_confirm->flag == 1)); }}\""
		
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrTrade_dlg
{
	meta:
		script = "$result = [@pattern + 0x39]"
		script = "Type.am CRxMgrTrade,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 6A 62 [3] B4 01 00 00 [3] D5 00 00 00 ?? 68 B4 01 00 00 68 D5 00 00 00 [2] E8 [9] 6A [4] 89 [5] E8 [4] 8B }
	condition:
		#pattern == 1
}

//22c CRxWnd * dlg_confirm;
rule CRxMgrTrade_dlg_confirm
{
	meta:
		script = "$result = [@pattern + 0x47]"
		script = "Type.am CRxMgrTrade,CRxWnd*,dlg_confirm,0,$result"
	strings:
		$pattern = { 6a 01 e8 [4] 68 [4] e8 [13] C6 [2] 02 [4-20] 6A 01 [2] 6A 73 68 03 01 00 00 6A 05 6A 3C 6A 14 [2] e8 [8] 8b }
	condition:
		#pattern == 1
}

//CRxLabel * lb_buddy_name;
//CRxLabel * lb_self_name;
rule CRxMgrTrade_lb_buddy_name
{
	meta:
		script = "$result = [@pattern +0xb]]"
		script = "Type.am CRxMgrTrade,CRxLabel*,lb_buddy_name,0,$result"
		script = "Type.am CRxMgrTrade,CRxLabel*,lb_self_name,0,$result + 4"
	strings:
		$pattern = { 6A 00 8D [6] 8B [5] E8 [4] 8D ?? 27 }
	condition:
		#pattern == 1
}

//254 CRxMgrList * ls_buddy_stuffs;
//258 CRxMgrList * ls_self_stuffs;
rule CRxMgrTrade_ls_buddy_stuffs
{
	meta:
		script = "$result = byte:[@pattern + 0x1e]"
		script = "Type.am CRxMgrTrade,CRxMgrList*,ls_buddy_stuffs,0,$offset + $result"
		script = "$result = byte:[@pattern + 0x1e]"
		script = "Type.am CRxMgrTrade,CRxMgrList*,ls_self_stuffs,0,$offset + $result + 4"
	strings:
		$pattern = { C6 [2] 0F [4] 68 [5] 6A 12 [3] E8 [8] 89 }
	condition:
		CRxMgrTrade_lb_buddy_name and #pattern == 1
}

//25c CRxLabel * lb_buddy_money;
//260 CRxLabel * lb_self_money;
//rule CRxMgrTrade_lb_buddy_money
//{
//	meta:
//		script = "$result = byte:[@pattern + 0x2e]"
//		script = "Type.am CRxMgrTrade,CRxLabel*,lb_buddy_money,0,$offset + $result"
//		script = "Type.am CRxMgrTrade,CRxLabel*,lb_self_money,0,$offset + $result + 4"
//	strings:
//		$pattern = { C6 [2] 0E [18] 6A 11 68 82 00 00 00 6A 06 [2] 85 00 00 00 ?? 6A 21 [2] E8 [8] 89 }
//	condition:
//		CRxMgrTrade_lb_buddy_name and #pattern == 1
//}

//294 CRxMgrTradeTip * mtr_tip;
rule CRxMgrTrade_mtr_tip
{
	meta:
		script = "$result = [@pattern + 0x37]"
		script = "Type.am CRxMgrTrade,CRxMgrTradeTip*,mtr_tip,0,$result"
	strings:
		$pattern = { 6A 02 68 93 10 00 00 E8 [15] E8 [8] 68 FF 00 00 00 68 FF 00 00 00 ?? 68 FF 00 00 00 [5] 89 }
	condition:
		#pattern == 1
}

rule CRxMgrTrade_end
{
	meta:
		script = "Type.print CRxMgrTrade,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}