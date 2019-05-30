rule CRxMgrDead_start
{
	meta:
		script = "Type.as CRxMgrDead"
		script = "Type.aanc CRxMgrDead,CRxMgr"
		script = "Type.comment CRxMgrDead, \"死亡保护管理\""
		script = "Type.ad CRxMgrDead,\"static const int dead_protect1_id = 0x385;\""
		script = "Type.ad CRxMgrDead,\"static const int dead_protect2_id = 0x386;\""
		script = "Type.ad CRxMgrDead,\"static const int dead_noprotect_id = 0x387;\""
		script = "Type.ad CRxMgrDead,\"static const int dead_close_id = 0x387;\""				
		script = "Type.ad CRxMgrDead,\"static const int pay_confirm_id = 0x388;\""
		script = "Type.ad CRxMgrDead,\"static const int pay_cancel_id = 0x389;\""		
		script = "Type.ad CRxMgrDead,\"static const int payfail_id = 0x38b;\""
		
		script = "Type.ad CRxMgrDead,\"inline void click_dead_protected1() {{ click(dead_protect1_id); }}\""
		script = "Type.ad CRxMgrDead,\"inline void click_dead_protected2() {{ click(dead_protect2_id); }}\""
		script = "Type.ad CRxMgrDead,\"inline void click_dead_noprotect() {{ click(dead_noprotect_id); }}\""
		
		script = "Type.ad CRxMgrDead,\"inline void click_dead_close() {{ click(dead_close_id); }}\""
		script = "Type.ad CRxMgrDead,\"inline void click_pay_confirm() {{ click(pay_confirm_id); }}\""
		script = "Type.ad CRxMgrDead,\"inline void click_pay_cancel() {{ click(pay_cancel_id); }}\""
		script = "Type.ad CRxMgrDead,\"inline void click_payfail() {{ click(payfail_id); }}\""
	condition:
		true
}

//230 CRxWnd * dlg_dead;
rule CRxMgrDead_dlg_dead
{
	meta:
		script = "$result = [@pattern + 0x48]"
		script = "Type.am CRxMgrDead,CRxWnd*,dlg_dead,0,$result"
	strings:
		$pattern = { 68 [26] C6 [2] 01 [10] 6A 01 6A 01 ?? 68 [8] E8 [9] 6A 78 88 [2] 89 }
	condition:
		#pattern == 1
}

//248 CRxWnd * dlg_pay;
rule CRxMgrDead_dlg_pay
{
	meta:
		script = "$result = [@pattern + 0x2d]"
		script = "Type.am CRxMgrDead,CRxWnd*,dlg_pay,0,$result"
	strings:
		$pattern = { C6 [2] 06 [10] 6A 01 6A 01 ?? 68 [8] E8 [9] 6A 78 88 [2] 89 }
	condition:
		#pattern == 1
}

//264 CRxWnd * dlg_payfail;
rule CRxMgrDead_dlg_payfail
{
	meta:
		script = "$result = [@pattern + 0x2d]"
		script = "Type.am CRxMgrDead,CRxWnd*,dlg_payfail,0,$result"
	strings:
		$pattern = { C6 [2] 0C [10] 6A 01 6A 01 ?? 68 [8] E8 [11] 88 [2] 89 }
	condition:
		#pattern == 1
}


//int lucky_flag;
rule CRxMgrDead_lucky_flag
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrDead,uint32_t,lucky_flag,0,$result"
	strings:
		$pattern = { 80 [5] 00 [2] 80 [5] 00 [2] 83 [5] 13 }
	condition:
		#pattern == 1
}

rule CRxMgrDead_end
{
	meta:
		script = "Type.print CRxMgrDead,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}