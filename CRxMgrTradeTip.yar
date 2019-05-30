rule CRxMgrTradeTip_start
{
	meta:
		script = "Type.as CRxMgrTradeTip"
		script = "Type.aanc CRxMgrTradeTip,CRxMgr"
		script = "Type.comment CRxMgrTradeTip, \"交易防骗提醒管理\""
		script = "Type.ad CRxMgrTradeTip,\"static const int confirm_id = 0x1;\""
		script = "Type.ad CRxMgrTradeTip,\"static const int cancel_id = 0x2;\""
		script = "Type.ad CRxMgrTradeTip,\"inline void click_confirm() {{ click(confirm_id); }}\""
		script = "Type.ad CRxMgrTradeTip,\"inline void click_cancel() {{ click(cancel_id); }}\""
	condition:
		true
}

//238 CRxWnd * dlg;
rule CRxMgrTradeTip_dlg
{
	meta:
		script = "$result = [@pattern + 0x30]"
		script = "Type.am CRxMgrTradeTip,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 6A 02 6A 00 6A 00 [2] 6A 00 6A 00 [22] E8 [4] 83 C4 24 6A 00 [2] 89 }
	condition:
		#pattern == 1
}

rule CRxMgrTradeTip_end
{
	meta:
		script = "Type.print CRxMgrTradeTip,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}