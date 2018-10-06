rule CRxMgrFlower_start
{
	meta:
		script = "Type.as CRxMgrFlower"
		script = "Type.aanc CRxMgrFlower,CRxMgr"
		script = "Type.comment CRxMgrFlower, \"送收花管理\""
		script = "Type.ad CRxMgrFlower,\"inline void click_hint_confirm() {{ click(0x5); }}\""
		script = "Type.ad CRxMgrFlower,\"inline void click_send_confirm() {{ click(0x6); }}\""
		script = "Type.ad CRxMgrFlower,\"inline void click_send_cancel() {{ click(0x7); }}\""
		script = "Type.ad CRxMgrFlower,\"inline void click_recv_confirm() {{ click(0x8); }}\""
		script = "Type.ad CRxMgrFlower,\"inline void click_recv_cancel() {{ click(0x9); }}\""
	condition:
		true
}

//248 CRxWnd * dlg_hint;
//24c CRxButton * hint_bn_confirm;
rule CRxMgrFlower_dlg_hint
{
	meta:
		script = "$result = [@pattern + 0x21]"
		script = "Type.am CRxMgrFlower,CRxWnd*,dlg_hint,0,$result"
		script = "Type.mcomment CRxMgrFlower,dlg_hint,\"收到花时右下角闪烁提示窗口\""
		//script = "$result = [@pattern + 0x34]"
		//script = "Type.am CRxMgrFlower,CRxButton*,hint_bn_confirm,0,$result"
	strings:
		$pattern = { 6A 05 D9 9D [4] 68 [5] 8B [6] 8B [9] 89 [5] E8 [4] 83 C4 4C 68 40 01 00 00 89 }
	condition:
		#pattern == 1
}

//250 CRxWnd * dlg_send;
//258 CRxButton * send_bn_confirm;
//25c CRxButton * send_bn_cancel;
rule CRxMgrFlower_dlg_send
{
	meta:
		script = "$result = [@pattern + 0x24]"
		script = "Type.am CRxMgrFlower,CRxWnd*,dlg_send,0,$result"
		script = "$result = [@pattern + 0x1e]"
		//script = "Type.am CRxMgrFlower,CRxButton*,send_bn_confirm,0,$result"
		//script = "Type.am CRxMgrFlower,CRxButton*,send_bn_cancel,0,$result+4"
	strings:
		$pattern = { 6A 06 68 [4] 68 [9] E8 [4] D9 05 [4] 89 [5] 8B [5] D9 9D }
	condition:
		#pattern == 1
}


//264 CRxWnd * dlg_receive;
//26c CRxButton * receive_bn_confirm;
//270 CRxButton * receive_bn_cancel;
rule CRxMgrFlower_dlg_receive
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrFlower,CRxWnd*,dlg_receive,0,$result"
		//script = "$result = [@pattern + 0x2f]"
		//script = "Type.am CRxMgrFlower,CRxButton*,receive_bn_confirm,0,$result"
		//script = "$result = [@pattern + 0x4c]"
		//script = "Type.am CRxMgrFlower,CRxButton*,receive_bn_cancel,0,$result"
	strings:
		$pattern = { 8B [5] D9 9D [4] D9 05 [4] 8B [6] D9 9D [5] 6A 09 68 [4] 68 [5] 89 [5] 8B [9] E8 [4] 83 C4 50 68 [4] 89 }
	condition:
		#pattern == 1
}

rule CRxMgrFlower_end
{
	meta:
		script = "Type.print CRxMgrFlower,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}