
//
//CRxMgrLogin部分成员分析
//

rule CRxMgrLogin_start
{
	meta:
		script = "Type.as CRxMgrLogin"
		script = "Type.aanc CRxMgrLogin,CRxMgr"
		script = "Type.ad CRxMgrLogin,\"inline void click_login_confirm() {{ click(0x7b); }}\""
		script = "Type.ad CRxMgrLogin,\"inline void click_login_cancel() {{ click(0x7c); }}\""
		script = "Type.ad CRxMgrLogin,\"inline void click_msgbox_confirm() {{ click(0x63); }}\""
		script = "Type.ad CRxMgrLogin,\"inline void click_server_exit() {{ click(0x0); }}\""
		script = "Type.ad CRxMgrLogin,\"inline void click_server_connect() {{ click(0x1); }}\""
		script = "Type.ad CRxMgrLogin,\"inline void click_server_item(int id) {{ click(0xa+id); }} //id:[0,9] \""
	condition:
		true
}

//24c CRxWndLogin *	dlg_login;
//250 CRxEdit *	edit_account;
//254 CRxEdit * edit_password;
rule CRxMgrLogin_dlg_login
{
	meta:
		script = "$result = [@pattern + 0x1f]"
		script = "Type.am CRxMgrLogin,CRxWnd*,dlg_login,0,$result"		
		script = "$result = [@pattern + 0x94]"
		script = "Type.am CRxMgrLogin,CRxEdit*,login_edit_account,0,$result"
		script = "Type.mcomment CRxMgrLogin,login_edit_account,\"输入帐户框\""
		script = "$result = [@pattern + 0x15d]"
		script = "Type.am CRxMgrLogin,CRxEdit*,login_edit_password,0,$result"
		script = "Type.mcomment CRxMgrLogin,login_edit_password,\"输出密码框\""		
	strings:
		$pattern = { 6A 01 6A 01 56 68 [4] 57 51 8B C8 E8 [4] EB ?? [90] 68 C8 00 00 00 53 56 6A 0E 68 A5 00 00 00 6A 56 6A 58 8B C8 E8 [4] EB ?? 33 C0 50 6A 78 88 5D ?? 89 86 [4] E8 [158] 68 C9 00 00 00 6A 01 56 6A 0E 68 A5 00 00 00 6A 73 6A 58 8B C8 E8 [4] EB ?? 33 C0 50 6A 78 88 5D ?? 89 86 [4] E8 }
	condition:
		#pattern == 1	
}


//rule CRxMgrLogin_login_bn_confirm
//{
//	meta:
//		script = "$result = [@pattern + 0x28]"
//		script = "Type.am CRxMgrLogin,CRxButton*,login_bn_confirm,0,$result"
//	strings:
//		$pattern = { 6A 7B [3] B2 00 00 00 [3] 55 [2] B2 00 00 00 ?? 55 [2] E8 [4] EB [3] 8B [5] 89 86 }
//	condition:
//		#pattern == 1
//}

//29c CRxWndMsgBox * dlg_msgbox;
rule CRxMgrLogin_dlg_msgbox
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxMgrLogin,CRxWnd*,dlg_msgbox,0,$result"
		script = "Type.mcomment CRxMgrLogin, dlg_msgbox, \"flag:0-正在连接, 1-登录出错\""
	strings:
		$pattern = { 6A 02 56 68 [4] 68 [4] 68 [4] 57 51 8B C8 E8 [4] EB ?? 33 C0 6A 01 8B C8 88 5D ?? 89 86 [4] E8 [4] 8B 8E [4] 53 E8 }
	condition:
		#pattern == 1	
}

rule CRxMgrLogin_msgbox_lb_text
{
	meta:
		script = "Type.offset CRxMgrLogin, dlg_msgbox"
		script = "$compare = $result"
		script = "$offset = 0x1e"
		load = "utils/match_dword_at.scr"
		script = "$result = [$result + 0x24]"
		script = "Type.am CRxMgrLogin,CRxLabelEx*,msgbox_lb_text,0,$result"
	strings:
		$pattern = { 6A 01 [2] 6A 73 68 03 01 00 00 6A 05 6A 3C 6A 14 8B C8 E8 [8] 8B 96 [4] 89 86 }
	condition:
		#pattern >= 1
}

//rule CRxMgrLogin_msgbox_bn_cancel
//{
//	meta:
//		script = "$result = [@pattern + 0x28]"
//		script = "Type.am CRxMgrLogin,CRxButton*,msgbox_bn_cancel,0,$result"
//	strings:
//		$pattern = { 6A 63 56 81 C1 B2 00 00 00 51 83 C2 77 52 68 B2 00 00 00 6A 77 8B C8 E8 [8] 8B 8E [4] 89 86 }
//	condition:
//		#pattern == 1
//}

//2b4 CRxWndServer * dlg_server;
rule CRxMgrLogin_dlg_server
{
	meta:
		script = "$result = [@pattern + 0x1f]"
		script = "Type.am CRxMgrLogin,CRxWnd*,dlg_server,0,$result"
	strings:
		$pattern = { 6A 01 6A 01 56 68 [4] 52 57 8B C8 E8 [4] EB ?? 33 C0 53 8B C8 88 5D ?? 89 86 [4] E8 [4] 8B 8E [4] 53 E8 }
	condition:
		#pattern == 1	
}

//2b8 CRxButton * server_bn_svr_list[0x0a];
rule CRxMgrLogin_server_bn_svr_list
{
	meta:
		script = "$result = [@pattern + 0xe]"
		script = "Type.am CRxMgrLogin,CRxLabel*,server_lb_svr_list,0x0a,$result-0x50"
		script = "Type.am CRxMgrLogin,CRxLabel*,server_lb_line_list,0x0a,$result-0x28"
		script = "Type.am CRxMgrLogin,CRxButton*,server_bn_svr_list,0x0a,$result"
		script = "Type.am CRxMgrLogin,CRxButton*,server_bn_line_list,0x0a,$result+0x28"
		script = "Type.am CRxMgrLogin,CRxLabel*,server_lb_status_list,0x0a,$result+0x50"
	strings:
		$pattern = { E8 [7] 14 00 00 00 8D BE [10] 0A 00 00 00 [14] E8 [4] 68 F0 03 00 00 E8 [4] 83 C4 04 [6] 09 }
	condition:
		#pattern == 1
}

//380 CRxButton * server_bn_exit;
//rule CRxMgrLogin_server_bn_exit
//{
//	meta:
//		script = "$result = [@pattern + 0x2b]"
//		script = "Type.am CRxMgrLogin,CRxButton*,server_bn_exit,0,$result"	
//	strings:
//		$pattern = { 81 C1 2F 01 00 00 51 81 C2 9F 01 00 00 52 68 2F 01 00 00 68 9F 01 00 00 8B C8 E8 [8] 8B 8E [4] 89 86 [4] 83 C1 28 }
//	condition:
//		#pattern == 1
//}

//384 CRxButton * server_bn_connect;
//rule CRxMgrLogin_server_bn_connect
//{
//	meta:
//		script = "$result = [@pattern + 0x2e]"
//		script = "Type.am CRxMgrLogin,CRxButton*,server_bn_connect,0,$result"
//	strings:
//		$pattern = { 6A 01 56 81 C2 2F 01 00 00 52 81 C1 1C 01 00 00 51 68 2F 01 00 00 68 1C 01 00 00 8B C8 E8 [8] 8B 96 [4] 89 86 }
//	condition:
//		#pattern == 1
//}

//388 SERVER_OBJECT * svrlist;
rule CRxMgrLogin_svrlist
{
	meta:
		script = "$result = [@pattern + 0x02]"
		script = "Type.am CRxMgrLogin,ServerObject*,svrlist,0,$result"
	strings:
		$pattern = { 8B 8E [4] 33 C0 89 45 ?? 3B C8 74 [20] 83 F8 64 0F 8F [4] 83 F8 33 7D ?? C7 45 ?? 00 00 00 00 EB ?? 33 C9 83 F8 5B }
	condition:
		#pattern == 1	
}

rule CRxMgrLogin_end
{
	meta:
		script = "Type.print CRxMgrLogin,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
