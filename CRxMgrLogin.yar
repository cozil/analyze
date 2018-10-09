
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
//250 CRxEdit *	login_edit_account;
//254 CRxEdit * login_edit_password;
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

//2a0 CRxLableEx * msgbox_lb_text;
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
