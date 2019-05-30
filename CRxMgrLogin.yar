
//
//CRxMgrLogin部分成员分析
//

rule CRxMgrLogin_start
{
	meta:
		script = "Type.as CRxMgrLogin"
		script = "Type.aanc CRxMgrLogin,CRxMgr"
		script = "Type.ad CRxMgrLogin,\"static const int login_confirm_id = 0x7b;\""
		script = "Type.ad CRxMgrLogin,\"static const int login_cancel_id = 0x7c;\""
		script = "Type.ad CRxMgrLogin,\"static const int msgbox_confirm_id = 0x63;\""
		script = "Type.ad CRxMgrLogin,\"static const int server_exit_id = 0x0;\""
		script = "Type.ad CRxMgrLogin,\"static const int server_connect_id = 0x1;\""
		script = "Type.ad CRxMgrLogin,\"static const int server_item_id = 0xa;\""
		
		script = "Type.ad CRxMgrLogin,\"inline void click_login_confirm() {{ click(login_confirm_id); }}\""
		script = "Type.ad CRxMgrLogin,\"inline void click_login_cancel() {{ click(login_cancel_id); }}\""
		script = "Type.ad CRxMgrLogin,\"inline void click_msgbox_confirm() {{ click(msgbox_confirm_id); }}\""
		script = "Type.ad CRxMgrLogin,\"inline void click_server_exit() {{ click(server_exit_id); }}\""
		script = "Type.ad CRxMgrLogin,\"inline void click_server_connect() {{ click(server_connect_id); }}\""
		script = "Type.ad CRxMgrLogin,\"inline void click_server_item(int id) {{ click(server_item_id+id); }} //id:[0,9] \""

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
	strings:
		$pattern = { 6A 01 6A 01 [25] 89 [5] E8 [11] E8 [11] E8 [11] E8 [47] 68 C8 00 00 00 }
	condition:
		#pattern == 1
}


rule CRxMgrLogin_login_edit_account
{
	meta:
		script = "$result = [@pattern + 0x25]"
		script = "Type.am CRxMgrLogin,CRxEdit*,login_edit_account,0,$result"
		script = "Type.mcomment CRxMgrLogin,login_edit_account,\"输入帐户框\""
	strings:
		$pattern = { 68 C8 00 00 00 [2] 6A 0E 68 A5 00 00 00 6A 56 6A 58 [2] E8 [14] 89 }
	condition:
		#pattern == 1	
}

rule CRxMgrLogin_login_edit_password
{
	meta:
		script = "$result = [@pattern + 0x26]"
		script = "Type.am CRxMgrLogin,CRxEdit*,login_edit_password,0,$result"
		script = "Type.mcomment CRxMgrLogin,login_edit_password,\"输出密码框\""		
	strings:
		$pattern = { 68 C9 00 00 00 6A 01 ?? 6A 0E 68 A5 00 00 00 6A 73 6A 58 [2] E8 [14] 89 }
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
		script = "$offset = 0x2d"
		load = "utils/match_dword_at.scr"
		script = "$result = [$result + 0x33]"
		script = "Type.am CRxMgrLogin,CRxLabelEx*,msgbox_lb_text,0,$result"
	strings:
		$pattern = { C6 [2] 10 [11] 6A 01 [2] 6A 73 68 03 01 00 00 6A 05 6A 3C 6A 14 [2] E8 [8] 8B [5] 89 }
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


rule CRxMgrLogin_ServerObject
{
	meta:
		//这两个为静态结构
		script = "Type.print LineInfo,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		script = "Type.print ServerHead,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
			
		//ServerItem结构
		script = "$result = [@pattern + 0x32] - [@pattern + 0x2b]"
		script = "Type.as ServerItem"
		script = "Type.am ServerItem,ServerHead,head,0,0"
		script = "Type.am ServerItem,LineInfo,lines,0x0a,$result"
		script = "Type.print ServerItem,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		
		//ServerObject结构
		script = "$result = [@pattern + 0x32]"
		script = "Type.as ServerObject"
		script = "Type.am ServerObject,ServerItem,servers,0x0a,$result"		
		script = "Type.print ServerObject,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
		
		//检查ServerItem大小
		script = "$result1 = [@pattern + 0x1a]"
		script = "Type.size ServerItem"
		script = "cmp $result,$result1"
		script = "jz _EXIT"
		script = "log \"Size of ServerItem has changed from 0x{$result} to 0x{$result1}\""
		script = "msg \"ServerItem结构发生改变\""
		script = "_EXIT:"
	strings:
		$pattern = { 83 ?? 0A [12] 83 ?? 0A [6] 69 [14] 0F [7] 0F [6] 6A 0D }
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
		//$pattern = { 8B 8E [4] 33 C0 89 45 ?? 3B C8 74 [20] 83 F8 64 0F 8F [4] 83 F8 33 7D ?? C7 45 ?? 00 00 00 00 EB ?? 33 C9 83 F8 5B }
		$pattern = { 8B [20] 69 [14] 64 [8] 33 [5] 00 00 00 00 [6] 5B }
		
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
