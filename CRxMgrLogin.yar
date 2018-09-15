
//
//CRxMgrLogin部分成员分析
//

rule CRxMgrLogin_start
{
	meta:
		script = "log"
		script = "log \"struct CRxMgrLogin {\""
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
		script = "log \"/*{p:$result}*/    CRxWndLogin * dlg_login;\""
		
		script = "$result = [@pattern + 0x94]"
		script = "log \"/*{p:$result}*/    CRxEdit * edit_account;\""

		script = "$result = [@pattern + 0x15d]"
		script = "log \"/*{p:$result}*/    CRxEdit * edit_account;\""		
	strings:
		$pattern = { 6A 01 6A 01 56 68 [4] 57 51 8B C8 E8 [4] EB ?? [90] 68 C8 00 00 00 53 56 6A 0E 68 A5 00 00 00 6A 56 6A 58 8B C8 E8 [4] EB ?? 33 C0 50 6A 78 88 5D ?? 89 86 [4] E8 [158] 68 C9 00 00 00 6A 01 56 6A 0E 68 A5 00 00 00 6A 73 6A 58 8B C8 E8 [4] EB ?? 33 C0 50 6A 78 88 5D ?? 89 86 [4] E8}
	condition:
		#pattern == 1	
}

//29c CRxWndMsgBox * dlg_msgbox;
rule CRxMgrLogin_dlg_msgbox
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "log \"/*{p:$result}*/    CRxWndMsgBox * dlg_msgbox;\""	
	strings:
		$pattern = { 6A 02 56 68 [4] 68 [4] 68 [4] 57 51 8B C8 E8 [4] EB ?? 33 C0 6A 01 8B C8 88 5D ?? 89 86 [4] E8 [4] 8B 8E [4] 53 E8 }
	condition:
		#pattern == 1	
}

//2b4 CRxWndServer * dlg_server;
rule CRxMgrLogin_dlg_server
{
	meta:
		script = "$result = [@pattern + 0x1f]"
		script = "log \"/*{p:$result}*/    CRxWndServer * dlg_server;\""	
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
		script = "log \"/*{p:$result}*/    SERVER_OBJECT * svrlist;\""
	strings:
		$pattern = { 8B 8E [4] 33 C0 89 45 ?? 3B C8 74 [20] 83 F8 64 0F 8F [4] 83 F8 33 7D ?? C7 45 ?? 00 00 00 00 EB ?? 33 C9 83 F8 5B }
	condition:
		#pattern == 1	
}

//8d4 CRxWnd * dlg_rolelist;
//8d8 CRxListBox * lbx_roleList;
rule CRxMgrLogin_dlg_rolelist
{
	meta:
		script = "$result = [@pattern + 0x1f]"
		script = "log \"/*{p:$result}*/    CRxWnd * dlg_rolelist;\""
		
		script = "$result = [@pattern + 0xd9]"
		script = "log \"/*{p:$result}*/    CRxListBox * lbx_roleList;\""		
	strings:
		$pattern = { 6A 01 6A 01 56 68 [4] 52 51 8B C8 E8 [4] EB ?? 33 C0 53 8B C8 88 5D ?? 89 86 [4] E8 [4] 8B 8E [4] 53 E8 [4] 8B 8E [4] 53 E8 [4] 8B 8E [4] E8 [4] D9 05 [4] 6A 04 [90] C7 85 [4] 2B 00 00 00 C7 85 [4] 75 00 00 00 C7 85 [4] 47 00 00 00 E8 [4] 6A 01 68 [4] 89 86 [4] E8 [4] 6A 01}
	condition:
		#pattern == 1	
}

//8e4 int roleCount;
//8e8 int roleMaxCount;
rule CRxMgrLogin_roleCount
{
	meta:
		script = "$result = [@pattern + 0x08]"
		script = "log \"/*{p:$result}*/    int roleCount;\""
		
		script = "$result = [@pattern + 0x02]"
		script = "log \"/*{p:$result}*/    int roleMaxCount;\""		
	strings:
		$pattern = { 8B BE [4] 39 BE [4] 7C ?? 6A 7F 50 8D 8D [4] 51 88 85 [4] E8 [4] 8B 0D [4] 83 C4 0C 57 68 33 11 00 00 E8}
	condition:
		#pattern == 1	
}



//8ec int roleUIDList[8];
rule CRxMgrLogin_roleUIDList
{
	meta:
		script = "$result = [@pattern + 0x2c]"
		script = "log \"/*{p:$result}*/    int roleUIDList[8];\""
			
	strings:
		$pattern = { 8D BE [4] BB 06 00 00 00 8B 0F 6A 00 68 [4] E8 [4] 83 C7 04 4B 75 ?? 8B 8E [4] E8 [4] 8D BE [4] BB 08 00 00 00 8B FF 81 3F FF FF 00 00}
	condition:
		#pattern == 1	
}



//1224 CRxButton * bn_enter;
rule CRxMgrLogin_bn_enter
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "log \"/*{p:$result}*/    CRxButton * bn_enter;\""	
	strings:
		$pattern = { 8B 8D [4] 8B 95 [4] 68 [4] 68 D1 07 00 00 56 51 52 53 53 8B C8 E8 [4] EB ?? 33 C0 89 86 [4] 8D 4E ?? 89 48}
	condition:
		#pattern == 1	
}

//1228 CRxButton * bn_back;
rule CRxMgrLogin_bn_back
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"/*{p:$result}*/    CRxButton * bn_back;\""	
	strings:
		$pattern = { 8B 8D [4] 8B 95 [4] 68 [4] 68 D2 07 00 00 56 81 C1 6B 01 00 00 51 83 C2 15 52 68 6B 01 00 00 6A 15 8B C8 E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 [4] 83 C1 28 89 48}
	condition:
		#pattern == 1	
}

//122c CRxButton * bn_delete;
rule CRxMgrLogin_bn_delete
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"/*{p:$result}*/    CRxButton * bn_delete;\""	
	strings:
		$pattern = { 8B 8D [4] 8B 95 [4] 68 [4] 68 D4 07 00 00 56 81 C1 37 01 00 00 51 83 C2 15 52 68 37 01 00 00 6A 15 8B C8 E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 [4] 83 C1 28 89 48}
	condition:
		#pattern == 1	
}

//122c CRxButton * bn_create;
rule CRxMgrLogin_bn_create
{
	meta:
		script = "$result = [@pattern + 0x3c]"
		script = "log \"/*{p:$result}*/    CRxButton * bn_create;\""	
	strings:
		$pattern = { 8B 8D [4] 8B 95 [4] 68 [4] 68 D3 07 00 00 56 81 C1 03 01 00 00 51 83 C2 15 52 68 03 01 00 00 6A 15 8B C8 E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 [4] 83 C1 28 89 48}
	condition:
		#pattern == 1	
}



rule CRxMgrLogin_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}
