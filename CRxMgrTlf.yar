rule CRxMgrTlf_start
{
	meta:
		script = "Type.as CRxMgrTlf"
		script = "Type.aanc CRxMgrTlf,CRxMgr"
		script = "Type.comment CRxMgrTlf, \"土灵符管理\""	
		script = "Type.ad CRxMgrTlf,\"inline void click_item(int id) {{ click(0x64+id); }} //id:[0,9]\""
	condition:
		true
}

//228 CRxWnd * dlg;
rule CRxMgrTlf_dlg
{
	meta:
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxMgrTlf,CRxWnd*,dlg,0,$result"
	strings:
		$pattern = { 6A 01 6A 01 ?? 68 [11] 0E 01 00 00 [3] E8 [9] 6A 78 88 [2] 89 }
	condition:
		#pattern == 1
}

//4a4 int tab_id;
//4a8 int btn_id;
rule CRxMgrTlf_tab_id
{
	meta:
		script = "$result = [@pattern + 0xe]"
		script = "Type.am CRxMgrTlf,int,tab_id,0,$result-4"
		script = "Type.am CRxMgrTlf,int,btn_id,0,$result"		
	strings:
		$pattern = { 8D ?? 9C 83 ?? 09 0F 87 [4] 8B }
	condition:
		#pattern == 1
}

rule CRxMgrTlf_end
{
	meta:
		script = "Type.print CRxMgrTlf,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}