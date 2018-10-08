rule CRxMgrMemberMenu_start
{
	meta:
		script = "Type.as CRxMgrMemberMenu"
		script = "Type.aanc CRxMgrMemberMenu,CRxMgr"
		script = "Type.comment CRxMgrMemberMenu, \"队伍成员菜单管理\""
		script = "Type.ad CRxMgrMemberMenu,\"inline void click_captain() { click(0x63);} //任命队长\""
		script = "Type.ad CRxMgrMemberMenu,\"inline void click_kick() { click(0x1);} //逐出队伍\""
	condition:
		true
}

//230 CRxWnd * dlg;
rule CRxMgrMemberMenu_t_exist
{
	meta:
		script = "$result = [@pattern + 0x31]"
		script = "Type.am CRxMgrMemberMenu,CRxWnd*,dlg,0,$result"
		script = "Type.mcomment CRxMgrMemberMenu,dlg,\"菜单窗口\""
	strings:
		$pattern = { FE FB FF FF [2] 48 [6] 0F B6 [5] FF [6] 8B [7] 0F 84 [4] 8B [5] 8B }
	condition:
		#pattern == 1
}

rule CRxMgrMemberMenu_end
{
	meta:
		script = "Type.print CRxMgrMemberMenu,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}