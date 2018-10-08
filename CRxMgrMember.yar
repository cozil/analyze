rule CRxMgrMember_start
{
	meta:
		script = "Type.as CRxMgrMember"
		script = "Type.aanc CRxMgrMember,CRxMgr"
		script = "Type.comment CRxMgrMember, \"队伍成员管理\""	
	condition:
		true
}

//228 char t_exist;
//22c short t_sid;
rule CRxMgrMember_t_exist
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxMgrMember,char,t_exist,0,$result"
		script = "Type.mcomment CRxMgrMember,t_exist,\"单元指向有效队员\""
		script = "$result = [@pattern + 0x32]"
		script = "Type.am CRxMgrMember,short,t_sid,0,$result"
		script = "Type.mcomment CRxMgrMember,t_sid,\"队员sid\""
	strings:
		$pattern = { FF 00 FF FF [2] 00 00 FF FF [8] 00 [5] 00 [13] 80 [5] 00 [2] 0F BF }
	condition:
		#pattern == 1
}

//274 CRxMgrMemberMenu * mgr_menu;
//rule CRxMgrMember_mgr_menu
//{
//	meta:
//		script = "$result = [@pattern + 0x2b]"
//		script = "Type.am CRxMgrMember,CRxMgrMemberMenu*,mgr_menu,0,$result"
//		script = "Type.mcomment CRxMgrMember,mgr_menu,\"成员菜单管理\""
//	strings:
//		$pattern = { FE FB FF FF [2] 48 [6] 0F B6 [5] FF [6] 8B [7] 0F 84 [4] 8B [5] 8B ｝
//	condition:
//		#pattern == 1
//}

rule CRxMgrMember_end
{
	meta:
		script = "Type.print CRxMgrMember,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}