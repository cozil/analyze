rule CRxMgrMember_start
{
	meta:
		script = "Type.as CRxMgrMember"
		script = "Type.aanc CRxMgrMember,CRxMgr"
		script = "Type.comment CRxMgrMember, \"队伍成员管理\""	
		script = "Type.ad CRxMgrMember,\"static const int MaxSize = 7; \""
	condition:
		true
}

//228 uint8_t t_exist;
//22c short t_sid;
rule CRxMgrMember_t_exist
{
	meta:
		script = "$result = [@pattern + 0x2A]"
		script = "Type.am CRxMgrMember,uint8_t,t_exist,0,$result"
		script = "Type.mcomment CRxMgrMember,t_exist,\"单元指向有效队员\""
		script = "$result = [@pattern + 0x34]"
		script = "Type.am CRxMgrMember,short,t_sid,0,$result"
		script = "Type.mcomment CRxMgrMember,t_sid,\"队员sid\""
	strings:
		$pattern = { C7 ?? 00 00 FF FF 80 [5] 00 [9] 00 [17] 80 [5] 00 [2] 0F BF }
	condition:
		#pattern == 1
}

//char t_name[0x20];
rule CRxMgrMember_t_name
{
	meta:
		script = "$result = [@pattern + 0x30]"
		script = "Type.am CRxMgrMember,char,t_name,0x20,$result"
		script = "Type.mcomment CRxMgrMember,t_name,\"队友名称\""
	strings:
		$pattern = { 68 00 FF FF FF [2] 6A FF E8 [12] 6A 01 [2] E8 [19] 89 }
	condition:
		#pattern == 1
}


rule CRxMgrMember_end
{
	meta:
		script = "Type.print CRxMgrMember,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}