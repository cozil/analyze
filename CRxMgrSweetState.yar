rule CRxMgrSweetState_start
{
	meta:
		script = "Type.as CRxMgrSweetState"
		script = "Type.aanc CRxMgrSweetState,CRxMgr"
		script = "Type.comment CRxMgrSweetState, \"情侣状态管理\""
		script = "Type.ad CRxMgrSweetState,\"inline bool online() const {{ return (state == 2); }}\""
	condition:
		true
}


//228 uint32_t state;
//260 uint32_t grade;
rule CRxMgrSweetState_mgr_flower
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrSweetState,uint32_t,state,0,$result"
		script = "Type.mcomment CRxMgrSweetState,state,\"情侣状态 0:无情侣 1:不在一条线上 2:在一条线上\""
		
		script = "Type.am CRxMgrSweetState,char,sweet_name,0x10,$result+0x14"
		script = "Type.mcomment CRxMgrSweetState,sweet_name,\"情侣名称\""
		
		script = "$result = [@pattern + 0x32]"
		script = "Type.am CRxMgrSweetState,uint32_t,grade,0,$result"
		script = "Type.mcomment CRxMgrSweetState,grade,\"情侣关系等级\""
	strings:
		$pattern = { 83 [5] 01 [2] 80 [5] 01 [2] C7 [2] 99 99 99 FF [2] C7 [2] 99 99 99 FF 8B [13] 8B }
	condition:
		#pattern == 1
}

rule CRxMgrSweetState_end
{
	meta:
		script = "Type.print CRxMgrSweetState,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}